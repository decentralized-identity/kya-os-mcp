/**
 * Every stage beat, end to end, in-process: a Responsible Party hub and a
 * merchant edge on ephemeral ports with their own temp var/ and .data/, a real
 * MCP client presenting a real credential + holder proof, and the shipped
 * verifier deciding. Also the two things the stage never shows on purpose: the
 * hub going DOWN (fail-closed) and the offline DID-document mirror.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';

const crypto = new NodeCryptoProvider();
// Paths relative to the example, not to whoever's cwd runs vitest.
const EXAMPLE_ROOT = fileURLToPath(new URL('..', import.meta.url));
const SCRIPTS = path.join(EXAMPLE_ROOT, 'scripts');
/** The published package's audit CLI, wherever the example resolved the package from. */
const AUDIT_CLI = path.join(path.dirname(createRequire(import.meta.url).resolve('@kya-os/mcp/package.json')), 'dist', 'audit', 'cli.js');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agentic-commerce-'));
const RP_PORT = 14950 + Math.floor(Math.random() * 1000);
const MERCHANT_PORT = RP_PORT + 1;

let rp: { server: { close: (cb?: () => void) => void } };
let merchant: { httpServer: { close: (cb?: () => void) => void }; statusListResolver: { invalidateCache(): void } };
let agent: typeof import('../src/agent/agent.js');
let merchantMod: typeof import('../src/merchant/server.js');
let merchantDid: string;

async function order(product: string, quantity = 1, forge = false) {
  const outcome = await agent.runAgentOrder({ product, quantity, forge, serverUrl: `http://localhost:${MERCHANT_PORT}/mcp`, audience: merchantDid });
  const text = outcome.result.content?.[0]?.text ?? '{}';
  const body = JSON.parse(text) as Record<string, unknown>;
  return { denied: !!outcome.result.isError || !!body['error'], code: body['error'] as string | undefined, reason: String(body['reason'] ?? body['message'] ?? ''), body, meta: outcome.result._meta };
}

beforeAll(async () => {
  // Environment BEFORE any example module is imported (wiring reads it at import).
  const rpKp = await crypto.generateKeyPair();
  const mKp = await crypto.generateKeyPair();
  const aKp = await crypto.generateKeyPair();
  merchantDid = generateDidKeyFromBase64(mKp.publicKey);
  Object.assign(process.env, {
    DEMO_VAR_DIR: path.join(tmp, 'var'),
    DEMO_DATA_DIR: path.join(tmp, 'data'),
    RP_PORT: String(RP_PORT),
    MERCHANT_PORT: String(MERCHANT_PORT),
    RP_DID: `did:web:localhost%3A${RP_PORT}`,
    RP_KID: `did:web:localhost%3A${RP_PORT}#key-1`,
    RP_PRIVATE_KEY_BASE64: rpKp.privateKey,
    RP_PUBLIC_KEY_BASE64: rpKp.publicKey,
    MERCHANT_DID: merchantDid,
    MERCHANT_PRIVATE_KEY_BASE64: mKp.privateKey,
    MERCHANT_PUBLIC_KEY_BASE64: mKp.publicKey,
    AGENT_DID: generateDidKeyFromBase64(aKp.publicKey),
    AGENT_ED25519_PRIVATE_KEY_BASE64: aKp.privateKey,
    AGENT_ED25519_PUBLIC_KEY_BASE64: aKp.publicKey,
    KEY_WEBAUTHN: '0', KEY_SETUP: '0', OFFLINE: '0',
  });
  const rpMod = await import('../src/rp/server.js');
  merchantMod = await import('../src/merchant/server.js');
  agent = await import('../src/agent/agent.js');
  const { ensureStatusList } = await import('../src/rp/statuslist.js');
  const { loadRpIdentity, makeVcSigningFunction, STATUS_LIST_URL } = await import('../src/lib/wiring.js');

  const identity = loadRpIdentity();
  rpMod.ensureDidDocument(identity);
  await ensureStatusList({ identity, signingFunction: makeVcSigningFunction(identity.privateKeyBase64), url: STATUS_LIST_URL });

  rp = rpMod.startRpServer(RP_PORT);
  merchant = await merchantMod.startMerchantServer({ port: MERCHANT_PORT, auditDir: path.join(tmp, 'audit') });
  await new Promise((r) => setTimeout(r, 300));
});

afterAll(async () => {
  if (merchant) await new Promise<void>((r) => merchant.httpServer.close(() => r()));
  if (rp) await new Promise<void>((r) => rp.server.close(() => r()));
  fs.rmSync(tmp, { recursive: true, force: true });
});

type Challenge = { authorizationUrl: string; resumeToken: string; expiresAt: number; scopes: string[] };
async function consent(challenge: Challenge, decision: 'approve' | 'deny') {
  return fetch(new URL(`/consent/${decision}`, challenge.authorizationUrl), {
    method: 'POST',
    body: new URLSearchParams({ tool: 'place_order', scopes: JSON.stringify(challenge.scopes), selected_scopes: JSON.stringify(challenge.scopes), agent_did: process.env['AGENT_DID']!, session_id: challenge.resumeToken }),
  });
}

describe('the stage, beat by beat', () => {
  it('refuses revocation without an active grant instead of silently revoking reserved index 94', async () => {
    const before = await (await fetch(`http://localhost:${RP_PORT}/api/rp/state`)).json();
    const response = await fetch(`http://localhost:${RP_PORT}/api/rp/revoke`, { method: 'POST', body: '{}' });
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ error: 'no_active_grant' });
    const after = await (await fetch(`http://localhost:${RP_PORT}/api/rp/state`)).json();
    expect(after.statusList.version).toBe(before.statusList.version);
    expect(after.activeIndex).toBeNull();
  });


  it('0 · discovery: the agent reads acceptedTrustSchemes and decides to present', async () => {
    const d = await agent.discover(`http://localhost:${MERCHANT_PORT}`);
    expect(d.accepted).toBe(true);
    expect(d.scheme?.['id']).toBe('org.kya-os/delegation');
    expect(d.audience).toBe(merchantDid);
    expect(d.clockSkewSeconds).toBe(120);
  });

  it('the agent starts with no delegation and receives a signed, bound human-consent challenge', async () => {
    expect(fs.existsSync(path.join(tmp, 'var', 'delegation-94.json'))).toBe(false);
    const r = await order('risotto', 2);
    expect(r.code).toBe('needs_authorization');
    const challenge = r.body as unknown as Challenge;
    expect(challenge.scopes).toContain('https://id.gs1.org/01/09506000134352');
    expect(challenge.expiresAt).toBeGreaterThan(Date.now() / 1000);
    const proof = r.meta?.['org.kya-os/response-proof'] as { meta: { outcome: string; responseHash: string } };
    expect(proof.meta.outcome).toBe('needs_authorization');
    expect(proof.meta.responseHash).toMatch(/^sha256:/);
    const page = await fetch(challenge.authorizationUrl);
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain('mcp-consent');
    for (const visible of ['09506000134352', '50.00', 'CHF', merchantDid, 'Approve grant']) expect(html).toContain(visible);
    const denied = await consent(challenge, 'deny');
    expect(denied.ok).toBe(true);
    expect((await fetch(`http://localhost:${RP_PORT}/api/rp/delegation`)).status).toBe(404);
    expect((await consent(challenge, 'approve')).ok).toBe(false);
  });

  it('human approval issues the original RP credential with the GS1 scope, CHF cap, audience, and status index', async () => {
    const r = await order('risotto', 2);
    expect(r.code).toBe('needs_authorization');
    const challenge = r.body as unknown as Challenge;
    const forged = await fetch(new URL('/consent/approve', challenge.authorizationUrl), {
      method: 'POST', body: new URLSearchParams({ tool: 'place_order', scopes: JSON.stringify(['https://id.gs1.org/01/07612345678901']), agent_did: process.env['AGENT_DID']!, session_id: challenge.resumeToken }),
    });
    expect(forged.ok).toBe(false);
    const approved = await consent(challenge, 'approve');
    expect(approved.ok, await approved.text()).toBe(true);
    const { credential: vc } = await (await fetch(`http://localhost:${RP_PORT}/api/rp/delegation`)).json();
    expect(vc.type).toContain('DelegationCredential');
    expect(vc.issuer).toBe(process.env['RP_DID']);
    expect(vc.credentialSubject.id).toBe(process.env['AGENT_DID']);
    expect(vc.credentialSubject.delegation.constraints.audience).toBe(merchantDid);
    expect(vc.credentialSubject.delegation.constraints.crisp.scopes[0]).toMatchObject({ resource: 'https://id.gs1.org/01/09506000134352', matcher: 'prefix', constraints: { maxAmount: '50.00', currency: 'CHF' } });
    expect(vc.credentialStatus.statusListIndex).toBe('94');
    expect((await consent(challenge, 'approve')).ok).toBe(false);
    const state = await (await fetch(`http://localhost:${MERCHANT_PORT}/api/state`)).json();
    expect(state.authorizationChallenge).toBeNull();
  });

  it('1 · an authorized order inside the class and the cap, with a signed receipt', async () => {
    const r = await order('risotto', 2);
    expect(r.denied).toBe(false);
    expect(r.body['orderId']).toMatch(/^ORD-/);
    expect((r.body['order'] as Record<string, unknown>)['total']).toBe('CHF 39.80');
    expect((r.body['mandate'] as Record<string, unknown>)['responsibleParty']).toBe(process.env['RP_DID']);
    const proof = r.meta?.['org.kya-os/response-proof'] as { jws?: string } | undefined;
    expect(proof?.jws).toMatch(/^eyJ/);
  });

  it('1b · a lot-level Digital Link beneath the class is in scope', async () => {
    expect((await order('risotto-lot', 1)).denied).toBe(false);
  });

  it('2 · another GTIN is refused: PRODUCT_OUT_OF_SCOPE', async () => {
    const r = await order('olive-oil', 1);
    expect(r.denied).toBe(true);
    expect(r.code).toBe('PRODUCT_OUT_OF_SCOPE');
  });

  it('3 · over the cap is refused: SPEND_CAP_EXCEEDED', async () => {
    const r = await order('risotto', 5);
    expect(r.code).toBe('SPEND_CAP_EXCEEDED');
  });

  it('5 · a stolen credential with the wrong key is refused before the handler', async () => {
    const r = await order('risotto', 1, true);
    expect(r.code).toBe('holder_binding_failed');
  });

  it('V · the receipt re-verifies in stdlib Python with no SDK', async () => {
    const res = await fetch(`http://localhost:${MERCHANT_PORT}/api/act/verify-receipt`, { method: 'POST' });
    const j = (await res.json()) as { ok: boolean; report?: { checks: string[] } };
    expect(j.ok).toBe(true);
    expect(j.report?.checks.length).toBeGreaterThanOrEqual(6);

    // and a tampered content array is refused by the same script
    const last = (await (await fetch(`http://localhost:${MERCHANT_PORT}/api/receipt/last`)).json()) as { content: Array<{ text: string }> };
    const tampered = { receipt: { ...last, content: [{ type: 'text', text: last.content[0]!.text.replace('"ok":true', '"ok":false') }] }, merchant: { did: merchantDid, kid: `${merchantDid}#x`, publicKeyBase64: process.env['MERCHANT_PUBLIC_KEY_BASE64'] } };
    const py = spawnSync('python3', [path.join(SCRIPTS, 'verify-receipt.py')], { input: JSON.stringify(tampered), encoding: 'utf8' });
    expect(py.status).toBe(1);
    expect(py.stdout).toMatch(/responseHash/);
  });

  it('K · the Responsible Party revokes; the next request is refused in one round trip', async () => {
    const res = await fetch(`http://localhost:${RP_PORT}/api/rp/revoke`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    const j = (await res.json()) as { revoked: boolean; version: number };
    expect(j.revoked).toBe(true);
    expect(j.version).toBe(2);
    const r = await order('risotto', 1);
    expect(r.denied).toBe(true);
    expect(r.reason).toMatch(/revoked/i);
  });

  it('A · every beat is in the ledger; the checkpoint is signed by the merchant and witnessed by the RP', async () => {
    const res = await fetch(`http://localhost:${MERCHANT_PORT}/api/act/audit`, { method: 'POST' });
    const r = (await res.json()) as { ledger: { ledgerId: string; ledgerEpochId: string }; entries: Array<{ eventType: string; outcome: string; reason: string | null; anchored: boolean }>; checkpoint: { treeSize: string; rootDigest: string } | null; witness: { observer: { did: string } } | null; witnessError: string | null; chainIntact: boolean; allIncluded: boolean; unanchored: number; profile: { advertised: string }; tree: unknown[] };
    expect(res.status).toBe(200);
    expect(r.chainIntact).toBe(true);
    expect(r.allIncluded).toBe(true);
    expect(r.unanchored).toBe(0);
    expect(r.profile.advertised).toBe('AAP-1');
    expect(r.checkpoint?.treeSize).toBe(String(r.entries.length));
    expect(r.tree.length).toBe(2 * r.entries.length - 1);
    expect(r.entries[0]?.eventType).toBe('ledger.epoch.started');
    const types = r.entries.map((e) => e.eventType);
    expect(types).toEqual(expect.arrayContaining(['consent.requested', 'credential.verified', 'authorization.approved']));
    expect(types).not.toContain('consent.approved');
    expect(types).not.toContain('delegation.issued');
    const rpLedger = await (await fetch(`http://localhost:${RP_PORT}/api/rp/audit/ledger`)).json();
    const rpTypes = rpLedger.entries.map((e: { eventType: string }) => e.eventType);
    expect(rpLedger.recorder.did).toBe(process.env['RP_DID']);
    expect(rpTypes).toEqual(expect.arrayContaining(['consent.denied', 'consent.approved', 'delegation.issued', 'delegation.revoked']));
    expect(rpTypes.indexOf('consent.approved')).toBeLessThan(rpTypes.indexOf('delegation.issued'));
    expect(rpTypes.indexOf('delegation.issued')).toBeLessThan(rpTypes.indexOf('delegation.revoked'));
    expect(types).toContain('tool.call.completed');      // beat 1
    expect(types).toContain('tool.call.failed');         // beats 2, 3 (handler refusals)
    expect(types).toContain('authorization.denied');     // beat 5 (holder binding) and the revoked retry
    expect(types).toContain('delegation.rejected');      // K → 4
    expect(r.witnessError).toBeNull();
    expect(r.witness?.observer.did).toBe(process.env['RP_DID']);
    const latest = (await (await fetch(`http://localhost:${RP_PORT}/api/rp/audit/latest?ledgerId=${encodeURIComponent(r.ledger.ledgerId)}&ledgerEpochId=${encodeURIComponent(r.ledger.ledgerEpochId)}`)).json()) as { observations: number; latest: { checkpoint: { core: { rootDigest: string } } } | null };
    expect(latest.observations).toBe(1);
    expect(latest.latest?.checkpoint.core.rootDigest).toBe(r.checkpoint?.rootDigest);
  });

  it('exports retained legacy revocations with missing scope without poisoning later consent', async () => {
    const { ConsentFlowStore } = await import('../src/rp/consent-store.js');
    new ConsentFlowStore().appendEvent({ type: 'delegation.revoked', actor: process.env['RP_DID']!, payload: {
      credentialId: 'status-list-index-93', index: 93, scope: '', cap: '', currency: '',
    } });
    const response = await fetch(`http://localhost:${RP_PORT}/api/rp/audit/export`, { method: 'POST' });
    expect(response.status, await response.text()).toBe(200);
  });

  it('T · an insider WITH the merchant key edits one entry: signature valid, chain + root + inclusion invalid', async () => {
    const t = (await (await fetch(`http://localhost:${MERCHANT_PORT}/api/act/tamper`, { method: 'POST' })).json()) as {
      target: { eventType: string; before: string; after: string }; rootsMatch: boolean; chainBreaksAt: string | null; honestInclusion: boolean; forgedInclusion: boolean; forgedReceiptVerifies: boolean; witnessStillBindsAnchoredRoot: boolean;
      reports: Record<'honest' | 'tampered', Record<string, { verdict: string; reasonCodes: string[] }>>;
    };
    expect(t.target.eventType).toBe('tool.call.denied');
    expect(t.target.before).toBe('denied');
    expect(t.target.after).toBe('succeeded');
    expect(t.forgedReceiptVerifies).toBe(true);       // the insider has the key
    expect(t.rootsMatch).toBe(false);
    expect(t.chainBreaksAt).not.toBeNull();
    expect(t.honestInclusion).toBe(true);
    expect(t.forgedInclusion).toBe(false);
    expect(t.witnessStillBindsAnchoredRoot).toBe(true);
    const h = t.reports.honest, x = t.reports.tampered;
    for (const dim of ['cryptographicIntegrity', 'chainIntegrity', 'checkpointIntegrity', 'anchorIntegrity', 'scopeEvidenceCompleteness']) expect(h[dim]?.verdict, dim).toBe('valid');
    expect(h['authorizedAsObserved']?.verdict).toBe('indeterminate'); // honest: the bundle carries no delegation collateral
    expect(x['cryptographicIntegrity']?.verdict).toBe('valid');       // re-signed correctly…
    expect(x['chainIntegrity']).toEqual({ verdict: 'invalid', reasonCodes: ['AUDIT_PREDECESSOR_MISMATCH'] });
    expect(x['checkpointIntegrity']?.verdict).toBe('invalid');
    expect(x['checkpointIntegrity']?.reasonCodes).toEqual(expect.arrayContaining(['AUDIT_CHECKPOINT_ROOT_MISMATCH', 'AUDIT_MERKLE_PROOF_INVALID']));
    expect(x['anchorIntegrity']?.verdict).toBe('valid');              // the RP's receipt still names the honest checkpoint
  });

  it('E · the exported bundle passes the SDK CLI and stdlib Python; the edited one fails both', async () => {
    const e = (await (await fetch(`http://localhost:${MERCHANT_PORT}/api/act/export`, { method: 'POST' })).json()) as { files: { bundle: string; tampered: string; policy: string; keys: string }; components: Array<{ path: string }> };
    expect(e.components.map((c) => c.path).sort()).toEqual(['checkpoints.json', 'entries.json', 'inclusion-proofs.json', 'observations.json']);
    const run = (bundle: string) => spawnSync(process.execPath, [AUDIT_CLI, 'verify', bundle, '--policy', e.files.policy, '--keys', e.files.keys], { encoding: 'utf8' });
    const ok = run(e.files.bundle);
    expect(ok.status, ok.stderr).toBe(0);
    expect((JSON.parse(ok.stdout) as { anchorIntegrity: { verdict: string } }).anchorIntegrity.verdict).toBe('valid');
    const bad = run(e.files.tampered);
    expect(bad.status).toBe(1);
    expect((JSON.parse(bad.stdout) as { chainIntegrity: { reasonCodes: string[] } }).chainIntegrity.reasonCodes).toContain('AUDIT_PREDECESSOR_MISMATCH');

    const py = (bundle: string) => spawnSync('python3', [path.join(SCRIPTS, 'verify-ledger.py'), bundle, '--keys', e.files.keys, '--quiet'], { encoding: 'utf8' });
    const pyOk = py(e.files.bundle);
    expect(pyOk.status, pyOk.stderr).toBe(0);
    const okReport = JSON.parse(pyOk.stdout) as { verdict: string; dimensions: Record<string, string>; checks: number };
    expect(okReport.verdict).toBe('valid');
    expect(okReport.dimensions['witness']).toBe('valid');
    expect(okReport.checks).toBeGreaterThan(100);
    const pyBad = py(e.files.tampered);
    expect(pyBad.status).toBe(1);
    const badReport = JSON.parse(pyBad.stdout) as { dimensions: Record<string, string> };
    expect(badReport.dimensions['chain']).toBe('invalid');
    expect(badReport.dimensions['checkpoint']).toBe('invalid');
    expect(badReport.dimensions['entries']).toBe('valid');
  });

  it('R · Start over clears the audit and authority; another human approval is required', async () => {
    const res = await fetch(`http://localhost:${MERCHANT_PORT}/api/act/reset`, { method: 'POST' });
    const j = (await res.json()) as { auditRunId: string; archivedAudit: { entries: number } };
    expect(j.auditRunId).toBeTruthy();
    expect(j.archivedAudit.entries).toBeGreaterThan(0);
    const freshAudit = await (await fetch(`http://localhost:${MERCHANT_PORT}/api/audit/ledger`)).json();
    expect(freshAudit.entries).toEqual([]);
    expect(freshAudit.ledger.ledgerEpochId).toBe(j.auditRunId);
    expect(res.ok).toBe(true);
    expect((await fetch(`http://localhost:${RP_PORT}/api/rp/delegation`)).status).toBe(404);
    const challenge = await order('risotto', 1);
    expect(challenge.code).toBe('needs_authorization');
    expect((await consent(challenge.body as unknown as Challenge, 'approve')).ok).toBe(true);
    expect((await order('risotto', 1)).denied).toBe(false);
  });

  it('the hub going down fails CLOSED: status unresolvable → refused', async () => {
    await new Promise<void>((r) => rp.server.close(() => r()));
    merchant.statusListResolver.invalidateCache();
    const r = await order('risotto', 1);
    expect(r.denied).toBe(true);
    expect(r.reason).toMatch(/status|revocation|unresolvable/i);
    const rpMod = await import('../src/rp/server.js');
    rp = rpMod.startRpServer(RP_PORT);
    await new Promise((r) => setTimeout(r, 200));
    expect((await order('risotto', 1)).denied).toBe(false);
  });

  it('OFFLINE=1: the RP DID document is served from the mirror and verification still passes', async () => {
    const offline = await merchantMod.startMerchantServer({ port: MERCHANT_PORT + 1, offline: true, witness: false });
    await new Promise((r) => setTimeout(r, 200));
    try {
      const outcome = await agent.runAgentOrder({ product: 'risotto', quantity: 1, serverUrl: `http://localhost:${MERCHANT_PORT + 1}/mcp`, audience: merchantDid });
      expect(outcome.result.isError).toBeFalsy();
      const state = (await (await fetch(`http://localhost:${MERCHANT_PORT + 1}/api/state`)).json()) as { responsibleParty: { from: string } };
      expect(state.responsibleParty.from).toBe('mirror');
    } finally {
      await new Promise<void>((r) => offline.httpServer.close(() => r()));
    }
  });
});
