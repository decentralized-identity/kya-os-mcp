import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { NodeCryptoProvider, generateDidKeyFromBase64, generateRequestProof, type DelegationCredential } from '@kya-os/mcp';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'commerce-audit-reset-'));
let rpPort: number, merchantPort: number;
let rp: ReturnType<typeof import('../src/rp/server.js').startRpServer>;
let merchant: Awaited<ReturnType<typeof import('../src/merchant/server.js').createMerchant>>;
let server: typeof import('../src/merchant/server.js');
let wiring: typeof import('../src/lib/wiring.js');
let wallet: typeof import('../src/agent/store.js');
let agent: typeof import('../src/agent/agent.js');
let vc: DelegationCredential;
let challenge: import('../src/lib/consent-contract.js').ConsentChallenge;
let auditDir: string;
const scope = 'https://id.gs1.org/01/09506000134352';
const crypto = new NodeCryptoProvider();
const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
};
const bodyOf = (result: { content?: Array<{ text?: string }> }) => JSON.parse(result.content?.[0]?.text ?? '{}');
const state = async () => (await merchant.app.request('/api/state')).json();

beforeAll(async () => {
  const reserve = async () => {
    const listener = net.createServer();
    await new Promise<void>(resolve => listener.listen(0, '127.0.0.1', resolve));
    return { listener, port: (listener.address() as net.AddressInfo).port };
  };
  const reservations = await Promise.all([reserve(), reserve()]);
  [rpPort, merchantPort] = reservations.map(reservation => reservation.port) as [number, number];
  await Promise.all(reservations.map(({ listener }) => new Promise<void>(resolve => listener.close(() => resolve()))));
  const [rpKey, merchantKey, agentKey] = await Promise.all([crypto.generateKeyPair(), crypto.generateKeyPair(), crypto.generateKeyPair()]);
  const merchantDid = generateDidKeyFromBase64(merchantKey.publicKey), agentDid = generateDidKeyFromBase64(agentKey.publicKey);
  const env = {
    DEMO_ENV_FILE: path.join(tmp, 'missing.env'), DEMO_VAR_DIR: path.join(tmp, 'var'), DEMO_DATA_DIR: path.join(tmp, 'data'),
    RP_PORT: String(rpPort), MERCHANT_PORT: String(merchantPort), RP_ORIGIN: `http://127.0.0.1:${rpPort}`,
    RP_DID: `did:web:localhost%3A${rpPort}`, RP_KID: `did:web:localhost%3A${rpPort}#key-1`,
    RP_PRIVATE_KEY_BASE64: rpKey.privateKey, RP_PUBLIC_KEY_BASE64: rpKey.publicKey,
    MERCHANT_DID: merchantDid, MERCHANT_PRIVATE_KEY_BASE64: merchantKey.privateKey, MERCHANT_PUBLIC_KEY_BASE64: merchantKey.publicKey,
    AGENT_DID: agentDid, AGENT_ED25519_PRIVATE_KEY_BASE64: agentKey.privateKey, AGENT_ED25519_PUBLIC_KEY_BASE64: agentKey.publicKey,
    KEY_WEBAUTHN: '0', CONSENT_WEBAUTHN: '0', KEY_SETUP: '0', OFFLINE: '0', COMMERCE_PAYMENTS: '0', GOOGLE_CLIENT_ID: '',
  };
  for (const [key, value] of Object.entries(env)) vi.stubEnv(key, value);
  wiring = await import('../src/lib/wiring.js');
  wallet = await import('../src/agent/store.js');
  agent = await import('../src/agent/agent.js');
  server = await import('../src/merchant/server.js');
  const rpModule = await import('../src/rp/server.js');
  rpModule.ensureDidDocument(wiring.loadRpIdentity());
  rp = rpModule.startRpServer(rpPort);
});

beforeEach(async () => {
  auditDir = path.join(tmp, `audit-${globalThis.crypto.randomUUID()}`);
  merchant = await server.createMerchant(server.merchantConfigFromEnv({ witness: true, auditDir }));
  await new Promise<void>(resolve => merchant.httpServer.listen(merchantPort, '127.0.0.1', resolve));
  wallet.clearAgentState();
  const first = await agent.runAgentOrder({ product: 'risotto', quantity: 1, serverUrl: `http://127.0.0.1:${merchantPort}/mcp` });
  challenge = bodyOf(first.result);
  expect(challenge.error).toBe('needs_authorization');
  const approval = await fetch(`http://127.0.0.1:${rpPort}/consent/approve`, { method: 'POST',
    body: new URLSearchParams({ tool: 'place_order', scopes: JSON.stringify([scope]), selected_scopes: JSON.stringify([scope]),
      agent_did: wiring.loadAgentIdentity().did, session_id: challenge.resumeToken }) });
  expect(approval.ok, await approval.text()).toBe(true);
  vc = (await import('../src/rp/issue.js')).activeCredential();
});
afterEach(async () => {
  vi.restoreAllMocks();
  merchant.httpServer.closeAllConnections();
  await new Promise<void>(resolve => merchant.httpServer.close(() => resolve()));
});
afterAll(async () => {
  if (rp) await new Promise<void>(resolve => rp.server.close(() => resolve()));
  vi.unstubAllEnvs(); fs.rmSync(tmp, { recursive: true, force: true });
});

async function signedArgs() {
  const identity = wiring.loadAgentIdentity();
  const args: Record<string, unknown> = { product: 'risotto', quantity: 1, _kyaos_delegation: vc };
  args['_kyaos_proof'] = await generateRequestProof({ identity: { did: identity.did, kid: identity.kid,
    privateKey: identity.privateKeyBase64, publicKey: identity.publicKeyBase64 }, crypto,
    toolName: 'place_order', args, audience: wiring.loadMerchantIdentity().did });
  return args;
}
const order = () => agent.runAgentOrder({ product: 'risotto', quantity: 1, serverUrl: `http://127.0.0.1:${merchantPort}/mcp` });
const reset = () => fetch(`http://127.0.0.1:${merchantPort}/api/act/reset`, { method: 'POST' });

describe('Start over starts a fresh merchant audit through the real HTTP/MCP path', () => {
  it('archives all records, empties the current run, and records the next challenge in a new witnessed epoch', async () => {
    expect(bodyOf((await order()).result).ok).toBe(true);
    await merchant.audit.anchor();
    await merchant.audit.tamper();
    // The archived run must include orders after the pinned insider-edit snapshot.
    expect(bodyOf((await order()).result).ok).toBe(true);
    const oldEntries = await merchant.audit.entries();
    const oldEpoch = merchant.audit.ledger.ledgerEpochId;
    const rpBefore = await (await fetch(`http://127.0.0.1:${rpPort}/api/rp/audit/ledger`)).json();
    const response = await reset();
    expect(response.status).toBe(200);
    const result = await response.json();
    expect(result.auditRunId).toBeTruthy();
    expect(result.auditRunId).not.toBe(oldEpoch);
    expect(result.archivedAudit).toMatchObject({ ledgerEpochId: oldEpoch });
    expect(await merchant.audit.entries()).toEqual([]);
    expect(await state()).toMatchObject({ orders: 0, lastMandate: null, lastReceipt: null, audit: { entries: 0 } });
    expect(wallet.readAgentState()).toEqual({});
    const archived = fs.readdirSync(path.join(auditDir, 'archives'), { recursive: true })
      .map(String).filter(file => file.endsWith('bundle.json'));
    expect(archived).toHaveLength(1);
    const bundle = JSON.parse(fs.readFileSync(path.join(auditDir, 'archives', archived[0]!), 'utf8'));
    expect(bundle.components.find((part: { path: string }) => part.path === 'entries.json').content).toEqual(oldEntries);
    const rpAfter = await (await fetch(`http://127.0.0.1:${rpPort}/api/rp/audit/ledger`)).json();
    expect(rpAfter.entries.length).toBeGreaterThanOrEqual(rpBefore.entries.length);
    expect(bodyOf((await order()).result).error).toBe('needs_authorization');
    const nextEntries = await merchant.audit.entries();
    expect(nextEntries.length).toBeGreaterThan(0);
    expect(JSON.stringify(nextEntries)).not.toContain(oldEpoch);
    expect(JSON.stringify(nextEntries)).toContain(result.auditRunId);
    const anchored = await merchant.audit.anchor();
    expect(anchored.witness).not.toBeNull();
    expect(anchored.witnessError).toBeNull();
  });

  it('keeps the current audit and wallet if the authorization host refuses reset', async () => {
    await order();
    const before = await merchant.audit.entries(), epoch = merchant.audit.ledger.ledgerEpochId;
    const previousWallet = wallet.readAgentState();
    const original = globalThis.fetch;
    vi.spyOn(globalThis, 'fetch').mockImplementation((url, init) => String(url).endsWith('/api/rp/reset')
      ? Promise.resolve(Response.json({ error: 'RESET_REFUSED' }, { status: 403 })) : original(url, init));
    expect((await reset()).status).toBe(502);
    expect(merchant.audit.ledger.ledgerEpochId).toBe(epoch);
    expect(await merchant.audit.entries()).toEqual(before);
    expect(wallet.readAgentState()).toEqual(previousWallet);
  });

  it('refuses to reset authority when the previous signed audit cannot be archived', async () => {
    await order();
    fs.mkdirSync(auditDir, { recursive: true });
    fs.writeFileSync(path.join(auditDir, 'archives'), 'not a directory');
    const previousWallet = wallet.readAgentState(), epoch = merchant.audit.ledger.ledgerEpochId;
    const original = globalThis.fetch;
    const resetRp = vi.fn();
    vi.spyOn(globalThis, 'fetch').mockImplementation((url, init) => { if (String(url).endsWith('/api/rp/reset')) resetRp(); return original(url, init); });
    expect((await reset()).status).toBe(503);
    expect(resetRp).not.toHaveBeenCalled();
    expect(merchant.audit.ledger.ledgerEpochId).toBe(epoch);
    expect(wallet.readAgentState()).toEqual(previousWallet);
    fs.unlinkSync(path.join(auditDir, 'archives'));
    expect((await reset()).status).toBe(200);
  });

  it('finishes a delayed credential pickup and order before clearing the shared wallet', async () => {
    const entered = deferred(), release = deferred();
    const original = globalThis.fetch;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      const response = await original(url, init);
      if (String(url).endsWith('/consent/pickup')) { entered.resolve(); await release.promise; }
      return response;
    });
    const buying = order();
    await entered.promise;
    let resetFinished = false;
    const resetting = reset().then(response => { resetFinished = true; return response; });
    await new Promise(resolve => setTimeout(resolve, 30));
    const completedBeforeRelease = resetFinished;
    release.resolve();
    const bought = await buying, restarted = await resetting;
    expect(completedBeforeRelease).toBe(false);
    expect(bodyOf(bought.result).ok).toBe(true);
    expect(restarted.status).toBe(200);
    expect(wallet.readAgentState()).toEqual({});
    expect(await merchant.audit.entries()).toEqual([]);
    expect((await state()).lastReceipt).toBeNull();
  });

  it('retains the current audit and reports partial reset if clearing the wallet fails', async () => {
    await order();
    const oldEpoch = merchant.audit.ledger.ledgerEpochId, entries = await merchant.audit.entries();
    const remove = fs.rmSync;
    const failure = vi.spyOn(fs, 'rmSync').mockImplementation((file, options) => {
      if (file === wallet.AGENT_STATE_FILE) throw new Error('wallet storage unavailable');
      remove(file, options);
    });
    const response = await reset();
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ error: 'RESET_WALLET_FAILED', authorityReset: true });
    expect(merchant.audit.ledger.ledgerEpochId).toBe(oldEpoch);
    expect(await merchant.audit.entries()).toEqual(entries);
    failure.mockRestore();
    expect((await reset()).status).toBe(200);
    expect(wallet.readAgentState()).toEqual({});
    expect(await merchant.audit.entries()).toEqual([]);
  });

  it('keeps a direct in-flight effect and its middleware records together before reset', async () => {
    const entered = deferred(), release = deferred();
    const oldEpoch = merchant.audit.ledger.ledgerEpochId;
    const buying = merchant.executeOrder(await signedArgs(), async ({ evidence }) => {
      entered.resolve(); await release.promise;
      return { body: { ...evidence, ok: true, orderId: 'IN-FLIGHT-ORDER' } };
    });
    await entered.promise;
    let resetFinished = false;
    const resetting = reset().then(response => { resetFinished = true; return response; });
    await new Promise(resolve => setTimeout(resolve, 30));
    const completedBeforeRelease = resetFinished, epochBeforeRelease = merchant.audit.ledger.ledgerEpochId;
    release.resolve();
    const bought = await buying, restarted = await resetting;
    expect(completedBeforeRelease).toBe(false);
    expect(epochBeforeRelease).toBe(oldEpoch);
    expect(bodyOf(bought).ok).toBe(true);
    expect(restarted.status).toBe(200);
    expect(await merchant.audit.entries()).toEqual([]);
  });

  it('waits for an audit action to finish before switching the run', async () => {
    await order();
    const entered = deferred(), release = deferred();
    const original = merchant.audit.report;
    vi.spyOn(merchant.audit, 'report').mockImplementationOnce(async () => {
      entered.resolve(); await release.promise; return original();
    });
    const showing = merchant.app.request('/api/act/audit', { method: 'POST' });
    await entered.promise;
    let resetFinished = false;
    const oldEpoch = merchant.audit.ledger.ledgerEpochId;
    const resetting = reset().then(response => { resetFinished = true; return response; });
    await new Promise(resolve => setTimeout(resolve, 30));
    const completedBeforeRelease = resetFinished;
    release.resolve();
    const report = await (await showing).json(), restarted = await resetting;
    expect(completedBeforeRelease).toBe(false);
    expect(report.ledger.ledgerEpochId).toBe(oldEpoch);
    expect(restarted.status).toBe(200);
    expect(await merchant.audit.entries()).toEqual([]);
  });

  it('allows repeated Start over on an empty run without extra archives', async () => {
    await order();
    expect((await reset()).status).toBe(200);
    const oldEpoch = merchant.audit.ledger.ledgerEpochId;
    const response = await reset();
    expect(response.status).toBe(200);
    const result = await response.json();
    expect(result.auditRunId).not.toBe(oldEpoch);
    expect(result.archivedAudit).toBeNull();
    expect(fs.readdirSync(path.join(auditDir, 'archives'))).toHaveLength(1);
    expect(await merchant.audit.entries()).toEqual([]);
    const empty = await merchant.app.request('/api/act/audit', { method: 'POST' });
    expect(empty.status).toBe(200);
    expect(await empty.json()).toMatchObject({ entries: [], checkpoint: null, witness: null });
  });
});
