import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';
import { CompactJwsAuditSignatureVerifier, CryptoProviderAuditHasher, verifyAuditBundle, type AuditReplayBundleV1, type SignedAuditEntryV1 } from '@kya-os/mcp/audit';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { MerchantAudit, MerchantAuditOptions } from '../src/merchant/audit.js';
import type { KeyedIdentity } from '../src/lib/wiring.js';

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'commerce-audit-runs-'));
let createMerchantAudit: typeof import('../src/merchant/audit.js').createMerchantAudit;
let createWitness: typeof import('../src/rp/witness.js').createWitness;
let identity: KeyedIdentity;
let witnessIdentity: KeyedIdentity;
let fixtureIndex = 0;
beforeAll(async () => {
  vi.stubEnv('DEMO_VAR_DIR', path.join(directory, 'var'));
  vi.stubEnv('DEMO_DATA_DIR', path.join(directory, 'data'));
  vi.stubEnv('DEMO_ENV_FILE', path.join(directory, 'missing.env'));
  ({ createMerchantAudit } = await import('../src/merchant/audit.js'));
  ({ createWitness } = await import('../src/rp/witness.js'));
  const keyed = async (): Promise<KeyedIdentity> => {
    const pair = await new NodeCryptoProvider().generateKeyPair();
    const did = generateDidKeyFromBase64(pair.publicKey);
    return { did, kid: `${did}#${did.slice(8)}`, privateKeyBase64: pair.privateKey, publicKeyBase64: pair.publicKey };
  };
  [identity, witnessIdentity] = await Promise.all([keyed(), keyed()]);
});
afterEach(() => vi.restoreAllMocks());
afterAll(() => { vi.unstubAllEnvs(); fs.rmSync(directory, { recursive: true, force: true }); });
async function fixture(options: MerchantAuditOptions = {}) {
  const auditDir = path.join(directory, `run-${fixtureIndex++}`);
  return { audit: await createMerchantAudit(identity, { auditDir, ...options }), auditDir };
}
const event = () => ({ eventType: 'authorization.denied' as const, action: { category: 'authorization' as const, name: 'place_order' },
  outcome: 'denied' as const, evidence: [], details: { family: 'authorization' as const, phase: 'denied' as const } });
async function record(audit: MerchantAudit, count = 1) { for (let i = 0; i < count; i++) expect((await audit.record(event())).status).toBe('recorded'); }
const entriesOf = (bundle: AuditReplayBundleV1) => bundle.components.find(component => component.path === 'entries.json')!.content as SignedAuditEntryV1[];
const archived = (auditDir: string, id: string, file: string) => JSON.parse(fs.readFileSync(path.join(auditDir, 'archives', id, file), 'utf8'));

describe('Start over prepares and commits a new merchant audit run', () => {
  it('uses unique epochs for independent merchant starts even at the same clock instant', async () => {
    const clock = { now: () => Date.parse('2026-09-09T10:00:00Z') };
    const a = await fixture({ clock }), b = await fixture({ clock });
    expect(a.audit.ledger.ledgerId).toBe(b.audit.ledger.ledgerId);
    expect(a.audit.ledger.ledgerEpochId).not.toBe(b.audit.ledger.ledgerEpochId);
  });

  it('archives the whole signed run, including entries after a pinned insider demonstration, before committing', async () => {
    const { audit, auditDir } = await fixture();
    await record(audit, 2);
    await audit.tamper();
    const pinned = await audit.bundle(), before = await audit.report();
    await record(audit, 2);
    const entireRun = await audit.entries();
    const ledger = { ...audit.ledger };
    const prepared = await audit.prepareNewRun();
    expect(audit.ledger).toEqual(ledger);
    expect(await audit.entries()).toEqual(entireRun);
    expect((await audit.report()).checkpoint).toEqual(before.checkpoint);
    expect(await audit.bundle()).toEqual(pinned);
    expect(prepared.archive).toMatchObject({ ledger, ledgerEpochId: ledger.ledgerEpochId, entries: entireRun.length });
    expect(prepared.ledger.ledgerEpochId).not.toBe(ledger.ledgerEpochId);
    const bundle = archived(auditDir, prepared.archive!.id, 'bundle.json');
    expect(entriesOf(bundle)).toEqual(entireRun);
    expect(entriesOf(bundle).length).toBeGreaterThan(entriesOf(pinned).length);
    const policy = archived(auditDir, prepared.archive!.id, 'policy.json');
    const keys = archived(auditDir, prepared.archive!.id, 'keys.json').keys;
    const verified = await verifyAuditBundle(bundle, policy, {
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      signatures: new CompactJwsAuditSignatureVerifier({ resolve: async signer => keys.find((key: { kid: string }) => key.kid === signer.kid)?.jwk ?? null }),
    });
    expect(verified.cryptographicIntegrity.verdict).toBe('valid');
    expect(verified.chainIntegrity.verdict).toBe('valid');
    expect(verified.checkpointIntegrity.verdict).toBe('valid');
    expect(JSON.stringify(prepared.archive)).not.toContain(directory);
    prepared.commit();
    expect(audit.ledger).toEqual(prepared.ledger);
    expect(await audit.entries()).toEqual([]);
    expect((await audit.report()).checkpoint).toBeNull();
    expect(entriesOf(archived(auditDir, prepared.archive!.id, 'bundle.json'))).toEqual(entireRun);
  });

  it('routes the middleware callback captured before reset and direct records into the same new epoch', async () => {
    const { audit } = await fixture();
    const middlewareRecord = audit.middlewareAudit.record;
    const directRecord = audit.record;
    await record(audit);
    const prepared = await audit.prepareNewRun();
    prepared.commit();
    expect((await middlewareRecord(event())).status).toBe('recorded');
    expect((await directRecord(event())).status).toBe('recorded');
    const entries = await audit.entries();
    expect(entries).toHaveLength(3); // Fresh genesis plus both records.
    expect(entries.every(entry => entry.core.ledgerEpochId === prepared.ledger.ledgerEpochId)).toBe(true);
    expect((await audit.report()).chainIntact).toBe(true);
  });

  it('can abandon a prepared reset and continue the original run without changing its displayed evidence', async () => {
    const { audit } = await fixture();
    await record(audit); await audit.tamper();
    const ledger = { ...audit.ledger }, originalBundle = await audit.bundle();
    await record(audit);
    await audit.prepareNewRun(); // The RP refuses; do not commit.
    expect(audit.ledger).toEqual(ledger);
    expect(await audit.bundle()).toEqual(originalBundle);
    await record(audit);
    expect((await audit.entries()).every(entry => entry.core.ledgerEpochId === ledger.ledgerEpochId)).toBe(true);
  });

  it('leaves the run and pinned demonstration intact when an archive write fails, then permits retry', async () => {
    const { audit, auditDir } = await fixture();
    await record(audit); await audit.tamper();
    const original = await audit.report(), originalBundle = await audit.bundle();
    await record(audit);
    fs.mkdirSync(auditDir, { recursive: true });
    fs.writeFileSync(path.join(auditDir, 'archives'), 'not a directory');
    await expect(audit.prepareNewRun()).rejects.toThrow();
    expect(audit.ledger).toEqual(original.ledger);
    expect((await audit.report()).checkpoint).toEqual(original.checkpoint);
    expect(await audit.bundle()).toEqual(originalBundle);
    fs.rmSync(path.join(auditDir, 'archives'));
    const prepared = await audit.prepareNewRun();
    prepared.commit();
    expect(await audit.entries()).toEqual([]);
  });

  it('rejects a stale commit if a record arrived after preparation', async () => {
    const { audit } = await fixture();
    await record(audit);
    const original = { ...audit.ledger }, prepared = await audit.prepareNewRun();
    await record(audit);
    await expect(async () => prepared.commit()).rejects.toThrow(/changed|busy|retry/i);
    expect(audit.ledger).toEqual(original);
    expect(await audit.entries()).toHaveLength(3);
  });

  it('starts a new empty epoch without fabricating or requiring an archive', async () => {
    const { audit, auditDir } = await fixture();
    const prepared = await audit.prepareNewRun();
    expect(prepared.archive).toBeNull();
    prepared.commit();
    expect(await audit.entries()).toEqual([]);
    expect(fs.existsSync(path.join(auditDir, 'archives'))).toBe(false);
  });

  it('retains the RP witness across merchant epochs and accepts the fresh run independently', async () => {
    const witness = await createWitness(witnessIdentity);
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      const receipt = await witness.observe(JSON.parse(String(init?.body)));
      return Response.json({ receipt });
    });
    const { audit } = await fixture({ witnessUrl: 'https://rp.example/api/rp/audit/observe', resolvePublicKeyBase64: async () => witnessIdentity.publicKeyBase64 });
    await record(audit);
    const oldLedger = { ...audit.ledger }, oldAnchor = await audit.anchor();
    const prepared = await audit.prepareNewRun();
    expect(prepared.archive?.witnessed).toBe(true);
    prepared.commit();
    await record(audit);
    const nextAnchor = await audit.anchor();
    expect(nextAnchor.witness).not.toBeNull();
    expect(nextAnchor.witnessError).toBeNull();
    expect((await witness.latest(oldLedger.ledgerId, oldLedger.ledgerEpochId))?.checkpoint.checkpointDigest).toBe(oldAnchor.checkpoint.checkpointDigest);
    expect((await witness.latest(audit.ledger.ledgerId, audit.ledger.ledgerEpochId))?.checkpoint.checkpointDigest).toBe(nextAnchor.checkpoint.checkpointDigest);
  });

  it('keeps a truthful signed local archive if the optional witness is unavailable', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json({ error: 'witness unavailable' }, { status: 503 }));
    const { audit, auditDir } = await fixture({ witnessUrl: 'https://rp.example/api/rp/audit/observe' });
    await record(audit);
    const prepared = await audit.prepareNewRun();
    expect(prepared.archive).toMatchObject({ witnessed: false, witnessError: 'witness unavailable' });
    const verified = archived(auditDir, prepared.archive!.id, 'verification.json');
    expect(verified.cryptographicIntegrity.verdict).toBe('valid');
    expect(verified.anchorIntegrity.verdict).not.toBe('valid');
    prepared.commit();
    expect(await audit.entries()).toEqual([]);
  });

  it('cleans up an incomplete archive and preserves the active run when atomic publication fails', async () => {
    const { audit, auditDir } = await fixture();
    await record(audit);
    const entries = await audit.entries(), original = { ...audit.ledger };
    const rename = vi.spyOn(fs, 'renameSync').mockImplementation(() => { throw new Error('archive rename failed'); });
    await expect(audit.prepareNewRun()).rejects.toThrow('archive rename failed');
    rename.mockRestore();
    expect(fs.readdirSync(path.join(auditDir, 'archives'))).toEqual([]);
    expect(audit.ledger).toEqual(original);
    expect(await audit.entries()).toEqual(entries);
    const retry = await audit.prepareNewRun();
    expect(retry.archive?.entries).toBe(entries.length);
    retry.commit();
  });

  it('never replaces earlier archive files on later resets', async () => {
    const { audit, auditDir } = await fixture();
    await record(audit);
    const first = await audit.prepareNewRun(); first.commit();
    const originalBytes = fs.readFileSync(path.join(auditDir, 'archives', first.archive!.id, 'bundle.json'), 'utf8');
    await record(audit, 2);
    const second = await audit.prepareNewRun(); second.commit();
    expect(second.archive!.id).not.toBe(first.archive!.id);
    expect(fs.readFileSync(path.join(auditDir, 'archives', first.archive!.id, 'bundle.json'), 'utf8')).toBe(originalBytes);
    expect(fs.readdirSync(path.join(auditDir, 'archives'))).toHaveLength(2);
    expect(() => first.commit()).toThrow(/changed/i);
  });
});
