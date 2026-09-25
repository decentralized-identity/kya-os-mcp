import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';
import { Rfc9162MerkleTree, type AuditReplayBundleV1, type SignedAuditEntryV1 } from '@kya-os/mcp/audit';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PartyAudit } from '../src/lib/party-audit.js';

let directory: string;
let createPartyAudit: typeof import('../src/lib/party-audit.js').createPartyAudit;
let createMerchant: typeof import('../src/merchant/server.js').createMerchant;
beforeAll(async () => {
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'commerce-audit-edit-'));
  vi.stubEnv('DEMO_VAR_DIR', path.join(directory, 'var'));
  vi.stubEnv('DEMO_DATA_DIR', path.join(directory, 'data'));
  vi.stubEnv('DEMO_ENV_FILE', path.join(directory, 'missing.env'));
  vi.stubEnv('PAYMENT_MODE', 'sandbox');
  // Runtime modules capture the paths above. Never import them before this
  // isolation, or a merchant fixture could open the presenter's live state.
  ({ createPartyAudit } = await import('../src/lib/party-audit.js'));
  ({ createMerchant } = await import('../src/merchant/server.js'));
});
afterAll(() => { vi.unstubAllEnvs(); fs.rmSync(directory, { recursive: true, force: true }); });

async function identity() {
  const key = await new NodeCryptoProvider().generateKeyPair();
  const did = generateDidKeyFromBase64(key.publicKey);
  return { did, kid: `${did}#${did.slice(8)}`, privateKeyBase64: key.privateKey, publicKeyBase64: key.publicKey };
}
async function record(audit: PartyAudit, count = 1) {
  for (let index = 0; index < count; index++) {
    await audit.record({ eventType: 'authorization.denied',
      action: { category: 'authorization', name: 'place_order' }, outcome: 'denied',
      evidence: [], details: { family: 'authorization', phase: 'denied' } });
  }
}
async function fixture(count = 3) {
  const audit = await createPartyAudit(await identity(), { auditDir: path.join(directory, `export-${crypto.randomUUID()}`) });
  await record(audit, count);
  const anchor = await audit.anchor();
  const entries = await audit.entries();
  const edit = { sequence: entries[1]!.core.sequence, outcome: 'succeeded' as const, checkpointDigest: anchor.checkpoint.checkpointDigest };
  return { audit, anchor, entries, edit };
}
function bundledEntries(bundle: AuditReplayBundleV1): SignedAuditEntryV1[] {
  return bundle.components.find(component => component.path === 'entries.json')!.content as SignedAuditEntryV1[];
}

describe('an insider edits the displayed anchored snapshot', () => {
  it('honors the selected entry and outcome, re-signs only a copy, and detects the real cryptographic failure', async () => {
    const { audit, entries, edit } = await fixture();
    const result = await audit.tamper({ ...edit, outcome: 'unknown' });
    expect(result.target).toMatchObject({ seq: entries[1]!.core.sequence, before: 'denied', after: 'unknown' });
    expect(result.chainBreaksAt).toBe(entries[2]!.core.sequence);
    expect(result.forgedReceiptVerifies).toBe(true);
    expect(result.honestInclusion).toBe(true);
    expect(result.forgedInclusion).toBe(false);
    expect(result.rootsMatch).toBe(false);
    expect(result.reports.honest.checkpointIntegrity.verdict).toBe('valid');
    expect(result.reports.tampered.checkpointIntegrity.verdict).toBe('invalid');
    expect(await audit.entries()).toEqual(entries);
  });

  it('does not invent a chain break for the last entry, whose checkpoint inclusion still fails', async () => {
    const { audit, entries, edit } = await fixture();
    const result = await audit.tamper({ ...edit, sequence: entries.at(-1)!.core.sequence });
    expect(result.chainBreaksAt).toBeNull();
    expect(result.forgedInclusion).toBe(false);
    expect(result.rootsMatch).toBe(false);
    expect(result.reports.tampered.checkpointIntegrity.verdict).toBe('invalid');
  });

  it.each(['succeeded', 'failed', 'challenged', 'unknown'] as const)('accepts the SDK outcome %s', async outcome => {
    const { audit, edit } = await fixture(1);
    expect((await audit.tamper({ ...edit, outcome })).target.after).toBe(outcome);
  });

  it('rejects unsupported, unchanged, unknown, and malformed selections', async () => {
    const { audit, edit, entries } = await fixture();
    for (const invalid of [
      { ...edit, outcome: 'allowed' }, { ...edit, outcome: 'denied' },
      { ...edit, sequence: '999' }, { ...edit, sequence: 0 },
      { sequence: edit.sequence, outcome: edit.outcome }, {}, null, [],
    ]) await expect(audit.tamper(invalid as never)).rejects.toThrow();
    expect(await audit.entries()).toEqual(entries);
  });

  it('rejects stale checkpoints and entries which are not in the displayed checkpoint', async () => {
    const { audit, edit } = await fixture();
    await record(audit);
    const appended = (await audit.entries()).at(-1)!;
    await expect(audit.tamper({ ...edit, sequence: appended.core.sequence })).rejects.toThrow(/anchor/i);
    await audit.anchor();
    await expect(audit.tamper(edit)).rejects.toThrow(/checkpoint|snapshot/i);
  });

  it('requires an existing anchor for explicit edits instead of silently anchoring unseen evidence', async () => {
    const audit = await createPartyAudit(await identity());
    await record(audit);
    await expect(audit.tamper({ sequence: '0', outcome: 'succeeded', checkpointDigest: `sha256:${'a'.repeat(64)}` })).rejects.toThrow(/anchor|checkpoint/i);
    expect((await audit.report()).checkpoint).toBeNull();
  });

  it('exports the exact demonstrated edit and original checkpoint after more live events arrive', async () => {
    const { audit, edit, entries, anchor } = await fixture();
    const result = await audit.tamper({ ...edit, outcome: 'unknown' });
    await record(audit);
    const exported = await audit.exportBundle();
    const honest = JSON.parse(fs.readFileSync(exported.files.bundle, 'utf8')) as AuditReplayBundleV1;
    const forged = JSON.parse(fs.readFileSync(exported.files.tampered, 'utf8')) as AuditReplayBundleV1;
    expect(bundledEntries(honest)).toEqual(entries);
    expect(bundledEntries(forged)[1]!.core.event.outcome).toBe('unknown');
    expect(bundledEntries(forged).filter((_, index) => index !== 1)).toEqual(entries.filter((_, index) => index !== 1));
    expect(JSON.stringify(forged)).toContain(anchor.checkpoint.checkpointDigest);
    expect(exported.reports).toEqual(result.reports);
    expect(exported.checkpointDigest).toBe(anchor.checkpoint.checkpointDigest);
    expect(exported.target).toEqual(result.target);
    // The download link beside the export must describe the same checkpoint,
    // even when the live agent has added more events since the demonstration.
    expect(await audit.bundle()).toEqual(honest);
    expect((await audit.report()).checkpoint?.checkpointDigest).toBe(anchor.checkpoint.checkpointDigest);
  });

  it('repeats an edit against the original snapshot without accumulating earlier forgeries', async () => {
    const { audit, edit, entries } = await fixture();
    await audit.tamper({ ...edit, outcome: 'unknown' });
    const result = await audit.tamper({ ...edit, sequence: entries[2]!.core.sequence, outcome: 'failed' });
    const exported = await audit.exportBundle();
    const forged = JSON.parse(fs.readFileSync(exported.files.tampered, 'utf8')) as AuditReplayBundleV1;
    expect(bundledEntries(forged)[1]).toEqual(entries[1]);
    expect(bundledEntries(forged)[2]!.core.event.outcome).toBe('failed');
    expect(exported.target).toEqual(result.target);
  });

  it('starts a new export demonstration when Show audit anchors a new snapshot', async () => {
    const { audit, edit, anchor } = await fixture();
    await audit.tamper({ ...edit, outcome: 'unknown' });
    await record(audit);
    const next = await audit.anchor();
    const exported = await audit.exportBundle();
    expect(exported.checkpointDigest).toBe(next.checkpoint.checkpointDigest);
    expect(exported.checkpointDigest).not.toBe(anchor.checkpoint.checkpointDigest);
    expect(exported.target.seq).toBe((await audit.entries()).at(-1)!.core.sequence);
  });

  it('does not expose the cached honest snapshot to callers of the bundle download API', async () => {
    const { audit, edit, entries } = await fixture();
    const first = await audit.bundle();
    bundledEntries(first)[1]!.core.event.outcome = 'unknown';
    const report = await audit.tamper(edit);
    expect(report.reports.honest.checkpointIntegrity.verdict).toBe('valid');
    expect(bundledEntries(await audit.bundle())).toEqual(entries);
  });

  it('keeps the no-body demonstration and reports its actual replacement outcome', async () => {
    const audit = await createPartyAudit(await identity());
    await audit.record({ eventType: 'tool.call.completed', action: { category: 'tool', name: 'place_order' },
      outcome: 'succeeded', evidence: [], details: { family: 'tool', phase: 'completed', attempt: '1' } });
    expect((await audit.tamper()).target.after).toBe('failed');
  });
});

describe('bounded bundle construction work', () => {
  it('shares SDK subtree roots for all bundle proofs, retaining the genuine inclusion paths', async () => {
    const { audit, entries } = await fixture(64);
    const hash = vi.spyOn(NodeCryptoProvider.prototype, 'hash');
    try {
      const bundle = await audit.bundle();
      expect(bundledEntries(bundle)).toHaveLength(entries.length);
      expect(hash.mock.calls.length).toBeLessThan(64 * 16);
    } finally { hash.mockRestore(); }
    const report = await audit.report();
    const bundle = await audit.bundle();
    const inclusions = bundle.components.find(component => component.path === 'inclusion-proofs.json')!.content as Array<{ proof: { auditPath: string[] } }>;
    expect(inclusions.map(entry => entry.proof.auditPath)).toEqual(report.inclusions.map(entry => entry.auditPath));
  });
});

describe('concurrent audit reports', () => {
  it.each([false, true])('keeps its checkpoint, witness, and witness error together while another anchor completes (witness failure: %s)', async failNextWitness => {
    const { createWitness } = await import('../src/rp/witness.js');
    const witness = await createWitness(await identity());
    let witnessFails = false;
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (witnessFails) return Response.json({ error: 'The later witness is unavailable' }, { status: 503 });
      return Response.json({ receipt: await witness.observe(JSON.parse(String(init?.body))) });
    });
    const audit = await createPartyAudit(await identity(), { witnessUrl: 'https://witness.example/observe' });
    await record(audit, 3);
    const before = await audit.anchor();
    expect(before.witness).not.toBeNull();
    let releaseProof!: () => void;
    const proofPaused = new Promise<void>(resolve => { releaseProof = resolve; });
    let enteredProof!: () => void;
    const proofEntered = new Promise<void>(resolve => { enteredProof = resolve; });
    const inclusionProof = Rfc9162MerkleTree.prototype.inclusionProof;
    const proofMock = vi.spyOn(Rfc9162MerkleTree.prototype, 'inclusionProof').mockImplementationOnce(async function (this: Rfc9162MerkleTree, ...args) {
      enteredProof();
      await proofPaused;
      return inclusionProof.apply(this, args);
    });
    try {
      const pending = audit.report();
      await proofEntered;
      await record(audit);
      witnessFails = failNextWitness;
      const next = await audit.anchor();
      expect(next.checkpoint.checkpointDigest).not.toBe(before.checkpoint.checkpointDigest);
      releaseProof();
      const report = await pending;
      expect(report.checkpoint?.checkpointDigest).toBe(before.checkpoint.checkpointDigest);
      expect(report.witness?.checkpointDigest).toBe(before.checkpoint.checkpointDigest);
      expect(report.witness?.observationDigest).toBe(before.witness!.observationDigest);
      expect(report.witnessError).toBe(before.witnessError);
      expect(report.tree[0]!.hash).toBe(before.checkpoint.core.rootDigest);
      expect(report.allIncluded).toBe(true);
      const current = await audit.report();
      expect(current.checkpoint?.checkpointDigest).toBe(next.checkpoint.checkpointDigest);
      expect(current.witness?.observationDigest ?? null).toBe(next.witness?.observationDigest ?? null);
      expect(current.witnessError).toBe(next.witnessError);
    } finally { releaseProof(); proofMock.mockRestore(); fetchMock.mockRestore(); }
  });
});

describe('merchant edit HTTP route', () => {
  it('passes the selected edit through and rejects malformed JSON without demonstrating an unrelated edit', async () => {
    const merchant = await createMerchant({ identity: await identity(), name: 'Audit test', port: 0,
      rpDid: 'did:web:localhost%3A1', rpDidMirrorUrl: 'http://localhost:1/.well-known/did.json',
      statusListUrl: 'http://localhost:1/status-list', rpOrigin: 'http://localhost:1', offline: true,
      allowInsecureLocalhost: true, statusCacheTtlMs: 0, pythonVerifier: null, witness: false });
    await record(merchant.audit, 3);
    const anchor = await merchant.audit.anchor();
    const entries = await merchant.audit.entries();
    const response = await merchant.app.request('/api/act/tamper', { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sequence: entries[1]!.core.sequence,
        outcome: 'challenged', checkpointDigest: anchor.checkpoint.checkpointDigest }) });
    expect(response.status).toBe(200);
    expect((await response.json()).target).toMatchObject({ seq: entries[1]!.core.sequence, after: 'challenged' });
    const malformed = await merchant.app.request('/api/act/tamper', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{broken' });
    expect(malformed.status).toBe(409);
    expect(await merchant.audit.entries()).toEqual(entries);
  });
});
