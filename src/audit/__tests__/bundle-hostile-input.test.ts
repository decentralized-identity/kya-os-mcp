/**
 * `verifyAuditBundle` is an offline, fail-closed verifier that anyone may hand a bundle: whatever
 * the bundle holds, it answers with a report, never throws, and spends work in proportion to what
 * the bundle carries, whether or not anyone authorized it.
 */

import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { AuditCheckpointBuilder, MemoryAuditCheckpointStore } from '../checkpoint.js';
import { CryptoProviderAuditHasher } from '../crypto.js';
import { AUDIT_BUNDLE_MEDIA_TYPES, AuditReplayBundleExporter, verifyAuditBundle } from '../replay-bundle.js';
import { AuditRecorderService } from '../recorder-service.js';
import type { AuditHasher, AuditSigner } from '../crypto.js';
import type { SignedAuditCheckpointV1, SignedAuditEntryV1 } from '../types.js';
import { AUDIT_REASON_CODES } from '../verifier.js';
import { policy, producerEvent, recordedHistory, tenantRef, TestSigner } from './audit-fixtures.js';

const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());

/** A key no policy names, as a stranger's would be. */
const stranger: AuditSigner = {
  ref: { did: 'did:key:zStranger', kid: 'did:key:zStranger#zStranger', alg: 'EdDSA' },
  sign: async () => 'not.a.signature',
};

/** A bundle the shipped exporter wrote under a stranger's key, with the components given. */
async function strangersBundle(
  components: Partial<Record<keyof typeof AUDIT_BUNDLE_MEDIA_TYPES, readonly unknown[]>>,
  lastSequence = '0',
): Promise<unknown> {
  const bundle = await new AuditReplayBundleExporter({
    hasher, signer: stranger, clock: { now: () => 1_750_000_010_000 },
  }).export({
    bundleId: 'bundle', purpose: 'any',
    verificationPolicyDigest: `sha256:${'0'.repeat(64)}`,
    selections: [{
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1', firstSequence: '0', lastSequence,
      expectedHeadDigest: `sha256:${'0'.repeat(64)}`, checkpointTreeSizes: [],
    }],
    components: Object.entries(components).map(([name, content]) => ({
      path: `${name}.json`,
      mediaType: AUDIT_BUNDLE_MEDIA_TYPES[name as keyof typeof AUDIT_BUNDLE_MEDIA_TYPES],
      disposition: 'included' as const,
      content,
    })),
  });
  return JSON.parse(JSON.stringify(bundle)) as unknown;
}

/** A bundle whose every evidence component carries `content`. */
function bundleCarrying(content: readonly unknown[]): Promise<unknown> {
  return strangersBundle(Object.fromEntries(
    Object.keys(AUDIT_BUNDLE_MEDIA_TYPES).map((name) => [name, content]),
  ));
}

/** How many digests the verifier computes to answer for `bundle`. */
async function digestsSpentOn(bundle: unknown): Promise<number> {
  let calls = 0;
  const counting: AuditHasher = {
    sha256: async (data) => {
      calls += 1;
      return hasher.sha256(data);
    },
  };
  const report = await verifyAuditBundle(bundle, policy, {
    hasher: counting, signatures: { verify: async () => false },
  });
  // Refused either way: the question is what refusing it costs.
  expect(report.cryptographicIntegrity.reasonCodes).toContain(AUDIT_REASON_CODES.BUNDLE_EXPORTER_UNAUTHORIZED);
  return calls;
}

/**
 * The recorded history grown to `size` entries, with a checkpoint at every tree size from its
 * first four entries on: one signed checkpoint for nearly every prefix of the ledger.
 */
async function checkpointedAtEverySize(size: number): Promise<{
  entries: SignedAuditEntryV1[];
  checkpoints: SignedAuditCheckpointV1[];
}> {
  const { journal, ledger } = await recordedHistory();
  const signer = new TestSigner();
  const recorder = new AuditRecorderService({
    ...ledger, tenantRef, binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'recorder-1',
    journal, signer, hasher, clock: { now: () => 1_750_000_001_000 },
  });
  const builder = new AuditCheckpointBuilder({
    journal, store: new MemoryAuditCheckpointStore(), signer, hasher, clock: { now: () => 1_750_000_002_000 },
  });
  const checkpoints = [await builder.createCheckpoint(ledger)];
  for (let sequence = 4; sequence < size; sequence += 1) {
    await recorder.submitAuthenticated({
      ledgerId: ledger.ledgerId, producerEvent: producerEvent(`evt_${sequence}`, sequence), encryptedEvidence: [],
    }, { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef });
    checkpoints.push(await builder.createCheckpoint(ledger));
  }
  return { entries: await journal.snapshot(ledger), checkpoints };
}

describe('a bundle verified for whoever sends it', () => {
  it('answers with a report when its components carry more items than a call takes arguments', async () => {
    const received = await bundleCarrying(new Array<number>(300_000).fill(0));

    const report = await verifyAuditBundle(received, policy, {
      hasher, signatures: { verify: async () => false },
    });

    expect(report.cryptographicIntegrity.verdict).toBe('invalid');
    expect(report.checkpointIntegrity.verdict).toBe('invalid');
    expect(report.anchorIntegrity.verdict).toBe('invalid');
  }, 60_000);

  it('spends work in proportion to the checkpoints it carries, however many repeat one tree', async () => {
    const { entries } = await recordedHistory();
    const { journal, ledger } = await recordedHistory();
    const checkpoint = await new AuditCheckpointBuilder({
      journal, store: new MemoryAuditCheckpointStore(), signer: new TestSigner(), hasher,
      clock: { now: () => 1_750_000_002_000 },
    }).createCheckpoint(ledger);
    const copies = (count: number) => strangersBundle({
      entries,
      checkpoints: Array.from({ length: count }, (_, index) => ({
        ...checkpoint, core: { ...checkpoint.core, checkpointId: `copy-${index}` },
      })),
    }, String(entries.length - 1));

    const small = await digestsSpentOn(await copies(150));
    const doubled = await digestsSpentOn(await copies(300));

    expect(doubled / small).toBeLessThan(2.5);
  }, 60_000);

  it('spends work in proportion to the ledger it carries, with a checkpoint at every tree size', async () => {
    const carrying = async (size: number) => {
      const { entries, checkpoints } = await checkpointedAtEverySize(size);
      return strangersBundle({ entries, checkpoints }, String(entries.length - 1));
    };

    const small = await digestsSpentOn(await carrying(40));
    const doubled = await digestsSpentOn(await carrying(80));

    expect(doubled / small).toBeLessThan(2.5);
  }, 60_000);
});
