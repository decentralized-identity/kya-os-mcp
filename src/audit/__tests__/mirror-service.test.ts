import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import type { AuditSignatureVerifier, AuditSigner } from '../crypto.js';
import { CryptoProviderAuditHasher } from '../crypto.js';
import { AuditMirrorService } from '../mirror-service.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { AuditRecorderService } from '../recorder-service.js';
import type { AuditVerificationPolicyV1, PartyRef, SignerRef } from '../types.js';
import { AuditArtifactVerifier } from '../verifier.js';
import type { AuditJournalProvider } from '../providers/journal.js';

class Signer implements AuditSigner {
  readonly ref = { did: 'did:key:zRecorder', kid: 'did:key:zRecorder#key', alg: 'EdDSA' as const };
  async sign(payload: Uint8Array): Promise<string> {
    return `test.${Buffer.from(payload).toString('base64url')}.signature`;
  }
}
class Signatures implements AuditSignatureVerifier {
  async verify(payload: Uint8Array, jws: string, signer: SignerRef): Promise<boolean> {
    return signer.kid === new Signer().ref.kid &&
      jws === `test.${Buffer.from(payload).toString('base64url')}.signature`;
  }
}
const tenantRef: PartyRef = {
  kind: 'keyed_commitment', value: `sha256:${'a'.repeat(64)}`, keyId: 'tenant-key',
};

async function fixture() {
  const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
  const source = new MemoryAuditJournal();
  const signer = new Signer();
  const recorder = new AuditRecorderService({
    ledgerId: 'ledger', ledgerEpochId: 'epoch', tenantRef,
    binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'recorder',
    journal: source, signer, hasher, clock: { now: () => 1_750_000_000_000 },
  });
  await recorder.submitAuthenticated({
    ledgerId: 'ledger', encryptedEvidence: [],
    producerEvent: {
      schema: 'https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0',
      eventId: 'evt_1', eventType: 'tool.call.completed', eventVersion: '1.0.0',
      binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', occurredAt: 1_750_000_000_000,
      tenantRef, source: { producer: { kind: 'pairwise_did', did: 'did:key:zProducer' }, sourceId: 'source' },
      action: { category: 'tool.call' }, outcome: 'succeeded', evidence: [],
      details: { family: 'tool', phase: 'completed', attempt: '1' },
      privacy: { classification: 'internal', retentionClass: 'audit' },
    },
  }, {
    producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant', tenantRef,
  });
  const entries = await source.snapshot({ ledgerId: 'ledger', ledgerEpochId: 'epoch' });
  const policy: AuditVerificationPolicyV1 = {
    policyId: 'policy',
    trustedLedgerEpochs: [{ ledgerId: 'ledger', ledgerEpochId: 'epoch', recorderKeys: [{ signer: signer.ref }] }],
    trustedObservers: [], authorizedExporters: [],
    acceptedIntegritySuites: ['KYA-AUDIT-JCS-SHA256-JWS-2026'],
    acceptedAlgorithms: ['EdDSA'], keyRevocationMode: 'as_observed',
  };
  const mirrorJournal = new MemoryAuditJournal();
  const verifier = new AuditArtifactVerifier({ hasher, signatures: new Signatures() });
  const mirror = new AuditMirrorService({
    ledger: { ledgerId: 'ledger', ledgerEpochId: 'epoch' }, journal: mirrorJournal,
    verifier,
    verificationPolicy: policy, hasher,
  });
  return { entries, mirror, mirrorJournal, verifier, policy, hasher };
}

describe('AuditMirrorService', () => {
  it('persists exact authoritative envelopes without resequencing or resigning', async () => {
    const { entries, mirror, mirrorJournal } = await fixture();
    for (const entry of entries) expect(await mirror.ingest(entry)).toBe(entry);
    expect(await mirrorJournal.snapshot({ ledgerId: 'ledger', ledgerEpochId: 'epoch' }))
      .toEqual(entries);
    expect(await mirror.ingest(entries[1]!)).toEqual(entries[1]);
  });

  it('rejects out-of-order and cryptographically mutated entries', async () => {
    const { entries, mirror } = await fixture();
    await expect(mirror.ingest(entries[1]!)).rejects.toMatchObject({
      code: 'AUDIT_MIRROR_OUT_OF_ORDER',
    });
    const mutated = structuredClone(entries[0]!);
    mutated.core.event.action.category = 'mutated';
    await expect(mirror.ingest(mutated)).rejects.toMatchObject({
      code: 'AUDIT_MIRROR_VERIFICATION_FAILED',
    });
    const wrongLedger = structuredClone(entries[0]!);
    wrongLedger.core.ledgerId = 'other-ledger';
    await expect(mirror.ingest(wrongLedger)).rejects.toMatchObject({
      code: 'AUDIT_LEDGER_MISMATCH',
    });
  });

  it('treats a compare-and-append race as an idempotent retry when the entry won', async () => {
    const { entries, verifier, policy, hasher } = await fixture();
    const entry = entries[0]!;
    let idempotencyReads = 0;
    const journal: AuditJournalProvider = {
      capabilities: { durability: 'ephemeral', atomicAppend: true, orderedRead: true },
      getHead: async () => null,
      getByIdempotencyKey: async () => (++idempotencyReads === 1 ? null : entry),
      compareAndAppend: async () => ({
        kind: 'head_conflict',
        actualHead: {
          ledgerId: 'ledger', ledgerEpochId: 'epoch',
          sequence: entry.core.sequence, entryDigest: entry.entryDigest,
        },
      }),
      readRange: async function* () {},
    };
    const mirror = new AuditMirrorService({
      ledger: { ledgerId: 'ledger', ledgerEpochId: 'epoch' },
      journal, verifier, verificationPolicy: policy, hasher,
    });

    await expect(mirror.ingest(entry)).resolves.toBe(entry);
  });

  it('raises a continuity alarm when a compare conflict cannot be reconciled', async () => {
    const { entries, verifier, policy, hasher } = await fixture();
    const entry = entries[0]!;
    const journal: AuditJournalProvider = {
      capabilities: { durability: 'ephemeral', atomicAppend: true, orderedRead: true },
      getHead: async () => null,
      getByIdempotencyKey: async () => null,
      compareAndAppend: async () => ({
        kind: 'head_conflict',
        actualHead: {
          ledgerId: 'ledger', ledgerEpochId: 'epoch',
          sequence: entry.core.sequence, entryDigest: `sha256:${'f'.repeat(64)}`,
        },
      }),
      readRange: async function* () {},
    };
    const mirror = new AuditMirrorService({
      ledger: { ledgerId: 'ledger', ledgerEpochId: 'epoch' },
      journal, verifier, verificationPolicy: policy, hasher,
    });

    await expect(mirror.ingest(entry)).rejects.toMatchObject({
      code: 'AUDIT_MIRROR_CONTINUITY_FAILED',
    });
  });
});
