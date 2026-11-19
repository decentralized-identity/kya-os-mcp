/**
 * Shared fixtures of the signed replay bundle tests.
 */

import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import type { AuditSignatureVerifier, AuditSigner } from '../crypto.js';
import { CryptoProviderAuditHasher, hashAuditValue } from '../crypto.js';
import {
  AuditReplayBundleExporter,
  verifyAuditBundle,
  AUDIT_BUNDLE_MEDIA_TYPES,
} from '../replay-bundle.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { AuditRecorderService } from '../recorder-service.js';
import { AuditCheckpointBuilder, MemoryAuditCheckpointStore } from '../checkpoint.js';
import type {
  AuditProducerEventCoreV1,
  AuditVerificationPolicyV1,
  PartyRef,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
  SignerRef,
} from '../types.js';

export class TestSigner implements AuditSigner {
  readonly ref = {
    did: 'did:key:zRecorder',
    kid: 'did:key:zRecorder#zRecorder',
    alg: 'EdDSA' as const,
  };
  async sign(payload: Uint8Array): Promise<string> {
    return `test.${Buffer.from(payload).toString('base64url')}.signature`;
  }
}

export class TestVerifier implements AuditSignatureVerifier {
  async verify(payload: Uint8Array, jws: string, signer: SignerRef): Promise<boolean> {
    return signer.kid === new TestSigner().ref.kid &&
      jws === `test.${Buffer.from(payload).toString('base64url')}.signature`;
  }
}

export const tenantRef: PartyRef = {
  kind: 'keyed_commitment',
  value: `sha256:${'a'.repeat(64)}`,
  keyId: 'tenant-key-1',
};

export function event(sequence: number): AuditProducerEventCoreV1 {
  return {
    schema: 'https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0',
    eventId: `evt_${sequence}`,
    eventType: 'tool.call.completed',
    eventVersion: '1.0.0',
    binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    occurredAt: 1_750_000_000_000 + sequence,
    tenantRef,
    source: {
      producer: { kind: 'pairwise_did', did: 'did:key:zProducer' },
      sourceId: 'source-1',
      sourceSequence: String(sequence),
    },
    action: { category: 'tool.call' },
    outcome: 'succeeded',
    evidence: [],
    details: { family: 'tool', phase: 'completed', attempt: '1' },
    privacy: { classification: 'internal', retentionClass: 'audit-365d' },
  };
}

export async function fixture() {
  const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
  const journal = new MemoryAuditJournal();
  const signer = new TestSigner();
  const recorder = new AuditRecorderService({
    ledgerId: 'kya:tenant:prod:primary',
    ledgerEpochId: 'epoch_1',
    tenantRef,
    binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    sourceId: 'recorder-1',
    journal,
    signer,
    hasher,
    clock: { now: () => 1_750_000_001_000 },
  });
  for (let sequence = 1; sequence <= 2; sequence += 1) {
    await recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: event(sequence),
      encryptedEvidence: [],
    }, { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef });
  }
  const entries = await journal.snapshot({
    ledgerId: 'kya:tenant:prod:primary',
    ledgerEpochId: 'epoch_1',
  });
  const policy: AuditVerificationPolicyV1 = {
    policyId: 'policy:test',
    trustedLedgerEpochs: [{
      ledgerId: 'kya:tenant:prod:primary',
      ledgerEpochId: 'epoch_1',
      recorderKeys: [{ signer: signer.ref }],
    }],
    trustedObservers: [],
    authorizedExporters: [{
      signerKeys: [{ signer: signer.ref }],
      allowedLedgerIds: ['kya:tenant:prod:primary'],
      allowedPurposes: ['regulatory-review'],
    }],
    acceptedIntegritySuites: [
      'KYA-AUDIT-JCS-SHA256-JWS-2026',
      'KYA-AUDIT-BUNDLE-JCS-SHA256-JWS-2026',
    ],
    acceptedAlgorithms: ['EdDSA'],
    keyRevocationMode: 'as_observed',
  };
  const policyDigest = await hashAuditValue(
    hasher,
    'org.kya-os.audit.verification-policy.v1',
    policy,
  );
  return { entries, hasher, signer, policy, policyDigest, journal };
}

export const rolloverContext = {
  producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef,
};

/**
 * epoch_1 sealed by a terminal checkpoint over its first three entries, and an
 * epoch_2 genesis that commits it; optionally with the builder's lifecycle hook
 * recording `checkpoint.created` into epoch_1 after the terminal is signed.
 */
export async function rolloverFixture(withLifecycleEvent = false) {
  const { hasher, signer, policy, journal } = await fixture();
  const epochOne = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };
  const epochTwo = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_2' };
  const epochOneRecorder = new AuditRecorderService({
    ...epochOne, tenantRef, binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    sourceId: 'recorder-1', journal, signer, hasher, clock: { now: () => 1_750_000_005_000 },
  });
  const builder = new AuditCheckpointBuilder({
    journal, store: new MemoryAuditCheckpointStore(), signer, hasher,
    clock: { now: () => 1_750_000_003_000 },
    ...(withLifecycleEvent
      ? {
          onCheckpointCreated: async (checkpoint: SignedAuditCheckpointV1) => {
            await epochOneRecorder.submitAuthenticated({
              ledgerId: epochOne.ledgerId,
              producerEvent: {
                ...event(3),
                eventId: `evt_checkpoint_${checkpoint.core.treeSize}`,
                eventType: 'checkpoint.created',
                action: { category: 'audit.ledger' },
                details: {
                  family: 'ledger', phase: 'checkpoint_created',
                  checkpointDigest: checkpoint.checkpointDigest,
                },
              },
              encryptedEvidence: [],
            }, rolloverContext);
          },
        }
      : {}),
  });
  const terminal = await builder.createCheckpoint(epochOne);
  await new AuditRecorderService({
    ...epochTwo, tenantRef, binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    sourceId: 'recorder-2', journal, signer, hasher, clock: { now: () => 1_750_000_004_000 },
    previousEpochId: epochOne.ledgerEpochId,
    previousTerminalCheckpointDigest: terminal.checkpointDigest,
    epochTransitionGuard: { verifyAndSeal: async () => true },
  }).submitAuthenticated({
    ledgerId: epochTwo.ledgerId, producerEvent: event(10), encryptedEvidence: [],
  }, rolloverContext);
  const twoEntries = await journal.snapshot(epochTwo);
  const multiEpochPolicy: AuditVerificationPolicyV1 = {
    ...policy,
    acceptedIntegritySuites: [...policy.acceptedIntegritySuites, 'KYA-AUDIT-RFC9162-SHA256-JWS-2026'],
    trustedLedgerEpochs: [
      ...policy.trustedLedgerEpochs,
      { ...epochTwo, recorderKeys: [{ signer: signer.ref }] },
    ],
  };
  const verifyRollover = async (
    oneEntries: readonly SignedAuditEntryV1[],
    oneCheckpoints: readonly SignedAuditCheckpointV1[],
  ) => verifyAuditBundle(await new AuditReplayBundleExporter({
    hasher, signer, clock: { now: () => 1_750_000_010_000 },
  }).export({
    bundleId: 'bundle_rollover', purpose: 'regulatory-review',
    verificationPolicyDigest: await hashAuditValue(
      hasher, 'org.kya-os.audit.verification-policy.v1', multiEpochPolicy,
    ),
    selections: [
      {
        ...epochOne, firstSequence: '0', lastSequence: String(oneEntries.length - 1),
        expectedHeadDigest: oneEntries.at(-1)!.entryDigest,
        checkpointTreeSizes: oneCheckpoints.map((checkpoint) => checkpoint.core.treeSize),
      },
      {
        ...epochTwo, firstSequence: '0', lastSequence: String(twoEntries.length - 1),
        expectedHeadDigest: twoEntries.at(-1)!.entryDigest, checkpointTreeSizes: [],
      },
    ],
    components: [
      { path: 'entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries, disposition: 'included', content: [...oneEntries, ...twoEntries] },
      { path: 'checkpoints.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.checkpoints, disposition: 'included', content: oneCheckpoints },
    ],
  }), multiEpochPolicy, { hasher, signatures: new TestVerifier() });
  return { journal, epochOne, builder, terminal, epochOneRecorder, verifyRollover };
}
