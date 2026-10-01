import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { canonicalizeJson } from '../../utils/canonical-json.js';
import type { AuditSignatureVerifier, AuditSigner } from '../crypto.js';
import { CryptoProviderAuditHasher, hashAuditValue } from '../crypto.js';
import { AUDIT_DIGEST_DOMAINS } from '../integrity.js';
import {
  AuditReplayBundleExporter,
  verifyAuditBundle,
  AUDIT_BUNDLE_MEDIA_TYPES,
} from '../replay-bundle.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { AuditRecorderService } from '../recorder-service.js';
import { AuditArtifactVerifier, AUDIT_REASON_CODES } from '../verifier.js';
import { AuditCheckpointBuilder, MemoryAuditCheckpointStore } from '../checkpoint.js';
import { MemoryAuditCheckpointObserver } from '../providers/observer.js';
import { MemorySupportingAnchorProvider } from '../providers/anchor.js';
import {
  parseAuditCheckpointCore,
  parseAuditObservationReceipt,
  parseAuditRecorderReceiptCore,
  parseAuditReplayBundle,
  parseAuditVerificationPolicy,
  parseSignedAuditCheckpoint,
  parseSignedAuditEntry,
} from '../schemas.js';
import type {
  AuditProducerEventCoreV1,
  AuditVerificationPolicyV1,
  PartyRef,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
  SignerRef,
} from '../types.js';

class TestSigner implements AuditSigner {
  readonly ref = {
    did: 'did:key:zRecorder',
    kid: 'did:key:zRecorder#zRecorder',
    alg: 'EdDSA' as const,
  };
  async sign(payload: Uint8Array): Promise<string> {
    return `test.${Buffer.from(payload).toString('base64url')}.signature`;
  }
}

class TestVerifier implements AuditSignatureVerifier {
  async verify(payload: Uint8Array, jws: string, signer: SignerRef): Promise<boolean> {
    return signer.kid === new TestSigner().ref.kid &&
      jws === `test.${Buffer.from(payload).toString('base64url')}.signature`;
  }
}

const tenantRef: PartyRef = {
  kind: 'keyed_commitment',
  value: `sha256:${'a'.repeat(64)}`,
  keyId: 'tenant-key-1',
};

function event(sequence: number): AuditProducerEventCoreV1 {
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

async function fixture() {
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

const rolloverContext = {
  producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef,
};

/**
 * epoch_1 sealed by a terminal checkpoint over its first three entries, and an
 * epoch_2 genesis that commits it; optionally with the builder's lifecycle hook
 * recording `checkpoint.created` into epoch_1 after the terminal is signed.
 */
async function rolloverFixture(withLifecycleEvent = false) {
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

describe('signed replay bundles', () => {
  it('returns a stable invalid report rather than throwing for hostile bundle input', async () => {
    const { hasher, policy } = await fixture();
    const report = await verifyAuditBundle(
      { manifest: { core: null }, components: 'not-an-array' } as never,
      policy,
      { hasher, signatures: new TestVerifier() },
    );
    expect(report.cryptographicIntegrity).toEqual({
      verdict: 'invalid',
      reasonCodes: [AUDIT_REASON_CODES.BUNDLE_SCHEMA_INVALID],
    });
    expect(report.chainIntegrity.verdict).toBe('invalid');
    expect(report.scopeEvidenceCompleteness.verdict).toBe('invalid');
  });

  it('canonicalizes inventory order into a byte-for-byte reproducible manifest', async () => {
    const { entries, hasher, signer, policyDigest } = await fixture();
    const exporter = new AuditReplayBundleExporter({
      hasher,
      signer,
      clock: { now: () => 1_750_000_010_000 },
    });
    const common = {
      bundleId: 'bundle_1',
      purpose: 'regulatory-review',
      verificationPolicyDigest: policyDigest,
      selections: [{
        ledgerId: 'kya:tenant:prod:primary',
        ledgerEpochId: 'epoch_1',
        firstSequence: '0',
        lastSequence: '2',
        expectedHeadDigest: entries[2]!.entryDigest,
        checkpointTreeSizes: [],
      }],
    } as const;
    const components = [
      { path: 'notes/redacted.json', mediaType: 'application/json', disposition: 'redacted' as const, reasonCode: 'DATA_MINIMIZATION' },
      { path: 'ledger/entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries, disposition: 'included' as const, content: entries },
    ];
    const first = await exporter.export({ ...common, components });
    const second = await exporter.export({ ...common, components: [...components].reverse() });
    expect(canonicalizeJson(first)).toBe(canonicalizeJson(second));
  });

  it('verifies exporter authority, complete inventory, policy binding, and ledger range', async () => {
    const { entries, hasher, signer, policy, policyDigest } = await fixture();
    const exporter = new AuditReplayBundleExporter({
      hasher,
      signer,
      clock: { now: () => 1_750_000_010_000 },
    });
    const bundle = await exporter.export({
      bundleId: 'bundle_1',
      purpose: 'regulatory-review',
      verificationPolicyDigest: policyDigest,
      selections: [{
        ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
        firstSequence: '0', lastSequence: '2',
        expectedHeadDigest: entries[2]!.entryDigest,
        checkpointTreeSizes: [],
      }],
      components: [{
        path: 'ledger/entries.json',
        mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries,
        disposition: 'included',
        content: entries,
      }],
    });
    const report = await verifyAuditBundle(bundle, policy, {
      hasher,
      signatures: new TestVerifier(),
      artifacts: new AuditArtifactVerifier({ hasher, signatures: new TestVerifier() }),
    });
    expect(report.cryptographicIntegrity.verdict).toBe('valid');
    expect(report.chainIntegrity.verdict).toBe('valid');
    expect(report.scopeEvidenceCompleteness.verdict).toBe('valid');

    const reordered = structuredClone(bundle);
    const entryComponent = reordered.components.find((component) =>
      component.mediaType === AUDIT_BUNDLE_MEDIA_TYPES.entries);
    entryComponent!.content = [...entries].reverse();
    const reorderedReport = await verifyAuditBundle(reordered, policy, {
      hasher,
      signatures: new TestVerifier(),
      artifacts: new AuditArtifactVerifier({ hasher, signatures: new TestVerifier() }),
    });
    expect(reorderedReport.scopeEvidenceCompleteness.verdict).toBe('valid');
  });

  it('rejects duplicate sequence padding even when count and endpoints appear complete', async () => {
    const { entries, hasher, signer, policy, policyDigest } = await fixture();
    const apparentLast = structuredClone(entries[2]!);
    apparentLast.core.sequence = '3';
    apparentLast.recorderReceipt.core.sequence = '3';
    const padded = [entries[0]!, entries[1]!, entries[1]!, apparentLast];
    const bundle = await new AuditReplayBundleExporter({
      hasher, signer, clock: { now: () => 1_750_000_010_000 },
    }).export({
      bundleId: 'bundle_duplicate_padding',
      purpose: 'regulatory-review',
      verificationPolicyDigest: policyDigest,
      selections: [{
        ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
        firstSequence: '0', lastSequence: '3',
        expectedHeadDigest: apparentLast.entryDigest,
        checkpointTreeSizes: [],
      }],
      components: [{
        path: 'ledger/entries.json',
        mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries,
        disposition: 'included',
        content: padded,
      }],
    });

    const report = await verifyAuditBundle(bundle, policy, {
      hasher, signatures: new TestVerifier(),
    });
    expect(report.scopeEvidenceCompleteness).toEqual({
      verdict: 'invalid',
      reasonCodes: [AUDIT_REASON_CODES.BUNDLE_SELECTION_INCOMPLETE],
    });
  });

  it('detects omitted inventory and rejects an exporter not authorized out of band', async () => {
    const { entries, hasher, signer, policy, policyDigest } = await fixture();
    const bundle = await new AuditReplayBundleExporter({
      hasher, signer, clock: { now: () => 1_750_000_010_000 },
    }).export({
      bundleId: 'bundle_1', purpose: 'regulatory-review',
      verificationPolicyDigest: policyDigest,
      selections: [{
        ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
        firstSequence: '0', lastSequence: '2', expectedHeadDigest: entries[2]!.entryDigest,
        checkpointTreeSizes: [],
      }],
      components: [{
        path: 'ledger/entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries,
        disposition: 'included', content: entries,
      }],
    });
    const deps = {
      hasher,
      signatures: new TestVerifier(),
      artifacts: new AuditArtifactVerifier({ hasher, signatures: new TestVerifier() }),
    };
    const omitted = structuredClone(bundle);
    omitted.components = [];
    expect((await verifyAuditBundle(omitted, policy, deps)).cryptographicIntegrity.reasonCodes)
      .toContain(AUDIT_REASON_CODES.BUNDLE_INVENTORY_MISMATCH);

    const unauthorized = await verifyAuditBundle(bundle, {
      ...policy,
      authorizedExporters: [],
    }, deps);
    expect(unauthorized.cryptographicIntegrity.reasonCodes).toContain(
      AUDIT_REASON_CODES.BUNDLE_EXPORTER_UNAUTHORIZED,
    );
  });

  it('verifies each selected ledger epoch independently while preserving sequence reset', async () => {
    const { entries, hasher, signer, policy, journal } = await fixture();
    const epochTwoRecorder = new AuditRecorderService({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_2', tenantRef,
      binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'recorder-2',
      journal, signer, hasher, clock: { now: () => 1_750_000_002_000 },
      previousEpochId: 'epoch_1',
      previousTerminalCheckpointDigest: `sha256:${'b'.repeat(64)}`,
      epochTransitionGuard: { verifyAndSeal: async () => true },
    });
    await epochTwoRecorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary', producerEvent: event(3), encryptedEvidence: [],
    }, { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef });
    const epochTwoEntries = await journal.snapshot({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_2',
    });
    const multiEpochPolicy: AuditVerificationPolicyV1 = {
      ...policy,
      trustedLedgerEpochs: [
        ...policy.trustedLedgerEpochs,
        {
          ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_2',
          recorderKeys: [{ signer: signer.ref }],
        },
      ],
    };
    const policyDigest = await hashAuditValue(
      hasher,
      'org.kya-os.audit.verification-policy.v1',
      multiEpochPolicy,
    );
    const bundle = await new AuditReplayBundleExporter({
      hasher, signer, clock: { now: () => 1_750_000_010_000 },
    }).export({
      bundleId: 'bundle_epochs', purpose: 'regulatory-review', verificationPolicyDigest: policyDigest,
      selections: [
        {
          ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
          firstSequence: '0', lastSequence: '2', expectedHeadDigest: entries[2]!.entryDigest,
          checkpointTreeSizes: [],
        },
        {
          ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_2',
          firstSequence: '0', lastSequence: '1',
          expectedHeadDigest: epochTwoEntries[1]!.entryDigest, checkpointTreeSizes: [],
        },
      ],
      components: [{
        path: 'ledger/entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries,
        disposition: 'included', content: [...entries, ...epochTwoEntries],
      }],
    });
    const report = await verifyAuditBundle(bundle, multiEpochPolicy, {
      hasher, signatures: new TestVerifier(),
    });
    expect(report.cryptographicIntegrity.verdict).toBe('valid');
    expect(report.chainIntegrity.verdict).toBe('valid');
    expect(report.scopeEvidenceCompleteness.verdict).toBe('valid');
  });

  it('detects a signed checkpoint whose predecessor link forks the checkpoint history', async () => {
    const { entries, hasher, signer, policy, journal } = await fixture();
    const store = new MemoryAuditCheckpointStore();
    const builder = new AuditCheckpointBuilder({
      journal, store, signer, hasher, clock: { now: () => 1_750_000_003_000 },
    });
    const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };
    const first = await builder.createCheckpoint(ledger);
    const recorder = new AuditRecorderService({
      ...ledger, tenantRef, binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
      sourceId: 'recorder-1', journal, signer, hasher,
      clock: { now: () => 1_750_000_004_000 },
    });
    await recorder.submitAuthenticated({
      ledgerId: ledger.ledgerId, producerEvent: event(3), encryptedEvidence: [],
    }, { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef });
    const second = structuredClone(await builder.createCheckpoint(ledger));
    const consistency = await builder.consistencyProof(ledger, first.core.treeSize, second);
    second.core.previousCheckpointDigest = `sha256:${'e'.repeat(64)}`;
    second.checkpointDigest = await hashAuditValue(
      hasher, AUDIT_DIGEST_DOMAINS.checkpoint, second.core,
    );
    second.jws = await signer.sign(new TextEncoder().encode(canonicalizeJson(second.core)));
    const allEntries = await journal.snapshot(ledger);
    const checkpointPolicy = {
      ...policy,
      acceptedIntegritySuites: [
        ...policy.acceptedIntegritySuites,
        'KYA-AUDIT-RFC9162-SHA256-JWS-2026',
      ],
    };
    const policyDigest = await hashAuditValue(
      hasher, 'org.kya-os.audit.verification-policy.v1', checkpointPolicy,
    );
    const bundle = await new AuditReplayBundleExporter({
      hasher, signer, clock: { now: () => 1_750_000_010_000 },
    }).export({
      bundleId: 'bundle_fork', purpose: 'regulatory-review', verificationPolicyDigest: policyDigest,
      selections: [{
        ...ledger, firstSequence: '0', lastSequence: '3',
        expectedHeadDigest: allEntries[3]!.entryDigest,
        checkpointTreeSizes: [first.core.treeSize, second.core.treeSize],
      }],
      components: [
        { path: 'ledger/entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries, disposition: 'included', content: allEntries },
        { path: 'ledger/checkpoints.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.checkpoints, disposition: 'included', content: [first, second] },
        {
          path: 'ledger/consistency-proofs.json',
          mediaType: AUDIT_BUNDLE_MEDIA_TYPES.consistencyProofs,
          disposition: 'included',
          content: [{
            ...ledger,
            oldCheckpointDigest: first.checkpointDigest,
            newCheckpointDigest: second.checkpointDigest,
            proof: consistency,
          }],
        },
      ],
    });
    const report = await verifyAuditBundle(bundle, checkpointPolicy, {
      hasher, signatures: new TestVerifier(),
    });
    expect(report.checkpointIntegrity.verdict).toBe('invalid');
    expect(report.checkpointIntegrity.reasonCodes).toContain(
      AUDIT_REASON_CODES.CHECKPOINT_CHAIN_MISMATCH,
    );
    expect(report.checkpointIntegrity.reasonCodes).not.toContain(
      AUDIT_REASON_CODES.MERKLE_PROOF_INVALID,
    );
  });

  it('verifies bundle-bound inclusion proofs and rejects a mutated audit path', async () => {
    const { entries, hasher, signer, policy, journal } = await fixture();
    const builder = new AuditCheckpointBuilder({
      journal, store: new MemoryAuditCheckpointStore(), signer, hasher,
      clock: { now: () => 1_750_000_003_000 },
    });
    const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };
    const checkpoint = await builder.createCheckpoint(ledger);
    const proof = structuredClone(await builder.inclusionProof(ledger, '1', checkpoint));
    proof.auditPath[0] = `sha256:${'f'.repeat(64)}`;
    const checkpointPolicy = {
      ...policy,
      acceptedIntegritySuites: [
        ...policy.acceptedIntegritySuites,
        'KYA-AUDIT-RFC9162-SHA256-JWS-2026',
      ],
    };
    const policyDigest = await hashAuditValue(
      hasher, 'org.kya-os.audit.verification-policy.v1', checkpointPolicy,
    );
    const bundle = await new AuditReplayBundleExporter({
      hasher, signer, clock: { now: () => 1_750_000_010_000 },
    }).export({
      bundleId: 'bundle_inclusion', purpose: 'regulatory-review',
      verificationPolicyDigest: policyDigest,
      selections: [{
        ...ledger, firstSequence: '0', lastSequence: '2',
        expectedHeadDigest: entries[2]!.entryDigest,
        checkpointTreeSizes: [checkpoint.core.treeSize],
      }],
      components: [
        { path: 'ledger/entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries, disposition: 'included', content: entries },
        { path: 'ledger/checkpoints.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.checkpoints, disposition: 'included', content: [checkpoint] },
        {
          path: 'ledger/inclusion-proofs.json',
          mediaType: AUDIT_BUNDLE_MEDIA_TYPES.inclusionProofs,
          disposition: 'included',
          content: [{ ...ledger, sequence: '1', entryDigest: entries[1]!.entryDigest, checkpointDigest: checkpoint.checkpointDigest, proof }],
        },
      ],
    });
    const report = await verifyAuditBundle(bundle, checkpointPolicy, {
      hasher, signatures: new TestVerifier(),
    });
    expect(report.checkpointIntegrity.verdict).toBe('invalid');
    expect(report.checkpointIntegrity.reasonCodes).toContain(
      AUDIT_REASON_CODES.MERKLE_PROOF_INVALID,
    );
  });

  it('rejects ambiguous export metadata and unsafe or duplicate component paths', async () => {
    const { entries, hasher, signer, policyDigest } = await fixture();
    const exporter = new AuditReplayBundleExporter({
      hasher, signer, clock: { now: () => 1_750_000_010_000 },
    });
    const common = {
      bundleId: 'bundle_validation', purpose: 'regulatory-review',
      verificationPolicyDigest: policyDigest,
      selections: [{
        ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
        firstSequence: '0', lastSequence: '2', expectedHeadDigest: entries[2]!.entryDigest,
        checkpointTreeSizes: [],
      }],
    } as const;
    await expect(exporter.export({ ...common, bundleId: '', components: [] }))
      .rejects.toThrow(/ID and export purpose/);
    await expect(exporter.export({
      ...common,
      components: [{
        path: '../entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries,
        disposition: 'included', content: entries,
      }],
    })).rejects.toThrow(/safe canonical relative path/);
    await expect(exporter.export({
      ...common,
      components: [
        { path: 'entries.json', mediaType: 'application/json', disposition: 'included', content: [] },
        { path: 'entries.json', mediaType: 'application/json', disposition: 'included', content: [] },
      ],
    })).rejects.toThrow(/Duplicate bundle component path/);
    await expect(exporter.export({
      ...common,
      components: [{
        path: 'redacted.json', mediaType: 'application/json', disposition: 'redacted',
      } as never],
    })).rejects.toThrow(/reason code/);
  });

  it('detects manifest, policy, signature, component, and selection tampering together', async () => {
    const { entries, hasher, signer, policy, policyDigest } = await fixture();
    const bundle = await new AuditReplayBundleExporter({
      hasher, signer, clock: { now: () => 1_750_000_010_000 },
    }).export({
      bundleId: 'bundle_tampering', purpose: 'regulatory-review',
      verificationPolicyDigest: policyDigest,
      selections: [{
        ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
        firstSequence: '0', lastSequence: '2', expectedHeadDigest: entries[2]!.entryDigest,
        checkpointTreeSizes: [],
      }],
      components: [{
        path: 'ledger/entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries,
        disposition: 'included', content: entries,
      }],
    });
    const tampered = structuredClone(bundle);
    tampered.manifest.core.verificationPolicyDigest = `sha256:${'c'.repeat(64)}`;
    tampered.manifest.manifestDigest = `sha256:${'d'.repeat(64)}`;
    tampered.manifest.jws = 'invalid.signature';
    tampered.components[0]!.content = [];

    const report = await verifyAuditBundle(tampered, {
      ...policy,
      acceptedIntegritySuites: ['KYA-AUDIT-JCS-SHA256-JWS-2026'],
      acceptedAlgorithms: ['ES256'],
      authorizedExporters: [{
        ...policy.authorizedExporters[0]!,
        signerKeys: [{ signer: signer.ref, validUntil: 1 }],
      }],
    }, { hasher, signatures: new TestVerifier() });
    expect(report.cryptographicIntegrity.reasonCodes).toEqual(expect.arrayContaining([
      AUDIT_REASON_CODES.UNSUPPORTED_SUITE,
      AUDIT_REASON_CODES.UNSUPPORTED_ALGORITHM,
      AUDIT_REASON_CODES.BUNDLE_EXPORTER_UNAUTHORIZED,
      AUDIT_REASON_CODES.BUNDLE_MANIFEST_DIGEST_MISMATCH,
      AUDIT_REASON_CODES.VERIFICATION_POLICY_MISMATCH,
      AUDIT_REASON_CODES.BUNDLE_SIGNATURE_INVALID,
      AUDIT_REASON_CODES.BUNDLE_COMPONENT_DIGEST_MISMATCH,
    ]));
    expect(report.scopeEvidenceCompleteness.reasonCodes).toContain(
      AUDIT_REASON_CODES.BUNDLE_SELECTION_INCOMPLETE,
    );
  });

  it('reports explicit evidence dispositions without treating a complete ledger range as invalid', async () => {
    const { entries, hasher, signer, policy, policyDigest } = await fixture();
    const bundle = await new AuditReplayBundleExporter({
      hasher, signer, clock: { now: () => 1_750_000_010_000 },
    }).export({
      bundleId: 'bundle_dispositions', purpose: 'regulatory-review',
      verificationPolicyDigest: policyDigest,
      selections: [{
        ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
        firstSequence: '0', lastSequence: '2', expectedHeadDigest: entries[2]!.entryDigest,
        checkpointTreeSizes: [],
      }],
      components: [
        { path: 'entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries, disposition: 'included', content: entries },
        { path: 'pii.json', mediaType: 'application/json', disposition: 'redacted', reasonCode: 'DATA_MINIMIZATION' },
        { path: 'expired.json', mediaType: 'application/json', disposition: 'disposed', reasonCode: 'RETENTION_EXPIRED' },
        { path: 'offline.json', mediaType: 'application/json', disposition: 'unavailable', reasonCode: 'SOURCE_OFFLINE' },
      ],
    });
    const completeness = (await verifyAuditBundle(bundle, policy, {
      hasher, signatures: new TestVerifier(),
    })).scopeEvidenceCompleteness;
    expect(completeness.verdict).toBe('indeterminate');
    expect(completeness.reasonCodes).toEqual(expect.arrayContaining([
      AUDIT_REASON_CODES.EXPLICITLY_REDACTED,
      AUDIT_REASON_CODES.EXPLICITLY_DISPOSED,
      AUDIT_REASON_CODES.EXPLICITLY_UNAVAILABLE,
    ]));
  });

  it('fails closed for malformed checkpoint, Merkle, observation, and anchor components', async () => {
    const { entries, hasher, signer, policy, policyDigest } = await fixture();
    const bundle = await new AuditReplayBundleExporter({
      hasher, signer, clock: { now: () => 1_750_000_010_000 },
    }).export({
      bundleId: 'bundle_malformed_evidence', purpose: 'regulatory-review',
      verificationPolicyDigest: policyDigest,
      selections: [{
        ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
        firstSequence: '0', lastSequence: '2', expectedHeadDigest: entries[2]!.entryDigest,
        checkpointTreeSizes: [],
      }],
      components: [
        { path: 'entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries, disposition: 'included', content: entries },
        { path: 'checkpoints.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.checkpoints, disposition: 'included', content: [{}] },
        { path: 'inclusion.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.inclusionProofs, disposition: 'included', content: [{}] },
        { path: 'consistency.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.consistencyProofs, disposition: 'included', content: [{}] },
        { path: 'observations.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.observations, disposition: 'included', content: [{}] },
        { path: 'anchors.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.anchors, disposition: 'included', content: [{}] },
      ],
    });
    const report = await verifyAuditBundle(bundle, policy, {
      hasher, signatures: new TestVerifier(),
    });
    expect(report.checkpointIntegrity.reasonCodes).toContain(AUDIT_REASON_CODES.SCHEMA_INVALID);
    expect(report.anchorIntegrity.reasonCodes).toContain(AUDIT_REASON_CODES.SCHEMA_INVALID);
  });

  it('verifies observation chains and evaluates supporting-anchor trust separately', async () => {
    const { entries, hasher, signer, policy, policyDigest, journal } = await fixture();
    const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };
    const checkpoint = await new AuditCheckpointBuilder({
      journal, store: new MemoryAuditCheckpointStore(), signer, hasher,
      clock: { now: () => 1_750_000_003_000 },
    }).createCheckpoint(ledger);
    const observer = new MemoryAuditCheckpointObserver({
      observerId: 'observer-1', signer, hasher,
      clock: { now: () => 1_750_000_004_000 },
      verifyCheckpoint: async () => true,
      verifyConsistency: async () => true,
    });
    const first = await observer.publish(checkpoint);
    const brokenLink = structuredClone(first);
    brokenLink.core.observedAt += 1;
    brokenLink.core.previousObservationDigest = `sha256:${'f'.repeat(64)}`;
    const anchorProvider = new MemorySupportingAnchorProvider({
      kind: 'worm', providerId: 'archive-1', clock: { now: () => 1_750_000_005_000 },
    });
    const anchor = await anchorProvider.publish(checkpoint);
    const evidencePolicy: AuditVerificationPolicyV1 = {
      ...policy,
      trustedObservers: [{ signer: signer.ref }],
      trustedSupportingAnchors: [{ kind: 'worm', providerId: 'archive-1' }],
      acceptedIntegritySuites: [
        ...policy.acceptedIntegritySuites,
        'KYA-AUDIT-RFC9162-SHA256-JWS-2026',
      ],
    };
    const evidencePolicyDigest = await hashAuditValue(
      hasher, 'org.kya-os.audit.verification-policy.v1', evidencePolicy,
    );
    const bundle = await new AuditReplayBundleExporter({
      hasher, signer, clock: { now: () => 1_750_000_010_000 },
    }).export({
      bundleId: 'bundle_observed', purpose: 'regulatory-review',
      verificationPolicyDigest: evidencePolicyDigest,
      selections: [{
        ...ledger, firstSequence: '0', lastSequence: '2',
        expectedHeadDigest: entries[2]!.entryDigest,
        checkpointTreeSizes: [checkpoint.core.treeSize],
      }],
      components: [
        { path: 'entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries, disposition: 'included', content: entries },
        { path: 'checkpoint.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.checkpoints, disposition: 'included', content: [checkpoint] },
        { path: 'observations.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.observations, disposition: 'included', content: [first, brokenLink] },
        { path: 'anchors.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.anchors, disposition: 'included', content: [anchor] },
      ],
    });
    const notEvaluated = await verifyAuditBundle(bundle, evidencePolicy, {
      hasher, signatures: new TestVerifier(),
    });
    expect(notEvaluated.anchorIntegrity.reasonCodes).toEqual(expect.arrayContaining([
      AUDIT_REASON_CODES.OBSERVATION_CHAIN_MISMATCH,
      AUDIT_REASON_CODES.NOT_EVALUATED,
    ]));

    const rejected = await verifyAuditBundle(bundle, {
      ...evidencePolicy,
      trustedSupportingAnchors: [],
    }, {
      hasher, signatures: new TestVerifier(), verifySupportingAnchor: async () => false,
    });
    expect(rejected.anchorIntegrity.reasonCodes).toEqual(expect.arrayContaining([
      AUDIT_REASON_CODES.UNTRUSTED_SUPPORTING_ANCHOR,
      AUDIT_REASON_CODES.SUPPORTING_ANCHOR_INVALID,
    ]));
  });

  it('returns a policy-specific invalid report before processing a bundle', async () => {
    const { hasher } = await fixture();
    const report = await verifyAuditBundle({}, { policyId: 'broken-policy' } as never, {
      hasher, signatures: new TestVerifier(),
    });
    expect(report.policyId).toBe('broken-policy');
    expect(report.cryptographicIntegrity).toEqual({
      verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.VERIFICATION_POLICY_INVALID],
    });
  });

  it('round-trips every public signed-artifact parser into an immutable boundary value', async () => {
    const { entries, hasher, signer, policy, policyDigest, journal } = await fixture();
    const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };
    const checkpoint = await new AuditCheckpointBuilder({
      journal, store: new MemoryAuditCheckpointStore(), signer, hasher,
      clock: { now: () => 1_750_000_003_000 },
    }).createCheckpoint(ledger);
    const observation = await new MemoryAuditCheckpointObserver({
      observerId: 'observer-1', signer, hasher,
      clock: { now: () => 1_750_000_004_000 },
      verifyCheckpoint: async () => true,
      verifyConsistency: async () => true,
    }).publish(checkpoint);
    const bundle = await new AuditReplayBundleExporter({
      hasher, signer, clock: { now: () => 1_750_000_010_000 },
    }).export({
      bundleId: 'bundle_parse_roundtrip', purpose: 'regulatory-review',
      verificationPolicyDigest: policyDigest,
      selections: [{
        ...ledger, firstSequence: '0', lastSequence: '2',
        expectedHeadDigest: entries[2]!.entryDigest, checkpointTreeSizes: [],
      }],
      components: [{
        path: 'entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries,
        disposition: 'included', content: entries,
      }],
    });

    const parsed = [
      parseSignedAuditEntry(structuredClone(entries[0]!)),
      parseAuditRecorderReceiptCore(structuredClone(entries[0]!.recorderReceipt.core)),
      parseAuditCheckpointCore(structuredClone(checkpoint.core)),
      parseSignedAuditCheckpoint(structuredClone(checkpoint)),
      parseAuditObservationReceipt(structuredClone(observation)),
      parseAuditReplayBundle(structuredClone(bundle)),
      parseAuditVerificationPolicy(structuredClone(policy)),
    ];
    expect(parsed.every(Object.isFrozen)).toBe(true);
  });

  it('fails a bundle that cannot meet the required audit profile of its policy', async () => {
    const { entries, hasher, signer, policy, journal } = await fixture();
    const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };
    const checkpoint = await new AuditCheckpointBuilder({
      journal, store: new MemoryAuditCheckpointStore(), signer, hasher,
      clock: { now: () => 1_750_000_003_000 },
    }).createCheckpoint(ledger);
    const exportUnder = async (required: AuditVerificationPolicyV1, withCheckpoint: boolean) => {
      const bundle = await new AuditReplayBundleExporter({
        hasher, signer, clock: { now: () => 1_750_000_010_000 },
      }).export({
        bundleId: 'bundle_profile', purpose: 'regulatory-review',
        verificationPolicyDigest: await hashAuditValue(
          hasher, 'org.kya-os.audit.verification-policy.v1', required,
        ),
        selections: [{
          ...ledger, firstSequence: '0', lastSequence: '2',
          expectedHeadDigest: entries[2]!.entryDigest,
          checkpointTreeSizes: withCheckpoint ? [checkpoint.core.treeSize] : [],
        }],
        components: [
          { path: 'entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries, disposition: 'included', content: entries },
          ...(withCheckpoint
            ? [{ path: 'checkpoints.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.checkpoints, disposition: 'included' as const, content: [checkpoint] }]
            : []),
        ],
      });
      return verifyAuditBundle(bundle, required, { hasher, signatures: new TestVerifier() });
    };
    const withSuites = (profile: AuditVerificationPolicyV1['requiredAuditProfile']) => ({
      ...policy,
      acceptedIntegritySuites: [...policy.acceptedIntegritySuites, 'KYA-AUDIT-RFC9162-SHA256-JWS-2026'],
      requiredAuditProfile: profile,
    });

    // The CLI exits 1 exactly when some dimension is invalid.
    const observed = await exportUnder(withSuites('AAP-4'), false);
    expect(observed.checkpointIntegrity.reasonCodes).toContain(AUDIT_REASON_CODES.REQUIRED_PROFILE_UNMET);
    expect(observed.anchorIntegrity.verdict).toBe('invalid');
    const transparent = await exportUnder(withSuites('AAP-3'), true);
    expect(transparent.checkpointIntegrity).toEqual({ verdict: 'valid', reasonCodes: [] });
    expect(transparent.anchorIntegrity.verdict).toBe('indeterminate');
  });

  it('verifies a subset export through inclusion proofs against its signed checkpoint', async () => {
    const { entries, hasher, signer, policy, journal } = await fixture();
    const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };
    const builder = new AuditCheckpointBuilder({
      journal, store: new MemoryAuditCheckpointStore(), signer, hasher,
      clock: { now: () => 1_750_000_003_000 },
    });
    const checkpoint = await builder.createCheckpoint(ledger);
    const proof = await builder.inclusionProof(ledger, '2', checkpoint);
    const checkpointPolicy = {
      ...policy,
      acceptedIntegritySuites: [...policy.acceptedIntegritySuites, 'KYA-AUDIT-RFC9162-SHA256-JWS-2026'],
    };
    const exportSubset = async (proofs: unknown[]) => new AuditReplayBundleExporter({
      hasher, signer, clock: { now: () => 1_750_000_010_000 },
    }).export({
      bundleId: 'bundle_subset', purpose: 'regulatory-review',
      verificationPolicyDigest: await hashAuditValue(
        hasher, 'org.kya-os.audit.verification-policy.v1', checkpointPolicy,
      ),
      selections: [{
        ...ledger, firstSequence: '2', lastSequence: '2',
        expectedHeadDigest: entries[2]!.entryDigest,
        checkpointTreeSizes: [checkpoint.core.treeSize],
      }],
      components: [
        { path: 'entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries, disposition: 'included', content: [entries[2]] },
        { path: 'checkpoints.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.checkpoints, disposition: 'included', content: [checkpoint] },
        { path: 'inclusion-proofs.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.inclusionProofs, disposition: 'included', content: proofs },
      ],
    });

    const proven = await verifyAuditBundle(await exportSubset([{
      ...ledger, sequence: '2', entryDigest: entries[2]!.entryDigest,
      checkpointDigest: checkpoint.checkpointDigest, proof,
    }]), checkpointPolicy, { hasher, signatures: new TestVerifier() });
    expect(proven.cryptographicIntegrity.verdict).toBe('valid');
    expect(proven.chainIntegrity.verdict).toBe('valid');
    expect(proven.checkpointIntegrity).toEqual({ verdict: 'valid', reasonCodes: [] });
    expect(proven.scopeEvidenceCompleteness.verdict).toBe('valid');

    const unproven = await verifyAuditBundle(await exportSubset([]), checkpointPolicy, {
      hasher, signatures: new TestVerifier(),
    });
    expect(unproven.checkpointIntegrity).toEqual({
      verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.MERKLE_PROOF_MISSING],
    });
  });

  it('accepts unlinked checkpoints only when a verified consistency proof binds them', async () => {
    const { hasher, signer, policy, journal } = await fixture();
    const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };
    const builder = new AuditCheckpointBuilder({
      journal, store: new MemoryAuditCheckpointStore(), signer, hasher,
      clock: { now: () => 1_750_000_003_000 },
    });
    const recorder = new AuditRecorderService({
      ...ledger, tenantRef, binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
      sourceId: 'recorder-1', journal, signer, hasher, clock: { now: () => 1_750_000_004_000 },
    });
    const submit = (sequence: number) => recorder.submitAuthenticated({
      ledgerId: ledger.ledgerId, producerEvent: event(sequence), encryptedEvidence: [],
    }, { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef });
    const three = await builder.createCheckpoint(ledger);
    await submit(3);
    await builder.createCheckpoint(ledger); // tree size 4, omitted from the export
    await submit(4);
    const five = await builder.createCheckpoint(ledger);
    const allEntries = await journal.snapshot(ledger);
    const checkpointPolicy = {
      ...policy,
      acceptedIntegritySuites: [...policy.acceptedIntegritySuites, 'KYA-AUDIT-RFC9162-SHA256-JWS-2026'],
    };
    const exportGapped = async (proofs: unknown[]) => new AuditReplayBundleExporter({
      hasher, signer, clock: { now: () => 1_750_000_010_000 },
    }).export({
      bundleId: 'bundle_gapped', purpose: 'regulatory-review',
      verificationPolicyDigest: await hashAuditValue(
        hasher, 'org.kya-os.audit.verification-policy.v1', checkpointPolicy,
      ),
      selections: [{
        ...ledger, firstSequence: '0', lastSequence: '4',
        expectedHeadDigest: allEntries[4]!.entryDigest,
        checkpointTreeSizes: [three.core.treeSize, five.core.treeSize],
      }],
      components: [
        { path: 'entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries, disposition: 'included', content: allEntries },
        { path: 'checkpoints.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.checkpoints, disposition: 'included', content: [three, five] },
        { path: 'consistency-proofs.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.consistencyProofs, disposition: 'included', content: proofs },
      ],
    });
    const consistency = {
      ...ledger, oldCheckpointDigest: three.checkpointDigest,
      newCheckpointDigest: five.checkpointDigest,
      proof: await builder.consistencyProof(ledger, three.core.treeSize, five),
    };

    const bound = await verifyAuditBundle(await exportGapped([consistency]), checkpointPolicy, {
      hasher, signatures: new TestVerifier(),
    });
    expect(bound.checkpointIntegrity).toEqual({ verdict: 'valid', reasonCodes: [] });
    const unbound = await verifyAuditBundle(await exportGapped([]), checkpointPolicy, {
      hasher, signatures: new TestVerifier(),
    });
    expect(unbound.checkpointIntegrity).toEqual({
      verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.CHECKPOINT_CHAIN_MISMATCH],
    });
  });

  it('rejects a predecessor checkpoint signed past the terminal its successor committed', async () => {
    const { journal, epochOne, builder, terminal, epochOneRecorder, verifyRollover } =
      await rolloverFixture();
    expect((await verifyRollover(await journal.snapshot(epochOne), [terminal]))
      .checkpointIntegrity).toEqual({ verdict: 'valid', reasonCodes: [] });

    // The old authority keeps sequencing epoch_1 after the rollover. Its
    // uncommitted tail entries prove nothing; a checkpoint over them does.
    for (let sequence = 3; sequence <= 4; sequence += 1) {
      await epochOneRecorder.submitAuthenticated({
        ledgerId: epochOne.ledgerId, producerEvent: event(sequence), encryptedEvidence: [],
      }, rolloverContext);
    }
    const tail = await journal.snapshot(epochOne);
    expect((await verifyRollover(tail, [terminal])).checkpointIntegrity)
      .toEqual({ verdict: 'valid', reasonCodes: [] });
    const split = await verifyRollover(tail, [terminal, await builder.createCheckpoint(epochOne)]);
    expect(split.cryptographicIntegrity.verdict).toBe('valid');
    expect(split.checkpointIntegrity).toEqual({
      verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.CHECKPOINT_FORK_DETECTED],
    });
  });

  it('accepts the terminal checkpoint lifecycle event that follows the terminal tree', async () => {
    // The builder's hook records `checkpoint.created` after signing, so the
    // event sits at sequence = terminal tree size in the predecessor epoch.
    const { journal, epochOne, terminal, verifyRollover } = await rolloverFixture(true);
    const predecessor = await journal.snapshot(epochOne);
    expect(predecessor.at(-1)?.core).toMatchObject({
      sequence: terminal.core.treeSize,
      event: { eventType: 'checkpoint.created' },
    });

    const report = await verifyRollover(predecessor, [terminal]);
    expect(report.checkpointIntegrity).toEqual({ verdict: 'valid', reasonCodes: [] });
    expect(report.cryptographicIntegrity.verdict).toBe('valid');
    expect(report.chainIntegrity.verdict).toBe('valid');
    expect(report.scopeEvidenceCompleteness.verdict).toBe('valid');
  });

  it('leaves an exporter key bounded by checkpoints indeterminate instead of rejecting it', async () => {
    const { entries, hasher, signer, policy } = await fixture();
    const exportUnder = async (exporterPolicy: AuditVerificationPolicyV1) => {
      const bundle = await new AuditReplayBundleExporter({
        hasher, signer, clock: { now: () => 1_750_000_010_000 },
      }).export({
        bundleId: 'bundle_bounded_exporter', purpose: 'regulatory-review',
        verificationPolicyDigest: await hashAuditValue(
          hasher, 'org.kya-os.audit.verification-policy.v1', exporterPolicy,
        ),
        selections: [{
          ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
          firstSequence: '0', lastSequence: '2', expectedHeadDigest: entries[2]!.entryDigest,
          checkpointTreeSizes: [],
        }],
        components: [{
          path: 'entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries,
          disposition: 'included', content: entries,
        }],
      });
      return verifyAuditBundle(bundle, exporterPolicy, { hasher, signatures: new TestVerifier() });
    };
    const boundedKey = {
      signer: signer.ref, validUntilCheckpoint: `sha256:${'c'.repeat(64)}` as const,
    };
    const bounded: AuditVerificationPolicyV1 = {
      ...policy,
      authorizedExporters: [{ ...policy.authorizedExporters[0]!, signerKeys: [boundedKey] }],
    };

    // An export has no ledger position to place it against the bound.
    const report = await exportUnder(bounded);
    expect(report.cryptographicIntegrity).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.KEY_BOUNDARY_UNRESOLVED],
    });
    expect(report.chainIntegrity.verdict).toBe('valid');
    expect(report.scopeEvidenceCompleteness.verdict).toBe('valid');

    // An unbounded key that authorizes the same export decides it.
    const alsoUnbounded: AuditVerificationPolicyV1 = {
      ...policy,
      authorizedExporters: [{
        ...policy.authorizedExporters[0]!, signerKeys: [boundedKey, { signer: signer.ref }],
      }],
    };
    expect((await exportUnder(alsoUnbounded)).cryptographicIntegrity)
      .toEqual({ verdict: 'valid', reasonCodes: [] });
  });

  it('holds exporter and observer keys to their current status under current and both', async () => {
    const { entries, hasher, signer, policy, journal } = await fixture();
    const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };
    const checkpoint = await new AuditCheckpointBuilder({
      journal, store: new MemoryAuditCheckpointStore(), signer, hasher,
      clock: { now: () => 1_750_000_003_000 },
    }).createCheckpoint(ledger);
    const observation = await new MemoryAuditCheckpointObserver({
      observerId: 'observer-1', signer, hasher,
      clock: { now: () => 1_750_000_004_000 },
      verifyCheckpoint: async () => true,
      verifyConsistency: async () => true,
    }).publish(checkpoint);
    // Both keys were valid when they signed and were revoked afterwards.
    const revokedAt = 1_750_000_020_000;
    const under = (
      keyRevocationMode: AuditVerificationPolicyV1['keyRevocationMode'],
      revoke: 'exporter' | 'observer',
    ): AuditVerificationPolicyV1 => ({
      ...policy,
      keyRevocationMode,
      acceptedIntegritySuites: [...policy.acceptedIntegritySuites, 'KYA-AUDIT-RFC9162-SHA256-JWS-2026'],
      trustedObservers: [{
        signer: signer.ref, ...(revoke === 'observer' ? { validUntil: revokedAt } : {}),
      }],
      authorizedExporters: [{
        ...policy.authorizedExporters[0]!,
        signerKeys: [{
          signer: signer.ref, ...(revoke === 'exporter' ? { validUntil: revokedAt } : {}),
        }],
      }],
    });
    const verifyUnder = async (bundlePolicy: AuditVerificationPolicyV1, now: number) => {
      const bundle = await new AuditReplayBundleExporter({
        hasher, signer, clock: { now: () => 1_750_000_010_000 },
      }).export({
        bundleId: 'bundle_current_keys', purpose: 'regulatory-review',
        verificationPolicyDigest: await hashAuditValue(
          hasher, 'org.kya-os.audit.verification-policy.v1', bundlePolicy,
        ),
        selections: [{
          ...ledger, firstSequence: '0', lastSequence: '2',
          expectedHeadDigest: entries[2]!.entryDigest,
          checkpointTreeSizes: [checkpoint.core.treeSize],
        }],
        components: [
          { path: 'entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries, disposition: 'included', content: entries },
          { path: 'checkpoints.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.checkpoints, disposition: 'included', content: [checkpoint] },
          { path: 'observations.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.observations, disposition: 'included', content: [observation] },
        ],
      });
      return verifyAuditBundle(bundle, bundlePolicy, {
        hasher,
        signatures: new TestVerifier(),
        artifacts: new AuditArtifactVerifier({
          hasher, signatures: new TestVerifier(), verifiedAt: () => now,
        }),
      });
    };
    const notCurrent = {
      verdict: 'invalid',
      reasonCodes: [
        AUDIT_REASON_CODES.CURRENT_AUTHORIZATION_NOT_EVALUATED,
        AUDIT_REASON_CODES.KEY_NOT_CURRENT,
      ],
    };

    for (const revoke of ['exporter', 'observer'] as const) {
      const historical = await verifyUnder(under('as_observed', revoke), revokedAt + 1);
      expect(historical.cryptographicIntegrity.verdict).toBe('valid');
      expect(historical.anchorIntegrity.verdict).toBe('valid');
      expect(historical.currentAuthorization).toEqual({
        verdict: 'indeterminate',
        reasonCodes: [AUDIT_REASON_CODES.CURRENT_AUTHORIZATION_NOT_EVALUATED],
      });
      for (const mode of ['current', 'both'] as const) {
        const report = await verifyUnder(under(mode, revoke), revokedAt + 1);
        expect(report.cryptographicIntegrity.verdict).toBe('valid');
        expect(report.anchorIntegrity.verdict).toBe('valid');
        expect(report.currentAuthorization).toEqual(notCurrent);
      }
      // Before the revocation the key is current, which alone proves nothing
      // about current authorization.
      expect((await verifyUnder(under('current', revoke), revokedAt - 1)).currentAuthorization)
        .toEqual(historical.currentAuthorization);
    }
  });
});
