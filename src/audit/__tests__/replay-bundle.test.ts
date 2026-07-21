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
import type {
  AuditProducerEventCoreV1,
  AuditVerificationPolicyV1,
  PartyRef,
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
    }, { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1' });
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
    });
    await epochTwoRecorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary', producerEvent: event(3), encryptedEvidence: [],
    }, { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1' });
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
    }, { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1' });
    const second = structuredClone(await builder.createCheckpoint(ledger));
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
      ],
    });
    const report = await verifyAuditBundle(bundle, checkpointPolicy, {
      hasher, signatures: new TestVerifier(),
    });
    expect(report.checkpointIntegrity.verdict).toBe('invalid');
    expect(report.checkpointIntegrity.reasonCodes).toContain(
      AUDIT_REASON_CODES.CHECKPOINT_CHAIN_MISMATCH,
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
});
