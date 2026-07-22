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
});
