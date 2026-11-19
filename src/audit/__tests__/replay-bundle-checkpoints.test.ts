import { describe, expect, it } from 'vitest';
import { canonicalizeJson } from '../../utils/canonical-json.js';
import { hashAuditValue } from '../crypto.js';
import { AUDIT_DIGEST_DOMAINS } from '../integrity.js';
import {
  AuditReplayBundleExporter,
  verifyAuditBundle,
  AUDIT_BUNDLE_MEDIA_TYPES,
} from '../replay-bundle.js';
import { AuditRecorderService } from '../recorder-service.js';
import { AUDIT_REASON_CODES } from '../verifier.js';
import { AuditCheckpointBuilder, MemoryAuditCheckpointStore } from '../checkpoint.js';
import type { AuditVerificationPolicyV1 } from '../types.js';
import { TestVerifier, tenantRef, event, fixture, rolloverContext, rolloverFixture } from './replay-bundle-fixtures.js';

describe('signed replay bundles: checkpoints and Merkle proofs', () => {
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
    // No checkpoint holds the selected epoch_2 entries, so the dimension is at
    // best indeterminate; what this test holds is whether a fork is reported.
    const unforked = {
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.CHECKPOINT_MISSING],
    };
    expect((await verifyRollover(await journal.snapshot(epochOne), [terminal]))
      .checkpointIntegrity).toEqual(unforked);

    // The old authority keeps sequencing epoch_1 after the rollover. Its
    // uncommitted tail entries prove nothing; a checkpoint over them does.
    for (let sequence = 3; sequence <= 4; sequence += 1) {
      await epochOneRecorder.submitAuthenticated({
        ledgerId: epochOne.ledgerId, producerEvent: event(sequence), encryptedEvidence: [],
      }, rolloverContext);
    }
    const tail = await journal.snapshot(epochOne);
    expect((await verifyRollover(tail, [terminal])).checkpointIntegrity).toEqual(unforked);
    const split = await verifyRollover(tail, [terminal, await builder.createCheckpoint(epochOne)]);
    expect(split.cryptographicIntegrity.verdict).toBe('valid');
    expect(split.checkpointIntegrity).toEqual({
      verdict: 'invalid',
      reasonCodes: [
        AUDIT_REASON_CODES.CHECKPOINT_FORK_DETECTED,
        AUDIT_REASON_CODES.CHECKPOINT_MISSING,
      ],
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
    // The lifecycle event, and the epoch_2 entries, sit in no checkpoint: the
    // dimension is indeterminate for that, and reports no fork.
    expect(report.checkpointIntegrity).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.CHECKPOINT_MISSING],
    });
    expect(report.cryptographicIntegrity.verdict).toBe('valid');
    expect(report.chainIntegrity.verdict).toBe('valid');
    expect(report.scopeEvidenceCompleteness.verdict).toBe('valid');
  });
});
