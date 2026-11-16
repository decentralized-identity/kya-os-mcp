/**
 * The audit verifiers, the recorder, the observer and the evidence store each ask a dependency the
 * host supplies for a verdict its type promises as a boolean: a signature verifier, a supporting
 * anchor verifier, a checkpoint and a consistency verifier, a submission authorizer, an epoch
 * transition guard and an evidence access policy. Each verdict passes only on the literal `true`.
 * Any other answer, which untyped code or a fault can give, is a signature that did not verify, an
 * anchor that is invalid, a checkpoint refused, a submission or an access denied.
 */

import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { NOT_TRUE } from '../../__tests__/utils/verdict-answers.js';
import { AuditCheckpointBuilder, MemoryAuditCheckpointStore } from '../checkpoint.js';
import type { AuditSignatureVerifier } from '../crypto.js';
import { CryptoProviderAuditHasher, hashAuditValue } from '../crypto.js';
import { MemoryAuditEvidenceProvider } from '../evidence.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { MemoryAuditCheckpointObserver } from '../providers/observer.js';
import { MemorySupportingAnchorProvider } from '../providers/anchor.js';
import { AuditRecorderService } from '../recorder-service.js';
import { AUDIT_BUNDLE_MEDIA_TYPES, AuditReplayBundleExporter, verifyAuditBundle } from '../replay-bundle.js';
import type { AuditVerificationPolicyV1 } from '../types.js';
import { AuditArtifactVerifier, AUDIT_REASON_CODES } from '../verifier.js';
import { policy, producerEvent, recordedHistory, tenantRef, TestSignatureVerifier, TestSigner } from './audit-fixtures.js';

const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
const signer = new TestSigner();
const SUBMITTER = { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef };

/** A dependency method that answers `answer`, whatever it is asked. */
const answering = (answer: unknown) => (async () => answer) as never;
const signatures = (answer: unknown): AuditSignatureVerifier => ({ verify: answering(answer) });

/** The recorded history with a checkpoint over it and one observer's receipt for that checkpoint. */
async function observedHistory() {
  const { journal, ledger, entries } = await recordedHistory();
  const checkpoints = new AuditCheckpointBuilder({
    journal, store: new MemoryAuditCheckpointStore(), signer, hasher, clock: { now: () => 1_750_000_002_000 },
  });
  const checkpoint = await checkpoints.createCheckpoint(ledger);
  const receipt = await new MemoryAuditCheckpointObserver({
    observerId: 'observer-1', signer, hasher, clock: { now: () => 1_750_000_003_000 },
    verifyCheckpoint: async () => true, verifyConsistency: async () => true,
  }).publish(checkpoint);
  return { journal, ledger, entries, checkpoints, checkpoint, receipt };
}

const observedPolicy: AuditVerificationPolicyV1 = { ...policy, trustedObservers: [{ signer: signer.ref }] };

describe.each(NOT_TRUE)('a signature verifier that answers %s', (_label, answer) => {
  const verifier = new AuditArtifactVerifier({ hasher, signatures: signatures(answer) });

  it('leaves an entry, a checkpoint and an observation with a signature that did not verify', async () => {
    const { entries, checkpoint, receipt } = await observedHistory();
    expect((await verifier.verifyEntries(entries, policy)).cryptographicIntegrity).toEqual({
      verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.SIGNATURE_INVALID],
    });
    expect(await verifier.verifySignedCheckpoint(checkpoint, policy)).toEqual({
      verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.CHECKPOINT_SIGNATURE_INVALID],
    });
    expect((await verifier.verifyObservation(checkpoint, receipt, observedPolicy)).reasonCodes)
      .toContain(AUDIT_REASON_CODES.OBSERVATION_SIGNATURE_INVALID);
  });
});

describe('a signature verifier that answers the literal true', () => {
  it('verifies an entry, a checkpoint and an observation', async () => {
    const verifier = new AuditArtifactVerifier({ hasher, signatures: signatures(true) });
    const { entries, checkpoint, receipt } = await observedHistory();
    expect((await verifier.verifyEntries(entries, policy)).cryptographicIntegrity).toEqual({ verdict: 'valid', reasonCodes: [] });
    expect(await verifier.verifySignedCheckpoint(checkpoint, policy)).toEqual({ verdict: 'valid', reasonCodes: [] });
    expect((await verifier.verifyObservation(checkpoint, receipt, observedPolicy)).reasonCodes)
      .not.toContain(AUDIT_REASON_CODES.OBSERVATION_SIGNATURE_INVALID);
  });
});

describe('verifyAuditBundle', () => {
  /** A bundle of the recorded history, its checkpoint and one supporting anchor, with the policy that accepts it. */
  async function bundled() {
    const { ledger, entries, checkpoint } = await observedHistory();
    const anchor = await new MemorySupportingAnchorProvider({
      kind: 'worm', providerId: 'archive-1', clock: { now: () => 1_750_000_005_000 },
    }).publish(checkpoint);
    const bundlePolicy: AuditVerificationPolicyV1 = {
      ...policy,
      authorizedExporters: [{
        signerKeys: [{ signer: signer.ref }], allowedLedgerIds: [ledger.ledgerId], allowedPurposes: ['regulatory-review'],
      }],
      trustedSupportingAnchors: [{ kind: 'worm', providerId: 'archive-1' }],
      acceptedIntegritySuites: [...policy.acceptedIntegritySuites, 'KYA-AUDIT-BUNDLE-JCS-SHA256-JWS-2026'],
    };
    const bundle = await new AuditReplayBundleExporter({ hasher, signer, clock: { now: () => 1_750_000_010_000 } }).export({
      bundleId: 'bundle_verdicts', purpose: 'regulatory-review',
      verificationPolicyDigest: await hashAuditValue(hasher, 'org.kya-os.audit.verification-policy.v1', bundlePolicy),
      selections: [{
        ...ledger, firstSequence: '0', lastSequence: String(entries.length - 1),
        expectedHeadDigest: entries.at(-1)!.entryDigest, checkpointTreeSizes: [checkpoint.core.treeSize],
      }],
      components: [
        { path: 'entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries, disposition: 'included', content: entries },
        { path: 'checkpoint.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.checkpoints, disposition: 'included', content: [checkpoint] },
        { path: 'anchors.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.anchors, disposition: 'included', content: [anchor] },
      ],
    });
    return { bundle, bundlePolicy };
  }

  it('verifies the bundle and its anchor when both verifiers answer the literal true', async () => {
    const { bundle, bundlePolicy } = await bundled();
    const report = await verifyAuditBundle(bundle, bundlePolicy, {
      hasher, signatures: new TestSignatureVerifier(), verifySupportingAnchor: async () => true,
    });
    expect(report.cryptographicIntegrity).toEqual({ verdict: 'valid', reasonCodes: [] });
    expect(report.anchorIntegrity.reasonCodes).not.toContain(AUDIT_REASON_CODES.SUPPORTING_ANCHOR_INVALID);
  });

  it.each(NOT_TRUE)('finds the bundle signature invalid when the signature verifier answers %s', async (_label, answer) => {
    const { bundle, bundlePolicy } = await bundled();
    const report = await verifyAuditBundle(bundle, bundlePolicy, {
      hasher, signatures: signatures(answer), artifacts: new AuditArtifactVerifier({ hasher, signatures: new TestSignatureVerifier() }),
    });
    expect(report.cryptographicIntegrity).toEqual({ verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.BUNDLE_SIGNATURE_INVALID] });
  });

  it.each(NOT_TRUE)('finds the supporting anchor invalid when its verifier answers %s', async (_label, answer) => {
    const { bundle, bundlePolicy } = await bundled();
    const report = await verifyAuditBundle(bundle, bundlePolicy, {
      hasher, signatures: new TestSignatureVerifier(), verifySupportingAnchor: answering(answer),
    });
    expect(report.anchorIntegrity.verdict).toBe('invalid');
    expect(report.anchorIntegrity.reasonCodes).toContain(AUDIT_REASON_CODES.SUPPORTING_ANCHOR_INVALID);
  });
});

describe('MemoryAuditCheckpointObserver', () => {
  const observer = (verifyCheckpoint: unknown, verifyConsistency: unknown) => new MemoryAuditCheckpointObserver({
    observerId: 'observer-1', signer, hasher, clock: { now: () => 1_750_000_003_000 },
    verifyCheckpoint: answering(verifyCheckpoint), verifyConsistency: answering(verifyConsistency),
  });

  /** A checkpoint and the next one, over one more entry of the same ledger. */
  async function successiveCheckpoints() {
    const { journal, ledger, checkpoints, checkpoint } = await observedHistory();
    await new AuditRecorderService({
      ...ledger, tenantRef, binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'recorder-1',
      journal, signer, hasher, clock: { now: () => 1_750_000_004_000 },
    }).submitAuthenticated({ ledgerId: ledger.ledgerId, producerEvent: producerEvent('evt_4', 4), encryptedEvidence: [] }, SUBMITTER);
    return { first: checkpoint, next: await checkpoints.createCheckpoint(ledger) };
  }

  it('observes a checkpoint and its successor when both verifiers answer the literal true', async () => {
    const { first, next } = await successiveCheckpoints();
    const observing = observer(true, true);
    await expect(observing.publish(first)).resolves.toBeDefined();
    await expect(observing.publish(next)).resolves.toBeDefined();
  });

  it.each(NOT_TRUE)('refuses a checkpoint its verifier answers %s for', async (_label, answer) => {
    const { first } = await successiveCheckpoints();
    await expect(observer(answer, true).publish(first)).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_INVALID' });
  });

  it.each(NOT_TRUE)('refuses a successor its consistency verifier answers %s for', async (_label, answer) => {
    const { first, next } = await successiveCheckpoints();
    const observing = observer(true, answer);
    await observing.publish(first);
    await expect(observing.publish(next)).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_CONFLICT' });
  });
});

describe('AuditRecorderService', () => {
  const recorder = (config: object) => new AuditRecorderService({
    ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1', tenantRef,
    binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'recorder-1',
    journal: new MemoryAuditJournal(), signer, hasher, clock: { now: () => 1_750_000_001_000 },
    ...config,
  });
  const submit = (service: AuditRecorderService) => service.submitAuthenticated(
    { ledgerId: 'kya:tenant:prod:primary', producerEvent: producerEvent('evt_1', 1), encryptedEvidence: [] }, SUBMITTER,
  );
  const successor = (verifyAndSeal: unknown) => recorder({
    ledgerEpochId: 'epoch_2', previousEpochId: 'epoch_1', previousTerminalCheckpointDigest: `sha256:${'c'.repeat(64)}`,
    epochTransitionGuard: { verifyAndSeal: answering(verifyAndSeal) },
  });

  it('records a submission its authorizer answers the literal true for, in an epoch its guard sealed with true', async () => {
    await expect(submit(recorder({ authorizer: { authorize: answering(true) } }))).resolves.toBeDefined();
    await expect(submit(successor(true))).resolves.toBeDefined();
  });

  it.each(NOT_TRUE)('refuses a submission its authorizer answers %s for', async (_label, answer) => {
    await expect(submit(recorder({ authorizer: { authorize: answering(answer) } })))
      .rejects.toMatchObject({ code: 'AUDIT_UNAUTHORIZED_SUBMISSION' });
  });

  it.each(NOT_TRUE)('opens no successor epoch its transition guard answers %s for', async (_label, answer) => {
    await expect(submit(successor(answer))).rejects.toMatchObject({ code: 'AUDIT_INVALID_CONFIGURATION' });
  });
});

describe('MemoryAuditEvidenceProvider', () => {
  const ref = { objectId: 'evidence-1' } as never;
  const access = { actor: 'auditor', purpose: 'regulatory-review' };

  it('lets a read through to the store when its access policy answers the literal true', async () => {
    await expect(new MemoryAuditEvidenceProvider(hasher, { authorizeAccess: answering(true) }).get(ref, access)).resolves.toBeNull();
  });

  it.each(NOT_TRUE)('denies a read its access policy answers %s for', async (_label, answer) => {
    await expect(new MemoryAuditEvidenceProvider(hasher, { authorizeAccess: answering(answer) }).get(ref, access))
      .rejects.toMatchObject({ code: 'AUDIT_EVIDENCE_ACCESS_DENIED' });
  });
});
