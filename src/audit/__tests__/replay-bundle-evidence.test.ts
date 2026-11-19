import { describe, expect, it } from 'vitest';
import { hashAuditValue } from '../crypto.js';
import {
  AuditReplayBundleExporter,
  verifyAuditBundle,
  AUDIT_BUNDLE_MEDIA_TYPES,
} from '../replay-bundle.js';
import { AuditArtifactVerifier, AUDIT_REASON_CODES } from '../verifier.js';
import { AuditCheckpointBuilder, MemoryAuditCheckpointStore } from '../checkpoint.js';
import { MemoryAuditCheckpointObserver } from '../providers/observer.js';
import { MemorySupportingAnchorProvider } from '../providers/anchor.js';
import type { AuditVerificationPolicyV1 } from '../types.js';
import { TestVerifier, fixture } from './replay-bundle-fixtures.js';

describe('signed replay bundles: observations, anchors, profiles and key status', () => {
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
    const { entries, hasher, signer, policy, journal } = await fixture();
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
    const observedBundle = (observations: unknown[]) => new AuditReplayBundleExporter({
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
        { path: 'observations.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.observations, disposition: 'included', content: observations },
        { path: 'anchors.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.anchors, disposition: 'included', content: [anchor] },
      ],
    });
    // A trusted anchor no verifier was given for leaves anchor integrity undecided.
    const observed = await observedBundle([first]);
    const anchoredOnly = await verifyAuditBundle(observed, evidencePolicy, {
      hasher, signatures: new TestVerifier(),
    });
    expect(anchoredOnly.anchorIntegrity).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.NOT_EVALUATED],
    });

    const notEvaluated = await verifyAuditBundle(await observedBundle([first, brokenLink]), evidencePolicy, {
      hasher, signatures: new TestVerifier(),
    });
    expect(notEvaluated.anchorIntegrity).toEqual({
      verdict: 'invalid',
      reasonCodes: [
        AUDIT_REASON_CODES.NOT_EVALUATED,
        AUDIT_REASON_CODES.OBSERVATION_CHAIN_MISMATCH,
        AUDIT_REASON_CODES.OBSERVATION_DIGEST_MISMATCH,
        AUDIT_REASON_CODES.OBSERVATION_SIGNATURE_INVALID,
      ],
    });

    const rejected = await verifyAuditBundle(observed, {
      ...evidencePolicy,
      trustedSupportingAnchors: [],
    }, {
      hasher, signatures: new TestVerifier(), verifySupportingAnchor: async () => false,
    });
    expect(rejected.anchorIntegrity).toEqual({
      verdict: 'invalid',
      reasonCodes: [
        AUDIT_REASON_CODES.SUPPORTING_ANCHOR_INVALID,
        AUDIT_REASON_CODES.UNTRUSTED_SUPPORTING_ANCHOR,
      ],
    });
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
      // Nothing dates an export: once its key has ended, the manifest is undecided.
      const exported = revoke === 'exporter' ? 'indeterminate' : 'valid';
      const historical = await verifyUnder(under('as_observed', revoke), revokedAt + 1);
      expect(historical.cryptographicIntegrity.verdict).toBe(exported);
      expect(historical.anchorIntegrity.verdict).toBe('valid');
      expect(historical.currentAuthorization).toEqual({
        verdict: 'indeterminate',
        reasonCodes: [AUDIT_REASON_CODES.CURRENT_AUTHORIZATION_NOT_EVALUATED],
      });
      for (const mode of ['current', 'both'] as const) {
        const report = await verifyUnder(under(mode, revoke), revokedAt + 1);
        expect(report.cryptographicIntegrity.verdict).toBe(exported);
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
