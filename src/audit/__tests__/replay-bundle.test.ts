import { describe, expect, it } from 'vitest';
import { canonicalizeJson } from '../../utils/canonical-json.js';
import {
  AuditReplayBundleExporter,
  verifyAuditBundle,
  AUDIT_BUNDLE_MEDIA_TYPES,
} from '../replay-bundle.js';
import { AuditArtifactVerifier, AUDIT_REASON_CODES } from '../verifier.js';
import { AuditCheckpointBuilder, MemoryAuditCheckpointStore } from '../checkpoint.js';
import { MemoryAuditCheckpointObserver } from '../providers/observer.js';
import {
  parseAuditCheckpointCore,
  parseAuditObservationReceipt,
  parseAuditRecorderReceiptCore,
  parseAuditReplayBundle,
  parseAuditVerificationPolicy,
  parseSignedAuditCheckpoint,
  parseSignedAuditEntry,
} from '../schemas.js';
import { TestVerifier, fixture } from './replay-bundle-fixtures.js';

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
