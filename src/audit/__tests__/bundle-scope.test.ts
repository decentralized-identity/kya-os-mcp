/**
 * A replay bundle's scope: the ledger ranges its signed manifest selects, and the components it
 * says it left out. The verifier reports what a bundle omits, and never reports a bundle complete
 * without saying so.
 */

import { describe, expect, it } from 'vitest';
import { AuditCheckpointBuilder, MemoryAuditCheckpointStore } from '../checkpoint.js';
import { MemoryAuditCheckpointObserver } from '../providers/observer.js';
import { AuditRecorderService } from '../recorder-service.js';
import type { AuditBundleDisposition, AuditVerificationPolicyV1 } from '../types.js';
import { AUDIT_REASON_CODES } from '../verifier.js';
import { history, producerEvent, recordedHistory, tenantRef } from './audit-fixtures.js';
import {
  bundlePolicy,
  exportBundle,
  hasher,
  included,
  selectionOf,
  signer,
  verifyBundle,
} from './bundle-fixtures.js';

const OUTSIDE = AUDIT_REASON_CODES.BUNDLE_CONTENT_OUTSIDE_SELECTION;

/**
 * The recorded history of the primary ledger, and a second ledger the same recorder keeps, with a
 * checkpoint, an observation and an inclusion proof of the second. The policy trusts the recorder
 * for both ledgers and authorizes the exporter for the primary ledger only.
 */
async function twoLedgers() {
  const { journal, entries } = await recordedHistory();
  const secondaryLedger = { ledgerId: 'kya:tenant:prod:secondary', ledgerEpochId: 'epoch_1' };
  const recorder = new AuditRecorderService({
    ...secondaryLedger, tenantRef, binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    sourceId: 'recorder-2', journal, signer, hasher, clock: { now: () => 1_750_000_001_000 },
  });
  for (let index = 1; index <= 3; index += 1) {
    await recorder.submitAuthenticated({
      ledgerId: secondaryLedger.ledgerId, producerEvent: producerEvent(`evt_b${index}`, index), encryptedEvidence: [],
    }, { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef });
  }
  const builder = new AuditCheckpointBuilder({
    journal, store: new MemoryAuditCheckpointStore(), signer, hasher, clock: { now: () => 1_750_000_002_000 },
  });
  const checkpoint = await builder.createCheckpoint(secondaryLedger);
  const secondary = await journal.snapshot(secondaryLedger);
  const observation = await new MemoryAuditCheckpointObserver({
    observerId: 'observer-1', signer, hasher, clock: { now: () => 1_750_000_003_000 },
    verifyCheckpoint: async () => true, verifyConsistency: async () => true,
  }).publish(checkpoint);
  const inclusion = {
    ...secondaryLedger, sequence: '1', entryDigest: secondary[1]!.entryDigest,
    checkpointDigest: checkpoint.checkpointDigest,
    proof: await builder.inclusionProof(secondaryLedger, '1', checkpoint),
  };
  const twoLedgerPolicy: AuditVerificationPolicyV1 = {
    ...bundlePolicy,
    trustedLedgerEpochs: [
      ...bundlePolicy.trustedLedgerEpochs,
      { ...secondaryLedger, recorderKeys: [{ signer: signer.ref }] },
    ],
    trustedObservers: [{ signer: signer.ref }],
  };
  return { primary: entries, secondary, checkpoint, observation, inclusion, twoLedgerPolicy };
}

describe('the components a bundle leaves out', () => {
  const omitting = async (disposition: Exclude<AuditBundleDisposition, 'included'>) => {
    const entries = await history();
    return (await verifyBundle(await exportBundle([selectionOf(entries)], [
      included('entries', entries),
      { path: 'evidence/approval.bin', mediaType: 'application/octet-stream', disposition, reasonCode: 'WITHHELD' },
    ]))).scopeEvidenceCompleteness;
  };

  it('reports each disposition as its own reason, and the scope as indeterminate', async () => {
    expect(await omitting('redacted')).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.EXPLICITLY_REDACTED],
    });
    expect(await omitting('disposed')).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.EXPLICITLY_DISPOSED],
    });
    expect(await omitting('unavailable')).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.EXPLICITLY_UNAVAILABLE],
    });
    expect(await omitting('policy_excluded')).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.EXPLICITLY_POLICY_EXCLUDED],
    });
  });

  it('reports a bundle that leaves nothing out as complete', async () => {
    const entries = await history();
    expect((await verifyBundle(await exportBundle([selectionOf(entries)], [
      included('entries', entries),
    ]))).scopeEvidenceCompleteness).toEqual({ verdict: 'valid', reasonCodes: [] });
  });
});

describe('what a bundle carries beyond the selections its manifest declares', () => {
  it('does not report a bundle complete when it carries a slice of a ledger no selection names', async () => {
    const { primary, secondary, twoLedgerPolicy } = await twoLedgers();
    const report = await verifyBundle(await exportBundle([selectionOf(primary)], [
      included('entries', [...primary, ...secondary.slice(1, 3)]),
    ], twoLedgerPolicy), twoLedgerPolicy);

    expect(report.cryptographicIntegrity.verdict).toBe('valid');
    expect(report.scopeEvidenceCompleteness).toEqual({ verdict: 'invalid', reasonCodes: [OUTSIDE] });
  });

  it('does not report a bundle complete when it carries entries past the range it selects', async () => {
    const entries = await history();
    const report = await verifyBundle(await exportBundle([selectionOf(entries.slice(0, 2))], [
      included('entries', entries),
    ]));

    expect(report.scopeEvidenceCompleteness.verdict).toBe('invalid');
    expect(report.scopeEvidenceCompleteness.reasonCodes).toContain(OUTSIDE);
  });

  it.each([
    ['checkpoint', 'checkpoints'],
    ['observation', 'observations'],
    ['inclusion proof', 'inclusionProofs'],
  ] as const)('does not report a bundle complete when it carries a %s of a ledger no selection names', async (
    _kind, mediaType,
  ) => {
    const ledgers = await twoLedgers();
    const carried = { checkpoints: ledgers.checkpoint, observations: ledgers.observation, inclusionProofs: ledgers.inclusion };
    const report = await verifyBundle(await exportBundle([selectionOf(ledgers.primary)], [
      included('entries', ledgers.primary),
      included(mediaType, [carried[mediaType]]),
    ], ledgers.twoLedgerPolicy), ledgers.twoLedgerPolicy);

    expect(report.scopeEvidenceCompleteness).toEqual({ verdict: 'invalid', reasonCodes: [OUTSIDE] });
  });

  it('accepts what sits inside a selection: entries in its range, and the checkpoint over them', async () => {
    const { secondary, checkpoint, observation, inclusion, twoLedgerPolicy } = await twoLedgers();
    const secondaryExport: AuditVerificationPolicyV1 = {
      ...twoLedgerPolicy,
      authorizedExporters: [{
        ...twoLedgerPolicy.authorizedExporters[0]!, allowedLedgerIds: [checkpoint.core.ledgerId],
      }],
    };
    const report = await verifyBundle(await exportBundle(
      [selectionOf(secondary.slice(1, 2), [checkpoint.core.treeSize])],
      [
        included('entries', secondary.slice(1, 2)),
        included('checkpoints', [checkpoint]),
        included('observations', [observation]),
        included('inclusionProofs', [inclusion]),
      ],
      secondaryExport,
    ), secondaryExport);

    expect(report.cryptographicIntegrity.verdict).toBe('valid');
    expect(report.scopeEvidenceCompleteness).toEqual({ verdict: 'valid', reasonCodes: [] });
  });
});
