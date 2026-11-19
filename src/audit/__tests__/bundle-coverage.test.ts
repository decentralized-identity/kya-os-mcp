/**
 * A replay bundle's checkpoint and observation verdicts speak for the entries it selects. They are
 * `valid` only when a checkpoint of each selected ledger epoch holds every entry selected, and an
 * independent observer saw such a checkpoint; an assurance profile that needs a supporting anchor
 * needs one for such a checkpoint. A checkpoint over an earlier tree, or of another epoch, is no
 * evidence about entries it does not hold.
 */

import { describe, expect, it } from 'vitest';
import { AuditCheckpointBuilder, MemoryAuditCheckpointStore } from '../checkpoint.js';
import { MemorySupportingAnchorProvider } from '../providers/anchor.js';
import { MemoryAuditCheckpointObserver } from '../providers/observer.js';
import { AuditRecorderService } from '../recorder-service.js';
import type { AuditLedgerRef, AuditVerificationPolicyV1 } from '../types.js';
import { AUDIT_REASON_CODES } from '../verifier.js';
import { producerEvent, recordedHistory, tenantRef } from './audit-fixtures.js';
import {
  bundlePolicy,
  exportBundle,
  hasher,
  included,
  selectionOf,
  signer,
  verifyBundle,
} from './bundle-fixtures.js';

const SUBMITTER = { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef };
const BINDING = 'urn:kya-os:audit-binding:mcp:2025-11-25';

const coveragePolicy: AuditVerificationPolicyV1 = {
  ...bundlePolicy,
  trustedObservers: [{ signer: signer.ref }],
  trustedSupportingAnchors: [{ kind: 'worm', providerId: 'archive-1' }],
};

/**
 * The recorded history with a checkpoint over its first four entries, a fifth entry, and a second
 * checkpoint over all five; one observer's receipt and one anchor receipt for each checkpoint.
 */
async function grownHistory() {
  const { journal, ledger } = await recordedHistory();
  const builder = new AuditCheckpointBuilder({
    journal, store: new MemoryAuditCheckpointStore(), signer, hasher, clock: { now: () => 1_750_000_002_000 },
  });
  const earlier = await builder.createCheckpoint(ledger);
  await new AuditRecorderService({
    ...ledger, tenantRef, binding: BINDING, sourceId: 'recorder-1', journal, signer, hasher,
    clock: { now: () => 1_750_000_002_500 },
  }).submitAuthenticated({
    ledgerId: ledger.ledgerId, producerEvent: producerEvent('evt_4', 4), encryptedEvidence: [],
  }, SUBMITTER);
  const later = await builder.createCheckpoint(ledger);
  const observer = new MemoryAuditCheckpointObserver({
    observerId: 'observer-1', signer, hasher, clock: { now: () => 1_750_000_003_000 },
    verifyCheckpoint: async () => true, verifyConsistency: async () => true,
  });
  const anchors = new MemorySupportingAnchorProvider({
    kind: 'worm', providerId: 'archive-1', clock: { now: () => 1_750_000_004_000 },
  });
  return {
    ledger,
    entries: await journal.snapshot(ledger),
    earlier,
    later,
    observedEarlier: await observer.publish(earlier),
    observedLater: await observer.publish(later),
    anchoredEarlier: await anchors.publish(earlier),
    anchoredLater: await anchors.publish(later),
    anchors,
  };
}

describe('checkpoint integrity of a bundle', () => {
  it('stays indeterminate while the entries selected run past every checkpoint', async () => {
    const { entries, earlier } = await grownHistory();
    const bundle = await exportBundle([selectionOf(entries, [earlier.core.treeSize])], [
      included('entries', entries),
      included('checkpoints', [earlier]),
    ], coveragePolicy);

    expect((await verifyBundle(bundle, coveragePolicy)).checkpointIntegrity).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.CHECKPOINT_MISSING],
    });
    const transparent = { ...coveragePolicy, requiredAuditProfile: 'AAP-3' as const };
    expect((await verifyBundle(bundle, transparent)).checkpointIntegrity).toEqual({
      verdict: 'invalid',
      reasonCodes: [AUDIT_REASON_CODES.CHECKPOINT_MISSING, AUDIT_REASON_CODES.REQUIRED_PROFILE_UNMET],
    });
  });

  it('is valid once a checkpoint of the selected epoch holds every entry selected', async () => {
    const { entries, earlier, later } = await grownHistory();
    const sizes = [earlier.core.treeSize, later.core.treeSize];
    const whole = await exportBundle([selectionOf(entries, sizes)], [
      included('entries', entries),
      included('checkpoints', [earlier, later]),
    ], coveragePolicy);
    const prefix = await exportBundle([selectionOf(entries.slice(0, 4), [earlier.core.treeSize])], [
      included('entries', entries.slice(0, 4)),
      included('checkpoints', [earlier]),
    ], coveragePolicy);

    expect((await verifyBundle(whole, coveragePolicy)).checkpointIntegrity)
      .toEqual({ verdict: 'valid', reasonCodes: [] });
    expect((await verifyBundle(prefix, coveragePolicy)).checkpointIntegrity)
      .toEqual({ verdict: 'valid', reasonCodes: [] });
  });
});

describe('observation integrity of a bundle', () => {
  const observedBundle = async (observation: 'earlier' | 'later', anchor?: 'earlier' | 'later') => {
    const history = await grownHistory();
    const { entries, earlier, later } = history;
    const observations = { earlier: history.observedEarlier, later: history.observedLater };
    const anchors = { earlier: history.anchoredEarlier, later: history.anchoredLater };
    const bundle = await exportBundle(
      [selectionOf(entries, [earlier.core.treeSize, later.core.treeSize])],
      [
        included('entries', entries),
        included('checkpoints', [earlier, later]),
        included('observations', [observations[observation]]),
        ...(anchor === undefined ? [] : [included('anchors', [anchors[anchor]])]),
      ],
      coveragePolicy,
    );
    return { bundle, verifySupportingAnchor: history.anchors.verify.bind(history.anchors) };
  };

  it('stays indeterminate when the observer saw only an earlier tree than the selection', async () => {
    const { bundle } = await observedBundle('earlier');

    expect((await verifyBundle(bundle, coveragePolicy)).anchorIntegrity).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.OBSERVER_EVIDENCE_MISSING],
    });
  });

  it('is valid when the observer saw a checkpoint that holds every entry selected', async () => {
    const { bundle } = await observedBundle('later');

    expect((await verifyBundle(bundle, coveragePolicy)).anchorIntegrity)
      .toEqual({ verdict: 'valid', reasonCodes: [] });
  });

  it('meets AAP-4 only with a supporting anchor for a checkpoint that holds the selection', async () => {
    const observed = { ...coveragePolicy, requiredAuditProfile: 'AAP-4' as const };
    const earlierAnchor = await observedBundle('later', 'earlier');
    const laterAnchor = await observedBundle('later', 'later');

    expect((await verifyBundle(earlierAnchor.bundle, observed, earlierAnchor)).anchorIntegrity).toEqual({
      verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.REQUIRED_PROFILE_UNMET],
    });
    expect((await verifyBundle(laterAnchor.bundle, observed, laterAnchor)).anchorIntegrity)
      .toEqual({ verdict: 'valid', reasonCodes: [] });
  });
});

describe('a bundle that selects a ledger epoch with no checkpoint of its own', () => {
  it('takes no checkpoint or observation of the epoch before it for evidence', async () => {
    const { journal, ledger } = await recordedHistory();
    const sealed = await new AuditCheckpointBuilder({
      journal, store: new MemoryAuditCheckpointStore(), signer, hasher, clock: { now: () => 1_750_000_002_000 },
    }).createCheckpoint(ledger);
    const observation = await new MemoryAuditCheckpointObserver({
      observerId: 'observer-1', signer, hasher, clock: { now: () => 1_750_000_003_000 },
      verifyCheckpoint: async () => true, verifyConsistency: async () => true,
    }).publish(sealed);
    const successor: AuditLedgerRef = { ledgerId: ledger.ledgerId, ledgerEpochId: 'epoch_2' };
    await new AuditRecorderService({
      ...successor, tenantRef, binding: BINDING, sourceId: 'recorder-2', journal, signer, hasher,
      clock: { now: () => 1_750_000_004_000 },
      previousEpochId: ledger.ledgerEpochId,
      previousTerminalCheckpointDigest: sealed.checkpointDigest,
      epochTransitionGuard: { verifyAndSeal: async () => true },
    }).submitAuthenticated({
      ledgerId: successor.ledgerId, producerEvent: producerEvent('evt_10', 10), encryptedEvidence: [],
    }, SUBMITTER);
    const entries = await journal.snapshot(successor);
    const twoEpochs: AuditVerificationPolicyV1 = {
      ...coveragePolicy,
      trustedLedgerEpochs: [
        ...coveragePolicy.trustedLedgerEpochs,
        { ...successor, recorderKeys: [{ signer: signer.ref }] },
      ],
    };

    const report = await verifyBundle(await exportBundle([selectionOf(entries)], [
      included('entries', entries),
      included('checkpoints', [sealed]),
      included('observations', [observation]),
    ], twoEpochs), twoEpochs);

    expect(report.checkpointIntegrity).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.CHECKPOINT_MISSING],
    });
    expect(report.anchorIntegrity).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.OBSERVER_EVIDENCE_MISSING],
    });
  });
});
