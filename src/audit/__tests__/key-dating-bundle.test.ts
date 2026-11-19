import { describe, expect, it } from 'vitest';
import { hashAuditValue } from '../crypto.js';
import { Rfc9162MerkleTree } from '../merkle.js';
import { MemoryAuditCheckpointObserver } from '../providers/observer.js';
import {
  AUDIT_BUNDLE_MEDIA_TYPES,
  AuditReplayBundleExporter,
  type AuditBundleComponentInput,
  verifyAuditBundle,
} from '../replay-bundle.js';
import type {
  AuditAnchorReceipt,
  AuditBundleSelectionV1,
  AuditVerificationPolicyV1,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
} from '../types.js';
import { AUDIT_REASON_CODES } from '../verifier.js';
import {
  A_YEAR_LATER,
  NamedKey,
  NamedKeyVerifier,
  ROTATED_AT,
  epoch,
  recordEpoch,
  rotatedLedger,
  terminalCheckpoint,
} from './key-dating-fixtures.js';
import { hasher } from './observer-fixtures.js';

const undated = { verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.KEY_ENDED_UNDATED] };

function selectionOf(
  entries: readonly SignedAuditEntryV1[],
  checkpoints: readonly SignedAuditCheckpointV1[],
): AuditBundleSelectionV1 {
  return {
    ledgerId: entries[0]!.core.ledgerId,
    ledgerEpochId: entries[0]!.core.ledgerEpochId,
    firstSequence: '0',
    lastSequence: String(entries.length - 1),
    expectedHeadDigest: entries.at(-1)!.entryDigest,
    checkpointTreeSizes: checkpoints.map((checkpoint) => checkpoint.core.treeSize),
  };
}

const included = (path: string, mediaType: string, content: unknown): AuditBundleComponentInput =>
  ({ path, mediaType, disposition: 'included', content });

async function exportBundle(
  policy: AuditVerificationPolicyV1,
  exporter: NamedKey,
  selections: readonly AuditBundleSelectionV1[],
  components: readonly AuditBundleComponentInput[],
) {
  return new AuditReplayBundleExporter({
    hasher, signer: exporter, clock: { now: () => ROTATED_AT + 10_000 },
  }).export({
    bundleId: 'bundle_rotated',
    purpose: 'regulatory-review',
    verificationPolicyDigest: await hashAuditValue(
      hasher, 'org.kya-os.audit.verification-policy.v1', policy,
    ),
    selections,
    components,
  });
}

async function exported(
  policy: AuditVerificationPolicyV1,
  exporter: NamedKey,
  epochs: readonly { entries: readonly SignedAuditEntryV1[]; checkpoints: readonly SignedAuditCheckpointV1[] }[],
  more: readonly AuditBundleComponentInput[] = [],
) {
  return exportBundle(
    policy,
    exporter,
    epochs.map(({ entries, checkpoints }) => selectionOf(entries, checkpoints)),
    [
      included('entries.json', AUDIT_BUNDLE_MEDIA_TYPES.entries, epochs.flatMap(({ entries }) => entries)),
      included('checkpoints.json', AUDIT_BUNDLE_MEDIA_TYPES.checkpoints,
        epochs.flatMap(({ checkpoints }) => checkpoints)),
      ...more,
    ],
  );
}

const verifiedAt = (
  bundle: unknown,
  policy: AuditVerificationPolicyV1,
  now: number | undefined,
  verifySupportingAnchor?: (checkpoint: SignedAuditCheckpointV1, receipt: AuditAnchorReceipt) => Promise<boolean>,
) => verifyAuditBundle(bundle, policy, {
  hasher,
  signatures: new NamedKeyVerifier(),
  ...(now === undefined ? {} : { verifiedAt: () => now }),
  ...(verifySupportingAnchor === undefined ? {} : { verifySupportingAnchor }),
});

const successors = (geneses: readonly SignedAuditEntryV1[]) =>
  included('successor-geneses.json', AUDIT_BUNDLE_MEDIA_TYPES.successorGeneses, geneses);

describe('verifyAuditBundle: records whose key has since ended', () => {
  it('keeps an honest rotated epoch valid when the bundle carries the successor genesis', async () => {
    const { newKey, oldEntries, terminal, genesis, policy } = await rotatedLedger();
    const epochs = [{ entries: oldEntries, checkpoints: [terminal] }];
    const dated = await verifiedAt(await exported(policy, newKey, epochs, [successors([genesis])]), policy, A_YEAR_LATER);
    expect(dated.cryptographicIntegrity.verdict).toBe('valid');
    expect(dated.checkpointIntegrity.verdict).toBe('valid');

    // A bundle exported before successor geneses existed reads as before while its keys are
    // live, and undecided, never invalid, once the old key has ended.
    const bare = await exported(policy, newKey, epochs);
    const before = await verifiedAt(bare, policy, ROTATED_AT);
    expect(before.cryptographicIntegrity.verdict).toBe('valid');
    expect(before.checkpointIntegrity.verdict).toBe('valid');
    const after = await verifiedAt(bare, policy, A_YEAR_LATER);
    expect(after.cryptographicIntegrity).toEqual(undated);
    expect(after.checkpointIntegrity).toEqual(undated);
    // With no clock, a key with an end may have ended.
    expect((await verifiedAt(bare, policy, undefined)).cryptographicIntegrity).toEqual(undated);
  });

  it('reports a successor genesis whose terminal checkpoint is not the one the bundle carries', async () => {
    const { newKey, oldEntries, terminal, genesis, policy } = await rotatedLedger({
      terminal: `sha256:${'e'.repeat(64)}`,
    });
    const report = await verifiedAt(
      await exported(policy, newKey, [{ entries: oldEntries, checkpoints: [terminal] }], [successors([genesis])]),
      policy,
      A_YEAR_LATER,
    );
    expect(report.cryptographicIntegrity).toEqual({
      verdict: 'indeterminate',
      reasonCodes: [AUDIT_REASON_CODES.KEY_ENDED_UNDATED, AUDIT_REASON_CODES.SUCCESSOR_GENESIS_MISMATCH],
    });
  });

  it('dates a subset export through its inclusion and consistency proofs', async () => {
    const { newKey, oldEntries, first, terminal, genesis, policy } = await rotatedLedger();
    const tree = new Rfc9162MerkleTree(hasher);
    const leaves = oldEntries.map((entry) => entry.entryDigest);
    const entry = oldEntries[1]!;
    const inclusion = async (checkpoint: SignedAuditCheckpointV1) => ({
      ...epoch(1),
      sequence: entry.core.sequence,
      entryDigest: entry.entryDigest,
      checkpointDigest: checkpoint.checkpointDigest,
      proof: {
        leafIndex: entry.core.sequence,
        treeSize: checkpoint.core.treeSize,
        auditPath: await tree.inclusionProof(leaves.slice(0, Number(checkpoint.core.treeSize)), 1),
      },
    });
    const bundle = await exportBundle(policy, newKey, [{
      ...epoch(1), firstSequence: '1', lastSequence: '1', expectedHeadDigest: entry.entryDigest,
      checkpointTreeSizes: [first.core.treeSize, terminal.core.treeSize],
    }], [
      included('entries.json', AUDIT_BUNDLE_MEDIA_TYPES.entries, [entry]),
      included('checkpoints.json', AUDIT_BUNDLE_MEDIA_TYPES.checkpoints, [first, terminal]),
      included('inclusion-proofs.json', AUDIT_BUNDLE_MEDIA_TYPES.inclusionProofs,
        [await inclusion(first), await inclusion(terminal)]),
      included('consistency-proofs.json', AUDIT_BUNDLE_MEDIA_TYPES.consistencyProofs, [{
        ...epoch(1),
        oldCheckpointDigest: first.checkpointDigest,
        newCheckpointDigest: terminal.checkpointDigest,
        proof: {
          oldTreeSize: first.core.treeSize,
          newTreeSize: terminal.core.treeSize,
          auditPath: await tree.consistencyProof(leaves, Number(first.core.treeSize)),
        },
      }]),
      successors([genesis]),
    ]);
    const report = await verifiedAt(bundle, policy, A_YEAR_LATER);
    expect(report.cryptographicIntegrity.verdict).toBe('valid');
    // The first checkpoint is dated by the terminal one its tree is consistent with.
    expect(report.checkpointIntegrity.verdict).toBe('valid');
  });

  it('dates through a successor whose own key has since ended, by the genesis after it', async () => {
    const { journal, oldKey, newKey, oldEntries, terminal } = await rotatedLedger();
    const newest = new NamedKey('Newest');
    const secondRotation = ROTATED_AT + 2_000;
    const middleTerminal = await terminalCheckpoint(journal, epoch(2), newKey, ROTATED_AT + 1_000);
    await recordEpoch(journal, epoch(3), newest, secondRotation, ['evt_newest'], {
      epochId: 'epoch_2', terminal: middleTerminal.checkpointDigest,
    });
    const middleEntries = await journal.snapshot(epoch(2));
    const [latest] = await journal.snapshot(epoch(3));
    const policy: AuditVerificationPolicyV1 = {
      ...(await rotatedLedger()).policy,
      trustedLedgerEpochs: [
        { ...epoch(1), recorderKeys: [{ signer: oldKey.ref, validUntil: ROTATED_AT }] },
        { ...epoch(2), recorderKeys: [{ signer: newKey.ref, validUntil: secondRotation }] },
        { ...epoch(3), recorderKeys: [{ signer: newest.ref }] },
      ],
    };
    policy.authorizedExporters[0]!.signerKeys[0] = { signer: newest.ref };
    const epochs = [
      { entries: oldEntries, checkpoints: [terminal] },
      { entries: middleEntries, checkpoints: [middleTerminal] },
    ];
    const chained = await verifiedAt(await exported(policy, newest, epochs, [successors([latest!])]), policy, A_YEAR_LATER);
    expect(chained.cryptographicIntegrity.verdict).toBe('valid');
    expect(chained.checkpointIntegrity.verdict).toBe('valid');
    // Without the newest genesis, the middle epoch's genesis is its own ended key's word.
    expect((await verifiedAt(await exported(policy, newest, epochs), policy, A_YEAR_LATER))
      .cryptographicIntegrity).toEqual(undated);
  });

  it('dates through an observation or a supporting anchor the old key does not control', async () => {
    const { newKey, oldEntries, terminal, policy } = await rotatedLedger();
    const observerKey = new NamedKey('Observer');
    const observed = (at: number) => new MemoryAuditCheckpointObserver({
      observerId: 'observer-1', signer: observerKey, hasher, clock: { now: () => at },
      verifyCheckpoint: async () => true, verifyConsistency: async () => true,
    }).publish(terminal);
    const observing = { ...policy, trustedObservers: [{ signer: observerKey.ref }] };
    const epochs = [{ entries: oldEntries, checkpoints: [terminal] }];
    const withObservation = async (at: number) => verifiedAt(await exported(observing, newKey, epochs, [
      included('observations.json', AUDIT_BUNDLE_MEDIA_TYPES.observations, [await observed(at)]),
    ]), observing, A_YEAR_LATER);
    expect((await withObservation(ROTATED_AT - 1)).cryptographicIntegrity.verdict).toBe('valid');
    expect((await withObservation(ROTATED_AT + 1)).cryptographicIntegrity).toEqual(undated);
    // An observer whose own key has ended is its word alone too, and dates nothing.
    const retiredObserver = {
      ...policy, trustedObservers: [{ signer: observerKey.ref, validUntil: ROTATED_AT + 1_000 }],
    };
    const retired = await verifiedAt(await exported(retiredObserver, newKey, epochs, [
      included('observations.json', AUDIT_BUNDLE_MEDIA_TYPES.observations, [await observed(ROTATED_AT - 1)]),
    ]), retiredObserver, A_YEAR_LATER);
    expect(retired.cryptographicIntegrity).toEqual(undated);
    expect(retired.anchorIntegrity.verdict).toBe('valid');

    const anchoring = {
      ...policy, trustedSupportingAnchors: [{ kind: 'worm' as const, providerId: 'archive-1' }],
    };
    const withAnchor = async (issuedAt: number) => verifiedAt(await exported(anchoring, newKey, epochs, [
      included('anchors.json', AUDIT_BUNDLE_MEDIA_TYPES.anchors, [{
        schema: 'https://schema.kya-os.org/v1/protocol/audit/anchor-receipt/v1.0.0',
        kind: 'worm', providerId: 'archive-1', checkpointDigest: terminal.checkpointDigest, issuedAt,
      }]),
    ]), anchoring, A_YEAR_LATER, async () => true);
    expect((await withAnchor(ROTATED_AT)).cryptographicIntegrity.verdict).toBe('valid');
    expect((await withAnchor(ROTATED_AT + 1)).cryptographicIntegrity).toEqual(undated);
    // Nor does an anchor from a provider the policy does not trust.
    const untrusted = { ...anchoring, trustedSupportingAnchors: [] };
    const unanchored = await verifiedAt(await exported(untrusted, newKey, epochs, [
      included('anchors.json', AUDIT_BUNDLE_MEDIA_TYPES.anchors, [{
        schema: 'https://schema.kya-os.org/v1/protocol/audit/anchor-receipt/v1.0.0',
        kind: 'worm', providerId: 'archive-1', checkpointDigest: terminal.checkpointDigest,
        issuedAt: ROTATED_AT,
      }]),
    ]), untrusted, A_YEAR_LATER, async () => true);
    expect(unanchored.cryptographicIntegrity).toEqual(undated);
  });

  it('leaves an export undecided once its exporter key has ended, as nothing dates an export', async () => {
    const { newKey, oldEntries, terminal, genesis, policy } = await rotatedLedger();
    const retired = {
      ...policy,
      authorizedExporters: [{
        ...policy.authorizedExporters[0]!, signerKeys: [{ signer: newKey.ref, validUntil: ROTATED_AT + 20_000 }],
      }],
    };
    const bundle = await exported(retired, newKey, [{ entries: oldEntries, checkpoints: [terminal] }], [successors([genesis])]);
    expect((await verifiedAt(bundle, retired, ROTATED_AT + 20_000)).cryptographicIntegrity.verdict).toBe('valid');
    expect((await verifiedAt(bundle, retired, A_YEAR_LATER)).cryptographicIntegrity).toEqual(undated);
  });
});
