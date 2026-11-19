import { describe, expect, it } from 'vitest';
import { canonicalizeJsonBytes } from '../../utils/canonical-json.js';
import { buildAuditRecorderReceiptCore, digestAuditEntry } from '../integrity.js';
import type { SignedAuditEntryV1 } from '../types.js';
import { AUDIT_REASON_CODES } from '../verifier.js';
import {
  A_YEAR_LATER,
  CHECKPOINTED_AT,
  NamedKey,
  ROTATED_AT,
  epoch,
  resigned,
  rotatedLedger,
  rotationPolicy,
  verifierAt,
} from './key-dating-fixtures.js';
import { hasher } from './observer-fixtures.js';
import { unsignedEntryAfter } from './stored-entry-fixtures.js';

const valid = { verdict: 'valid', reasonCodes: [] };
const undated = { verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.KEY_ENDED_UNDATED] };
const mismatched = {
  verdict: 'indeterminate',
  reasonCodes: [AUDIT_REASON_CODES.KEY_ENDED_UNDATED, AUDIT_REASON_CODES.SUCCESSOR_GENESIS_MISMATCH],
};

describe('AuditArtifactVerifier: a record whose key has since ended', () => {
  it('reads an honest record undecided once its key has ended, until the successor genesis dates it', async () => {
    const { oldEntries, terminal, genesis, policy } = await rotatedLedger();
    const later = verifierAt(A_YEAR_LATER);

    // Before the rotation the key is live, and its word on time is the key's own.
    expect((await verifierAt(ROTATED_AT).verifyEntries(oldEntries, policy)).cryptographicIntegrity)
      .toEqual(valid);
    // After it, whoever still holds the old key could have written any of these.
    expect((await later.verifyEntries(oldEntries, policy, { checkpoints: [terminal] }))
      .cryptographicIntegrity).toEqual(undated);
    // The new key's genesis commits to the terminal checkpoint, which holds every one of them.
    expect((await later.verifyEntries(oldEntries, policy, {
      checkpoints: [terminal], successorGeneses: [genesis],
    })).cryptographicIntegrity).toEqual(valid);
  });

  it('never dates a record written after the rotation, or outside the terminal checkpoint', async () => {
    const { oldKey, oldEntries, terminal, genesis, policy } = await rotatedLedger();
    const evidence = { checkpoints: [terminal], successorGeneses: [genesis] };
    const later = verifierAt(A_YEAR_LATER);
    const head = oldEntries.at(-1)!;
    // Stated as recorded before the rotation, appended after the terminal checkpoint.
    const appended = await unsignedEntryAfter(
      { sequence: head.core.sequence, entryDigest: head.entryDigest },
      { recorder: oldKey.ref, ledgerRef: epoch(1), signWith: oldKey },
    );
    expect(appended.core.recordedAt).toBeLessThan(ROTATED_AT);
    const afterward = await later.verifyEntries([...oldEntries, appended], policy, evidence);
    expect(afterward.cryptographicIntegrity).toEqual(undated);
    expect(afterward.chainIntegrity).toEqual(valid);

    // A fork of the epoch in place of a record its terminal checkpoint holds.
    const forked = await unsignedEntryAfter(
      { sequence: oldEntries[0]!.core.sequence, entryDigest: oldEntries[0]!.entryDigest },
      { recorder: oldKey.ref, ledgerRef: epoch(1), signWith: oldKey },
    );
    expect((await later.verifyEntries([oldEntries[0]!, forked], policy, evidence))
      .cryptographicIntegrity).toEqual(undated);
  });

  it('reports a successor genesis whose terminal checkpoint is not the one carried, and dates nothing with it', async () => {
    const elsewhere = `sha256:${'e'.repeat(64)}` as const;
    const { oldEntries, terminal, genesis, policy } = await rotatedLedger({ terminal: elsewhere });
    const later = verifierAt(A_YEAR_LATER);
    expect((await later.verifyEntries(oldEntries, policy, {
      checkpoints: [terminal], successorGeneses: [genesis],
    })).cryptographicIntegrity).toEqual(mismatched);
    // It is reported while the old key is live too, when nothing needs dating.
    expect((await verifierAt(ROTATED_AT).verifyEntries(oldEntries, policy, {
      checkpoints: [terminal], successorGeneses: [genesis],
    })).cryptographicIntegrity).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.SUCCESSOR_GENESIS_MISMATCH],
    });

    // Without the terminal checkpoint, an honest genesis has nothing to date either.
    const honest = await rotatedLedger();
    expect((await later.verifyEntries(honest.oldEntries, honest.policy, {
      successorGeneses: [honest.genesis],
    })).cryptographicIntegrity).toEqual(mismatched);
    // Nor does a record offered as one that is not a successor genesis.
    expect((await later.verifyEntries(honest.oldEntries, honest.policy, {
      checkpoints: [honest.terminal], successorGeneses: [honest.oldEntries[1]!, { not: 'an entry' }] as never,
    })).cryptographicIntegrity).toEqual(mismatched);
  });

  it('takes only the first entry of an epoch as its genesis', async () => {
    const { newKey, oldEntries, terminal, genesis, policy } = await rotatedLedger();
    // The genesis's own event, signed by the new key one entry later in its epoch.
    const core = {
      ...genesis.core, sequence: '1', previousEntryDigest: genesis.entryDigest,
    };
    const entryDigest = await digestAuditEntry(hasher, core);
    const receipt = buildAuditRecorderReceiptCore(core, entryDigest);
    const second: SignedAuditEntryV1 = {
      core, eventDigest: genesis.eventDigest, entryDigest,
      recorderReceipt: { core: receipt, jws: await newKey.sign(canonicalizeJsonBytes(receipt)) },
    };
    expect((await verifierAt(A_YEAR_LATER).verifyEntries(oldEntries, policy, {
      checkpoints: [terminal], successorGeneses: [second],
    })).cryptographicIntegrity).toEqual(mismatched);
  });

  it('checks the new key at the genesis, and dates nothing by a genesis whose own key has ended undated', async () => {
    const later = verifierAt(A_YEAR_LATER);
    // The new key was not yet valid when the genesis says it signed.
    const early = await rotatedLedger({ newKey: { validFrom: ROTATED_AT + 1 } });
    expect((await later.verifyEntries(early.oldEntries, early.policy, {
      checkpoints: [early.terminal], successorGeneses: [early.genesis],
    })).cryptographicIntegrity).toEqual(mismatched);

    // The new key has ended too, and nothing dates its genesis before then.
    const ended = await rotatedLedger({ newKey: { validUntil: ROTATED_AT + 1_000 } });
    expect((await later.verifyEntries(ended.oldEntries, ended.policy, {
      checkpoints: [ended.terminal], successorGeneses: [ended.genesis],
    })).cryptographicIntegrity).toEqual(undated);
  });

  it('dates a record through an earlier checkpoint that the dated one holds', async () => {
    const { oldEntries, first, middle, terminal, genesis, policy } = await rotatedLedger();
    const later = verifierAt(A_YEAR_LATER);
    // The middle checkpoint's leaves only: the terminal checkpoint holds it by its chain link.
    expect(terminal.core.previousCheckpointDigest).toBe(middle.checkpointDigest);
    expect((await later.verifyEntries(oldEntries.slice(0, Number(middle.core.treeSize)), policy, {
      checkpoints: [middle, terminal], successorGeneses: [genesis],
    })).cryptographicIntegrity).toEqual(valid);
    // Every leaf, and a checkpoint the terminal one does not link to: the leaves hold one in the other.
    expect((await later.verifyEntries(oldEntries, policy, {
      checkpoints: [first, terminal], successorGeneses: [genesis],
    })).cryptographicIntegrity).toEqual(valid);
  });

  it('takes a checkpoint the policy retires the key at, or one a live key signs, as dating', async () => {
    const { oldKey, newKey, oldEntries, terminal } = await rotatedLedger();
    const later = verifierAt(A_YEAR_LATER);
    const retiredAtTerminal = rotationPolicy(
      { signer: oldKey.ref, validUntilCheckpoint: terminal.checkpointDigest },
      { signer: newKey.ref },
    );
    expect((await later.verifyEntries(oldEntries, retiredAtTerminal, { checkpoints: [terminal] }))
      .cryptographicIntegrity).toEqual(valid);
    // A record at a position the checkpoint covers, but not in its tree, is not dated by it.
    const forked = await unsignedEntryAfter(
      { sequence: oldEntries[0]!.core.sequence, entryDigest: oldEntries[0]!.entryDigest },
      { recorder: oldKey.ref, ledgerRef: epoch(1), signWith: oldKey },
    );
    expect((await later.verifyEntries([oldEntries[0]!, forked], retiredAtTerminal, {
      checkpoints: [terminal],
    })).cryptographicIntegrity).toEqual(undated);

    // A checkpoint over the same leaves by a builder key that is still live.
    const builder = new NamedKey('Builder');
    const byBuilder = await resigned(terminal, builder);
    const twoKeys = rotationPolicy({ signer: oldKey.ref, validUntil: ROTATED_AT }, { signer: newKey.ref });
    twoKeys.trustedLedgerEpochs[0]!.recorderKeys.push({ signer: builder.ref });
    expect((await later.verifyEntries(oldEntries, twoKeys, { checkpoints: [byBuilder] }))
      .cryptographicIntegrity).toEqual(valid);
    // Not when the policy does not trust that key.
    const oneKey = rotationPolicy({ signer: oldKey.ref, validUntil: ROTATED_AT }, { signer: newKey.ref });
    expect((await later.verifyEntries(oldEntries, oneKey, { checkpoints: [byBuilder] }))
      .cryptographicIntegrity).toEqual(undated);
    // One it signed at the moment the old key ended still dates the records, as the end is inclusive.
    const atTheEnd = await resigned({ ...terminal, core: { ...terminal.core, createdAt: ROTATED_AT } }, builder);
    expect((await later.verifyEntries(oldEntries, twoKeys, { checkpoints: [atTheEnd] }))
      .cryptographicIntegrity).toEqual(valid);
    // One it signed after the old key ended dates nothing before that end.
    const lateBuilder = await resigned({ ...terminal, core: { ...terminal.core, createdAt: ROTATED_AT + 1 } }, builder);
    expect((await later.verifyEntries(oldEntries, twoKeys, { checkpoints: [lateBuilder] }))
      .cryptographicIntegrity).toEqual(undated);
  });

  it('dates a checkpoint signed by a key that has ended the same way', async () => {
    const { terminal, genesis, policy } = await rotatedLedger();
    const later = verifierAt(A_YEAR_LATER);
    expect(terminal.core.createdAt).toBe(CHECKPOINTED_AT);
    expect(await later.verifySignedCheckpoint(terminal, policy)).toEqual(undated);
    expect(await later.verifySignedCheckpoint(terminal, policy, { successorGeneses: [genesis] }))
      .toEqual(valid);
  });

  it('takes a key with an end as ended when the verifier has no clock', async () => {
    const { oldEntries, terminal, genesis, policy } = await rotatedLedger();
    const unclocked = verifierAt(undefined);
    expect((await unclocked.verifyEntries(oldEntries, policy, { checkpoints: [terminal] }))
      .cryptographicIntegrity).toEqual(undated);
    // The new key has no end, so its genesis is its word whatever the time.
    expect((await unclocked.verifyEntries(oldEntries, policy, {
      checkpoints: [terminal], successorGeneses: [genesis],
    })).cryptographicIntegrity).toEqual(valid);
  });
});
