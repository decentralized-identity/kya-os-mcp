import { canonicalizeJsonBytes } from '../utils/canonical-json.js';
import { AUDIT_ERROR_CODES, AuditProtocolError } from './errors.js';
import { hashAuditValue } from './crypto.js';
import {
  AUDIT_DIGEST_DOMAINS,
  buildAuditRecorderReceiptCore,
  digestAuditEntry,
  digestAuditEvidenceManifest,
  digestAuditEvent,
} from './integrity.js';
import type { AuditRecorderSubmission } from './providers/recorder-client.js';
import {
  sameSigner,
  validateEventAuthority,
  validateSubmissionEnvelope,
} from './recorder-authority.js';
import type {
  AuditRecorderServiceConfig,
  AuthenticatedAuditSubmissionContext,
} from './recorder-config.js';
import { RecorderWriteAheadEvidence } from './recorder-evidence.js';
import { genesisEvent, validateExistingGenesis } from './recorder-genesis.js';
import {
  AUDIT_ENTRY_SCHEMA_ID,
  AUDIT_INTEGRITY_SUITE,
  parseAuditEntryCore,
  parseAuditProducerEvent,
} from './schemas.js';
import {
  requireStoredAuditEntry,
  StoredAuditEntryVerifier,
  verifyStoredAuditEntry,
} from './stored-entry.js';
import type {
  AuditHead,
  AuditLedgerRef,
  AuditProducerEventCoreV1,
  Digest,
  SignedAuditEntryV1,
} from './types.js';

export type {
  AuditClock,
  AuditEpochTransitionGuard,
  AuditRecorderServiceConfig,
  AuditSubmissionAuthorizer,
  AuthenticatedAuditSubmissionContext,
} from './recorder-config.js';

function deepFreeze<T>(value: T): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function sameHead(left: AuditHead | null, right: AuditHead | null): boolean {
  if (left === null || right === null) return left === right;
  return left.entryDigest === right.entryDigest && left.sequence === right.sequence;
}

/** The later of two heads; at an equal sequence the first one is kept. */
function higherHead(current: AuditHead | null, candidate: AuditHead | null): AuditHead | null {
  if (candidate === null) return current;
  if (current === null) return candidate;
  return BigInt(candidate.sequence) > BigInt(current.sequence) ? candidate : current;
}

export class AuditRecorderService {
  private readonly maxAppendConflicts: number;
  private initialization?: Promise<SignedAuditEntryV1>;
  /** Highest head this recorder has itself appended in its epoch. */
  private committedHead: AuditHead | null = null;
  /** Highest head the journal has reported in a compare-and-append result. */
  private reportedHead: AuditHead | null = null;
  /** The last journal head whose stored entry verified as one its recorder signed. */
  private receiptedHead: AuditHead | null = null;
  /** Write-ahead evidence held, persisted and disposed for submissions in flight. */
  private readonly writeAhead: RecorderWriteAheadEvidence;
  /** How a head this recorder did not append is checked before it chains to it. */
  private readonly storedEntries: StoredAuditEntryVerifier;

  constructor(private readonly config: AuditRecorderServiceConfig) {
    if ((config.previousEpochId === undefined) !==
      (config.previousTerminalCheckpointDigest === undefined)) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.INVALID_CONFIGURATION,
        'Previous epoch ID and terminal checkpoint digest must be supplied together',
      );
    }
    if (config.previousEpochId !== undefined && config.epochTransitionGuard === undefined) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.INVALID_CONFIGURATION,
        'Epoch transitions require an authoritative verify-and-seal guard',
      );
    }
    this.maxAppendConflicts = config.maxAppendConflicts ?? 256;
    this.writeAhead = new RecorderWriteAheadEvidence(config);
    this.storedEntries = new StoredAuditEntryVerifier(config);
  }

  async submitAuthenticated(
    submission: AuditRecorderSubmission,
    context: AuthenticatedAuditSubmissionContext,
  ): Promise<SignedAuditEntryV1> {
    validateSubmissionEnvelope(this.config.ledgerId, submission, context);
    const producerEvent = parseAuditProducerEvent(submission.producerEvent);
    validateEventAuthority(this.config.tenantRef, producerEvent, context);
    if (this.config.authorizer !== undefined &&
      (await this.config.authorizer.authorize({ submission, context })) !== true) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.UNAUTHORIZED_SUBMISSION,
        'Audit producer is not authorized for this ledger',
      );
    }

    const identity = await this.identifyEvent(producerEvent, context);
    const duplicate = await this.config.journal.getByIdempotencyKey(
      this.config.ledgerId,
      identity.idempotencyKey,
    );
    if (duplicate !== null) return this.resolveDuplicate(duplicate, identity.eventDigest);

    // Only a new append must target the active epoch. Logical-ledger idempotency
    // is resolved first so a redelivered submission pinned to a retained earlier
    // epoch returns its original entry instead of wedging on EPOCH_MISMATCH.
    if (submission.expectedLedgerEpochId !== undefined &&
      submission.expectedLedgerEpochId !== this.config.ledgerEpochId) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.EPOCH_MISMATCH, 'Wrong audit ledger epoch');
    }

    await this.ensureInitialized();
    const held = this.writeAhead.hold(submission.encryptedEvidence);
    try {
      const stored = await this.writeAhead.persist(
        submission.encryptedEvidence,
        producerEvent,
      );
      try {
        return await this.appendEvent(producerEvent, context, false, identity);
      } catch (error) {
        await this.writeAhead.disposeUncommitted(stored, identity);
        throw error;
      }
    } finally {
      this.writeAhead.release(held);
    }
  }

  private async ensureInitialized(): Promise<SignedAuditEntryV1> {
    const ledger = this.ledgerRef();
    const existingHead = await this.config.journal.getHead(ledger);
    if (existingHead !== null) {
      const first = this.config.journal.readRange({ ...ledger, limit: 1 });
      for await (const entry of first) return validateExistingGenesis(entry, this.config);
      throw new AuditProtocolError(AUDIT_ERROR_CODES.JOURNAL_FAILURE, 'Ledger head exists without genesis');
    }

    if (this.config.previousEpochId !== undefined) {
      const verifiedAndSealed = await this.config.epochTransitionGuard!.verifyAndSeal({
        ledgerId: this.config.ledgerId,
        previousEpochId: this.config.previousEpochId,
        nextEpochId: this.config.ledgerEpochId,
        previousTerminalCheckpointDigest: this.config.previousTerminalCheckpointDigest!,
      });
      if (verifiedAndSealed !== true) {
        throw new AuditProtocolError(
          AUDIT_ERROR_CODES.INVALID_CONFIGURATION,
          'Predecessor checkpoint could not be verified and sealed',
        );
      }
    }

    this.initialization ??= this.appendEvent(
      genesisEvent(this.config),
      {
        producerAuthority: this.config.signer.ref.did,
        tenantAuthority: 'audit-recorder',
        producerRef: { kind: 'public_did', did: this.config.signer.ref.did },
        tenantRef: this.config.tenantRef,
      },
      true,
    ).finally(() => {
      this.initialization = undefined;
    });
    return this.initialization;
  }

  private async appendEvent(
    event: AuditProducerEventCoreV1,
    context: AuthenticatedAuditSubmissionContext,
    genesis = false,
    knownIdentity?: { eventDigest: Digest; idempotencyKey: Digest },
  ): Promise<SignedAuditEntryV1> {
    const { eventDigest, idempotencyKey } = knownIdentity ??
      await this.identifyEvent(event, context);

    const duplicate = await this.config.journal.getByIdempotencyKey(
      this.config.ledgerId,
      idempotencyKey,
    );
    if (duplicate !== null) {
      // A raced replica genesis differs only in recorder-authored timing, so it
      // resolves through epoch-configuration validation, not content identity.
      return genesis
        ? validateExistingGenesis(duplicate, this.config)
        : this.resolveDuplicate(duplicate, eventDigest);
    }

    const ledger = this.ledgerRef();
    for (let attempt = 0; attempt <= this.maxAppendConflicts; attempt += 1) {
      // A read behind this recorder's own commits (a lagging replica) is not
      // an append position: compare-and-append against the committed head, so
      // a stale read costs one retry and a journal that really moved backwards
      // answers with a conflict that proves it instead of accepting a second
      // entry at a receipted sequence.
      const committed = this.committedHead;
      const reported = this.reportedHead;
      const head = higherHead(committed, await this.config.journal.getHead(ledger));
      if (genesis && head !== null) {
        const raced = await this.config.journal.getByIdempotencyKey(
          this.config.ledgerId,
          idempotencyKey,
        );
        if (raced !== null) return validateExistingGenesis(raced, this.config);
      }

      await this.assertHeadReceipted(head);
      const candidate = await this.buildCandidate(event, eventDigest, head, genesis);
      let result;
      try {
        result = await this.config.journal.compareAndAppend({
          ledger,
          expectedHead: head,
          entry: candidate,
          idempotencyKey,
        });
      } catch (error) {
        throw new AuditProtocolError(
          AUDIT_ERROR_CODES.JOURNAL_FAILURE,
          'Audit journal append failed',
          undefined,
          { cause: error },
        );
      }

      if (result.kind === 'appended') {
        const appended = {
          ...ledger,
          sequence: result.entry.core.sequence,
          entryDigest: result.entry.entryDigest,
        };
        this.committedHead = higherHead(this.committedHead, appended);
        this.reportedHead = higherHead(this.reportedHead, appended);
        return result.entry;
      }
      if (result.kind === 'duplicate' || result.kind === 'idempotency_conflict') {
        const existing = result.kind === 'duplicate' ? result.entry : result.existing;
        // A replica that lost the cold-start genesis race finds a genesis that
        // differs only in recorder-authored timing; it is accepted on epoch
        // configuration, never as an event-identity conflict.
        return genesis
          ? validateExistingGenesis(existing, this.config)
          : this.resolveDuplicate(existing, eventDigest);
      }
      this.assertNoRegression(result.actualHead, committed, reported);
      this.reportedHead = higherHead(this.reportedHead, result.actualHead);
      if (sameHead(head, result.actualHead)) {
        throw new AuditProtocolError(
          AUDIT_ERROR_CODES.JOURNAL_FAILURE,
          'Audit journal reported a head conflict without advancing its head',
        );
      }
    }

    throw new AuditProtocolError(
      AUDIT_ERROR_CODES.APPEND_CONFLICT_EXHAUSTED,
      'Audit append conflict retry budget exhausted',
    );
  }

  /**
   * The compare-and-append result is the journal's authoritative head. One
   * below a head this recorder had committed before issuing the append, or a
   * different digest at a sequence the journal already reported, means a
   * failover to a lagging primary or a restore. Retrying there would sign a
   * second entry at a receipted sequence, so the recorder fails closed. The
   * heads compared are the ones known when the append was issued, so a
   * concurrent submission's later commit never makes a correct answer look
   * stale.
   */
  private assertNoRegression(
    actual: AuditHead | null,
    committed: AuditHead | null,
    reported: AuditHead | null,
  ): void {
    const forks = (known: AuditHead | null): boolean => known !== null && actual !== null &&
      known.sequence === actual.sequence && known.entryDigest !== actual.entryDigest;
    if ((committed !== null &&
      (actual === null || BigInt(actual.sequence) < BigInt(committed.sequence))) ||
      forks(committed) || forks(reported)) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.JOURNAL_FAILURE,
        'Audit journal head moved behind a head this recorder already committed or saw',
        { committedSequence: committed?.sequence, reportedSequence: actual?.sequence },
      );
    }
  }

  /**
   * With `signatures`, the recorder chains only to a head it appended in this
   * process or one whose stored entry verifies as one it signed for this
   * ledger epoch. A head read from the journal is otherwise whatever a writer
   * of the journal store put there, and the next receipt would commit to it.
   */
  private async assertHeadReceipted(head: AuditHead | null): Promise<void> {
    if (head === null || sameHead(head, this.committedHead) || sameHead(head, this.receiptedHead)) return;
    const verification = await this.storedEntries.verification();
    if (verification === undefined) return;
    const ledger = this.ledgerRef();
    // The recorder of an epoch signs every entry in it, its genesis included,
    // so an entry under another key is not one it can chain to.
    await requireStoredAuditEntry(head.sequence, async () => {
      const entry = await this.entryAt(ledger, head.sequence);
      return entry !== undefined &&
        entry.entryDigest === head.entryDigest &&
        sameSigner(entry.core.recorder, this.config.signer.ref) &&
        verifyStoredAuditEntry(entry, ledger, verification);
    });
    this.receiptedHead = head;
  }

  /** The stored entry at `sequence`, if the journal returns that one first from just below it. */
  private async entryAt(
    ledger: AuditLedgerRef,
    sequence: string,
  ): Promise<SignedAuditEntryV1 | undefined> {
    const position = BigInt(sequence);
    const range = this.config.journal.readRange({
      ...ledger,
      ...(position === 0n ? {} : { afterSequence: String(position - 1n) }),
      limit: 1,
    });
    for await (const entry of range) return entry.core.sequence === sequence ? entry : undefined;
    return undefined;
  }

  private async identifyEvent(
    event: AuditProducerEventCoreV1,
    context: AuthenticatedAuditSubmissionContext,
  ): Promise<{ eventDigest: Digest; idempotencyKey: Digest }> {
    const eventDigest = await digestAuditEvent(this.config.hasher, event);
    const idempotencyKey = await hashAuditValue(
      this.config.hasher,
      AUDIT_DIGEST_DOMAINS.idempotency,
      {
        ledgerId: this.config.ledgerId,
        producerAuthority: context.producerAuthority,
        sourceId: event.source.sourceId,
        eventId: event.eventId,
      },
    );
    return { eventDigest, idempotencyKey };
  }

  private resolveDuplicate(existing: SignedAuditEntryV1, digest: Digest): SignedAuditEntryV1 {
    if (existing.eventDigest !== digest) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.EVENT_ID_CONFLICT,
        'Authenticated producer event identity was reused with different content',
        { eventId: existing.core.event.eventId },
      );
    }
    return existing;
  }

  private async buildCandidate(
    event: AuditProducerEventCoreV1,
    eventDigest: Digest,
    head: AuditHead | null,
    genesis: boolean,
  ): Promise<SignedAuditEntryV1> {
    const sequence = head === null ? '0' : (BigInt(head.sequence) + 1n).toString();
    if (genesis !== (sequence === '0')) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.JOURNAL_FAILURE,
        genesis ? 'Genesis must be the first epoch entry' : 'Producer event cannot replace genesis',
      );
    }
    const recordedAt = this.config.clock.now();
    const evidenceManifestDigest = await digestAuditEvidenceManifest(this.config.hasher, event);
    const core = parseAuditEntryCore({
      schema: AUDIT_ENTRY_SCHEMA_ID,
      ledgerId: this.config.ledgerId,
      ledgerEpochId: this.config.ledgerEpochId,
      sequence,
      previousEntryDigest: head?.entryDigest ?? null,
      recordedAt,
      recorder: this.config.signer.ref,
      eventDigest,
      event,
      evidenceManifestDigest,
      integritySuite: AUDIT_INTEGRITY_SUITE,
    });
    const entryDigest = await digestAuditEntry(this.config.hasher, core);
    const receiptCore = buildAuditRecorderReceiptCore(core, entryDigest);
    const jws = await this.config.signer.sign(canonicalizeJsonBytes(receiptCore));
    return deepFreeze({
      core,
      eventDigest,
      entryDigest,
      recorderReceipt: { core: receiptCore, jws },
    } satisfies SignedAuditEntryV1);
  }

  private ledgerRef(): AuditLedgerRef {
    return {
      ledgerId: this.config.ledgerId,
      ledgerEpochId: this.config.ledgerEpochId,
    } as const;
  }
}
