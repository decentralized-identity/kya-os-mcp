import { canonicalizeJson, canonicalizeJsonBytes } from '../utils/canonical-json.js';
import { AUDIT_ERROR_CODES, AuditProtocolError } from './errors.js';
import { hashAuditValue, type AuditHasher, type AuditSigner } from './crypto.js';
import {
  AUDIT_DIGEST_DOMAINS,
  buildAuditRecorderReceiptCore,
  collectAuditEvidenceRefs,
  digestAuditEntry,
  digestAuditEvidenceManifest,
  digestAuditEvent,
} from './integrity.js';
import type { AuditEvidenceProvider, EncryptedEvidenceInput } from './providers/evidence.js';
import type { AuditJournalProvider } from './providers/journal.js';
import type { AuditRecorderSubmission } from './providers/recorder-client.js';
import {
  AUDIT_ENTRY_SCHEMA_ID,
  AUDIT_EVENT_SCHEMA_ID,
  AUDIT_INTEGRITY_SUITE,
  parseAuditEntryCore,
  parseAuditProducerEvent,
  parseSignedAuditEntry,
} from './schemas.js';
import type {
  AuditHead,
  AuditLedgerRef,
  AuditProducerEventCoreV1,
  Digest,
  PartyRef,
  ProtocolBindingId,
  SignedAuditEntryV1,
} from './types.js';

export interface AuditClock {
  now(): number;
}

export interface AuthenticatedAuditSubmissionContext {
  producerAuthority: string;
  tenantAuthority: string;
  /** Exact authenticated producer binding for non-public or non-DID identifiers. */
  producerRef?: PartyRef;
  /** Exact authenticated tenant binding for opaque or commitment-based tenant identifiers. */
  tenantRef?: PartyRef;
}

export interface AuditSubmissionAuthorizer {
  authorize(input: {
    submission: AuditRecorderSubmission;
    context: AuthenticatedAuditSubmissionContext;
  }): Promise<boolean> | boolean;
}

/**
 * Authoritative epoch-transition port. A successful result means the predecessor terminal
 * checkpoint was verified and the predecessor epoch was atomically sealed against new appends.
 * Implementations must be idempotent for identical transition inputs.
 */
export interface AuditEpochTransitionGuard {
  verifyAndSeal(input: {
    ledgerId: string;
    previousEpochId: string;
    nextEpochId: string;
    previousTerminalCheckpointDigest: Digest;
  }): Promise<boolean>;
}

export interface AuditRecorderServiceConfig {
  ledgerId: string;
  ledgerEpochId: string;
  tenantRef: PartyRef;
  binding: ProtocolBindingId;
  sourceId: string;
  journal: AuditJournalProvider;
  signer: AuditSigner;
  hasher: AuditHasher;
  clock: AuditClock;
  evidence?: AuditEvidenceProvider;
  authorizer?: AuditSubmissionAuthorizer;
  previousEpochId?: string;
  previousTerminalCheckpointDigest?: Digest;
  epochTransitionGuard?: AuditEpochTransitionGuard;
  maxAppendConflicts?: number;
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function sameHead(left: AuditHead | null, right: AuditHead | null): boolean {
  if (left === null || right === null) return left === right;
  return left.entryDigest === right.entryDigest && left.sequence === right.sequence;
}

function sameSigner(left: AuditSigner['ref'], right: AuditSigner['ref']): boolean {
  return left.did === right.did && left.kid === right.kid && left.alg === right.alg;
}

function sameParty(left: PartyRef, right: PartyRef): boolean {
  return canonicalizeJson(left) === canonicalizeJson(right);
}

function authorityMatchesParty(
  authority: string,
  boundRef: PartyRef | undefined,
  claimedRef: PartyRef,
): boolean {
  if (boundRef !== undefined) return sameParty(boundRef, claimedRef);
  return (claimedRef.kind === 'public_did' || claimedRef.kind === 'pairwise_did') &&
    claimedRef.did === authority;
}

export class AuditRecorderService {
  private readonly maxAppendConflicts: number;
  private initialization?: Promise<SignedAuditEntryV1>;

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
  }

  async submitAuthenticated(
    submission: AuditRecorderSubmission,
    context: AuthenticatedAuditSubmissionContext,
  ): Promise<SignedAuditEntryV1> {
    this.validateSubmissionEnvelope(submission, context);
    const producerEvent = parseAuditProducerEvent(submission.producerEvent);
    this.validateEventAuthority(producerEvent, context);
    if (this.config.authorizer !== undefined &&
      !(await this.config.authorizer.authorize({ submission, context }))) {
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

    await this.ensureInitialized();
    await this.persistSubmittedEvidence(submission.encryptedEvidence, producerEvent);
    return this.appendEvent(producerEvent, context, false, identity);
  }

  private validateSubmissionEnvelope(
    submission: AuditRecorderSubmission,
    context: AuthenticatedAuditSubmissionContext,
  ): void {
    if (!context.producerAuthority || !context.tenantAuthority) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.UNAUTHORIZED_SUBMISSION,
        'Authenticated producer and tenant authority are required',
      );
    }
    if (submission.ledgerId !== this.config.ledgerId) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.LEDGER_MISMATCH, 'Wrong audit ledger');
    }
    if (submission.expectedLedgerEpochId !== undefined &&
      submission.expectedLedgerEpochId !== this.config.ledgerEpochId) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.EPOCH_MISMATCH, 'Wrong audit ledger epoch');
    }
  }

  private validateEventAuthority(
    event: AuditProducerEventCoreV1,
    context: AuthenticatedAuditSubmissionContext,
  ): void {
    if (!authorityMatchesParty(
      context.producerAuthority,
      context.producerRef,
      event.source.producer,
    )) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.UNAUTHORIZED_SUBMISSION,
        'Event producer does not match the authenticated producer authority',
      );
    }
    if (!sameParty(event.tenantRef, this.config.tenantRef) ||
      !authorityMatchesParty(context.tenantAuthority, context.tenantRef, event.tenantRef)) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.UNAUTHORIZED_SUBMISSION,
        'Event tenant does not match the authenticated tenant authority',
      );
    }
  }

  private async persistSubmittedEvidence(
    evidence: readonly EncryptedEvidenceInput[],
    event: AuditProducerEventCoreV1,
  ): Promise<void> {
    if (evidence.length === 0) return;
    if (this.config.evidence === undefined) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.EVIDENCE_FAILURE,
        'Encrypted evidence was submitted but no evidence provider is configured',
      );
    }
    try {
      const refs = new Map(collectAuditEvidenceRefs(event).map((ref) => [ref.objectId, ref]));
      const submitted = new Set<string>();
      for (const item of evidence) {
        const referenced = refs.get(item.ref.objectId);
        if (submitted.has(item.ref.objectId) || referenced === undefined ||
          canonicalizeJson(referenced) !== canonicalizeJson(item.ref)) {
          throw new AuditProtocolError(
            AUDIT_ERROR_CODES.EVIDENCE_FAILURE,
            'Submitted evidence does not exactly match a unique frozen event reference',
            { objectId: item.ref.objectId },
          );
        }
        submitted.add(item.ref.objectId);
        await this.config.evidence.putIfAbsent(item);
      }
    } catch (error) {
      if (error instanceof AuditProtocolError &&
        error.code === AUDIT_ERROR_CODES.EVIDENCE_FAILURE) throw error;
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.EVIDENCE_FAILURE,
        'Required evidence could not be persisted',
        undefined,
        { cause: error },
      );
    }
  }

  private async ensureInitialized(): Promise<SignedAuditEntryV1> {
    const ledger = this.ledgerRef();
    const existingHead = await this.config.journal.getHead(ledger);
    if (existingHead !== null) {
      const first = this.config.journal.readRange({ ...ledger, limit: 1 });
      for await (const entry of first) return this.validateExistingGenesis(entry);
      throw new AuditProtocolError(AUDIT_ERROR_CODES.JOURNAL_FAILURE, 'Ledger head exists without genesis');
    }

    if (this.config.previousEpochId !== undefined) {
      const verifiedAndSealed = await this.config.epochTransitionGuard!.verifyAndSeal({
        ledgerId: this.config.ledgerId,
        previousEpochId: this.config.previousEpochId,
        nextEpochId: this.config.ledgerEpochId,
        previousTerminalCheckpointDigest: this.config.previousTerminalCheckpointDigest!,
      });
      if (!verifiedAndSealed) {
        throw new AuditProtocolError(
          AUDIT_ERROR_CODES.INVALID_CONFIGURATION,
          'Predecessor checkpoint could not be verified and sealed',
        );
      }
    }

    this.initialization ??= this.appendEvent(
      this.genesisEvent(),
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

  private validateExistingGenesis(candidate: SignedAuditEntryV1): SignedAuditEntryV1 {
    try {
      const entry = parseSignedAuditEntry(candidate);
      const details = entry.core.event.details;
      const valid = entry.core.sequence === '0' &&
        entry.core.previousEntryDigest === null &&
        entry.core.ledgerId === this.config.ledgerId &&
        entry.core.ledgerEpochId === this.config.ledgerEpochId &&
        sameSigner(entry.core.recorder, this.config.signer.ref) &&
        entry.core.event.eventType === 'ledger.epoch.started' &&
        entry.core.event.binding === this.config.binding &&
        entry.core.event.source.sourceId === this.config.sourceId &&
        entry.core.event.source.producer.kind === 'public_did' &&
        entry.core.event.source.producer.did === this.config.signer.ref.did &&
        sameParty(entry.core.event.tenantRef, this.config.tenantRef) &&
        details.family === 'ledger' &&
        details.phase === 'epoch_started' &&
        details.previousEpochId === this.config.previousEpochId &&
        details.previousTerminalCheckpointDigest ===
          this.config.previousTerminalCheckpointDigest;
      if (!valid) throw new Error('Genesis does not match recorder epoch configuration');
      return entry;
    } catch (error) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.JOURNAL_FAILURE,
        'Existing ledger genesis does not match the authoritative recorder configuration',
        undefined,
        { cause: error },
      );
    }
  }

  private genesisEvent(): AuditProducerEventCoreV1 {
    return parseAuditProducerEvent({
      schema: AUDIT_EVENT_SCHEMA_ID,
      eventId: `genesis:${this.config.ledgerId}:${this.config.ledgerEpochId}`,
      eventType: 'ledger.epoch.started',
      eventVersion: '1.0.0',
      binding: this.config.binding,
      occurredAt: this.config.clock.now(),
      tenantRef: this.config.tenantRef,
      source: {
        producer: { kind: 'public_did', did: this.config.signer.ref.did },
        sourceId: this.config.sourceId,
        sourceSequence: '0',
      },
      resource: { kind: 'public_did', did: this.config.signer.ref.did },
      action: { category: 'ledger.epoch' },
      outcome: 'succeeded',
      evidence: [],
      details: {
        family: 'ledger',
        phase: 'epoch_started',
        ...(this.config.previousEpochId
          ? {
              previousEpochId: this.config.previousEpochId,
              previousTerminalCheckpointDigest:
                this.config.previousTerminalCheckpointDigest,
            }
          : {}),
      },
      privacy: { classification: 'internal', retentionClass: 'integrity-ledger' },
    });
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
    if (duplicate !== null) return this.resolveDuplicate(duplicate, eventDigest);

    const ledger = this.ledgerRef();
    for (let attempt = 0; attempt <= this.maxAppendConflicts; attempt += 1) {
      const head = await this.config.journal.getHead(ledger);
      if (genesis && head !== null) {
        const raced = await this.config.journal.getByIdempotencyKey(
          this.config.ledgerId,
          idempotencyKey,
        );
        if (raced !== null) return this.resolveDuplicate(raced, eventDigest);
      }

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

      if (result.kind === 'appended' || result.kind === 'duplicate') {
        return result.kind === 'duplicate'
          ? this.resolveDuplicate(result.entry, eventDigest)
          : result.entry;
      }
      if (result.kind === 'idempotency_conflict') {
        return this.resolveDuplicate(result.existing, eventDigest);
      }
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
