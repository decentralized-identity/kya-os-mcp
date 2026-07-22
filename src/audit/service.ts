import { canonicalizeJson } from '../utils/canonical-json.js';
import type { AuditDeliveryMode } from './assurance.js';
import { assertAuditCapabilities, type AuditCapabilities } from './assurance.js';
import type { AuditHasher } from './crypto.js';
import { AuditProtocolError, AUDIT_ERROR_CODES } from './errors.js';
import { collectAuditEvidenceRefs, digestAuditEvent } from './integrity.js';
import type { EncryptedEvidenceInput } from './providers/evidence.js';
import type { AuditOutboxProvider } from './providers/outbox.js';
import type {
  AuditRecorderClient,
  AuditRecorderSubmission,
} from './providers/recorder-client.js';
import {
  type AuditSourceState,
  type AuditSourceStateProvider,
} from './providers/source-state.js';
import { parseAuditProducerEvent } from './schemas.js';
import type {
  AuditProducerEventCoreV1,
  PartyRef,
  ProtocolBindingId,
  SignedAuditEntryV1,
} from './types.js';

type ServiceControlledEventFields =
  | 'schema'
  | 'eventId'
  | 'eventVersion'
  | 'binding'
  | 'occurredAt'
  | 'tenantRef'
  | 'source'
  | 'privacy';

export type AuditTrailEventInput =
  Omit<AuditProducerEventCoreV1, ServiceControlledEventFields> & {
    eventId?: string;
    occurredAt?: number;
    privacy?: AuditProducerEventCoreV1['privacy'];
  };

export interface AuditTrailConfiguration {
  recorder: AuditRecorderClient;
  delivery: AuditDeliveryMode;
  hasher: AuditHasher;
  ledgerId: string;
  expectedLedgerEpochId?: string;
  tenantRef: PartyRef;
  producer: PartyRef;
  sourceId: string;
  binding: ProtocolBindingId;
  privacy: AuditProducerEventCoreV1['privacy'];
  clock: { now(): number };
  outbox?: AuditOutboxProvider;
  eventIdFactory?: () => string;
  onDeliveryFailure?: (error: unknown, event: AuditProducerEventCoreV1) => void;
  /** Called when an event is committed but the local source watermark cannot advance. */
  onSourceStateFailure?: (error: unknown, event: AuditProducerEventCoreV1) => void;
  /** Optional deployment claim; validated against configured delivery at startup. */
  capabilities?: AuditCapabilities;
  /**
   * Durable in production. It is explicit because silently resetting source
   * sequence/linkage state on process restart makes high-water claims ambiguous.
   */
  sourceState: AuditSourceStateProvider;
}

export type AuditEmitResult =
  | { status: 'recorded'; event: AuditProducerEventCoreV1; entry: SignedAuditEntryV1 }
  | { status: 'pending'; event: AuditProducerEventCoreV1 }
  | { status: 'failed'; event: AuditProducerEventCoreV1; error: unknown };

export interface AuditRecordOptions {
  encryptedEvidence?: readonly EncryptedEvidenceInput[];
}

/** Producer-side service: creates frozen events and applies declared delivery semantics. */
export class AuditTrailService {
  readonly configuration: Readonly<AuditTrailConfiguration>;
  private idCounter = 0n;
  private readonly sourceState: AuditSourceStateProvider;
  private sourceConstructionTail: Promise<void> = Promise.resolve();

  get auditProfile(): AuditCapabilities['profile'] {
    return this.configuration.capabilities?.profile ?? 'AAP-0';
  }

  get capabilities(): AuditCapabilities | undefined {
    return this.configuration.capabilities;
  }

  constructor(configuration: AuditTrailConfiguration) {
    if (configuration.delivery === 'buffered' &&
      configuration.outbox?.capabilities.durability !== 'durable') {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.INVALID_CONFIGURATION,
        'Buffered audit delivery requires a durable outbox provider',
      );
    }
    if (configuration.capabilities !== undefined) {
      if (configuration.capabilities.delivery !== configuration.delivery) {
        throw new AuditProtocolError(
          AUDIT_ERROR_CODES.INVALID_CONFIGURATION,
          'Advertised audit delivery does not match the trail delivery mode',
        );
      }
      assertAuditCapabilities(configuration.capabilities);
      if (configuration.capabilities.sourceHighWater &&
        configuration.sourceState.capabilities.durability !== 'durable') {
        throw new AuditProtocolError(
          AUDIT_ERROR_CODES.INVALID_CONFIGURATION,
          'Advertised source high-water support requires durable source state',
        );
      }
    }
    this.configuration = Object.freeze({ ...configuration });
    this.sourceState = configuration.sourceState;
  }

  /**
   * A direct-mode retry is idempotent only when it rebuilds the identical frozen
   * event: callers retrying with a stable `eventId` must also pin `occurredAt`,
   * otherwise the recorder correctly rejects the divergent content as an
   * event-identity conflict. Buffered redelivery is always byte-stable.
   */
  async record(
    input: AuditTrailEventInput,
    options: AuditRecordOptions = {},
  ): Promise<AuditEmitResult> {
    const eventId = input.eventId ?? this.nextEventId();
    const encryptedEvidence = options.encryptedEvidence ?? [];
    const buffered = this.configuration.delivery === 'buffered';
    const { event, submission } = await this.withSourceConstruction(async () => {
      const builtEvent = await this.buildAndLinkEvent(input, eventId);
      this.assertEvidenceIsReferenced(builtEvent, encryptedEvidence);
      const frozenSubmission: AuditRecorderSubmission = Object.freeze({
        ledgerId: this.configuration.ledgerId,
        // Buffered submissions are never epoch-pinned: a durable outbox item may
        // be redelivered after an epoch rollover, where logical-ledger
        // idempotency (not epoch pinning) carries the retry guarantee.
        ...(buffered || this.configuration.expectedLedgerEpochId === undefined
          ? {}
          : { expectedLedgerEpochId: this.configuration.expectedLedgerEpochId }),
        producerEvent: builtEvent,
        encryptedEvidence: Object.freeze([...encryptedEvidence]),
      });
      if (buffered) {
        // Enqueued inside the source-construction lock so items commit to the
        // outbox in claimed source-sequence order for FIFO providers.
        await this.configuration.outbox!.enqueue(Object.freeze({
          eventId: builtEvent.eventId,
          submission: frozenSubmission,
          enqueuedAt: this.configuration.clock.now(),
          attempts: 0,
        }));
      }
      return { event: builtEvent, submission: frozenSubmission };
    });

    if (buffered) return { status: 'pending', event };

    let entry: SignedAuditEntryV1;
    try {
      entry = await this.submitAndValidate(submission);
    } catch (error) {
      this.configuration.onDeliveryFailure?.(error, event);
      if (this.configuration.delivery === 'required') throw error;
      return { status: 'failed', event, error };
    }
    try {
      await this.sourceState.markReceipted(
        this.configuration.sourceId,
        event.source.sourceSequence!,
        entry.entryDigest,
      );
    } catch (error) {
      // The recorder commit is authoritative and must not be reported as
      // failed: doing so encourages a caller to emit a new event identity.
      this.configuration.onSourceStateFailure?.(error, event);
    }
    return { status: 'recorded', event, entry };
  }

  async flush(limit?: number): Promise<{ delivered: number; failed: number }> {
    if (this.configuration.delivery !== 'buffered') return { delivered: 0, failed: 0 };
    let delivered = 0;
    let failed = 0;
    const blockedSources = new Set<string>();
    for await (const item of this.configuration.outbox!.pending(limit)) {
      const sourceId = item.submission.producerEvent.source.sourceId;
      if (blockedSources.has(sourceId)) continue;
      try {
        const entry = await this.submitAndValidate(item.submission);
        try {
          await this.sourceState.markReceipted(
            sourceId,
            item.submission.producerEvent.source.sourceSequence!,
            entry.entryDigest,
          );
        } catch (error) {
          this.configuration.onSourceStateFailure?.(error, item.submission.producerEvent);
        }
        await this.configuration.outbox!.markDelivered(item.eventId);
        delivered += 1;
      } catch (error) {
        await this.configuration.outbox!.markFailed(item.eventId, error);
        this.configuration.onDeliveryFailure?.(error, item.submission.producerEvent);
        blockedSources.add(sourceId);
        failed += 1;
      }
    }
    return { delivered, failed };
  }

  async getSourceState(): Promise<AuditSourceState> {
    return this.sourceState.getState(this.configuration.sourceId);
  }

  /** Emits the producer's declared high-water mark as an ordinary chained event. */
  async recordSourceHighWater(input: { eventId?: string } = {}): Promise<AuditEmitResult> {
    const state = await this.getSourceState();
    return this.record({
      ...(input.eventId === undefined ? {} : { eventId: input.eventId }),
      eventType: 'audit.source_high_water',
      action: { category: 'audit.source_high_water' },
      outcome: 'succeeded',
      evidence: [],
      details: {
        family: 'administration',
        phase: 'source_high_water',
        sourceSequence: state.highestEmitted,
      },
    });
  }

  private async withSourceConstruction<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.sourceConstructionTail;
    let release!: () => void;
    this.sourceConstructionTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  private async buildAndLinkEvent(
    input: AuditTrailEventInput,
    eventId: string,
  ): Promise<AuditProducerEventCoreV1> {
    const claim = await this.sourceState.claimEvent(this.configuration.sourceId, eventId);
    const event = this.buildEvent(input, eventId, claim);
    const eventDigest = await digestAuditEvent(this.configuration.hasher, event);
    await this.sourceState.markEmitted(
      this.configuration.sourceId,
      eventId,
      claim.sequence,
      eventDigest,
    );
    return event;
  }

  private buildEvent(
    input: AuditTrailEventInput,
    eventId: string,
    sourceClaim: { sequence: string; previousSourceEventDigest?: `sha256:${string}` },
  ): AuditProducerEventCoreV1 {
    return parseAuditProducerEvent({
      ...input,
      schema: 'https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0',
      eventId,
      eventVersion: '1.0.0',
      binding: this.configuration.binding,
      occurredAt: input.occurredAt ?? this.configuration.clock.now(),
      tenantRef: this.configuration.tenantRef,
      source: {
        producer: this.configuration.producer,
        sourceId: this.configuration.sourceId,
        sourceSequence: sourceClaim.sequence,
        ...(sourceClaim.previousSourceEventDigest === undefined
          ? {}
          : { previousSourceEventDigest: sourceClaim.previousSourceEventDigest }),
      },
      privacy: input.privacy ?? this.configuration.privacy,
    });
  }

  private nextEventId(): string {
    if (this.configuration.eventIdFactory !== undefined) {
      return this.configuration.eventIdFactory();
    }
    this.idCounter += 1n;
    return `audit_${this.configuration.clock.now()}_${this.idCounter}`;
  }

  private assertEvidenceIsReferenced(
    event: AuditProducerEventCoreV1,
    encryptedEvidence: readonly EncryptedEvidenceInput[],
  ): void {
    const refs = new Map(collectAuditEvidenceRefs(event).map((ref) => [ref.objectId, ref]));
    const submittedIds = new Set<string>();
    for (const item of encryptedEvidence) {
      const referenced = refs.get(item.ref.objectId);
      if (submittedIds.has(item.ref.objectId) || referenced === undefined ||
        canonicalizeJson(referenced) !== canonicalizeJson(item.ref)) {
        throw new AuditProtocolError(
          AUDIT_ERROR_CODES.EVIDENCE_FAILURE,
          'Encrypted evidence must exactly match one unique reference in the frozen event',
          { objectId: item.ref.objectId },
        );
      }
      submittedIds.add(item.ref.objectId);
    }
  }

  private async submitAndValidate(
    submission: AuditRecorderSubmission,
  ): Promise<SignedAuditEntryV1> {
    const entry = await this.configuration.recorder.submit(submission);
    const eventDigest = await digestAuditEvent(
      this.configuration.hasher,
      submission.producerEvent,
    );
    // The binding is content-scoped: an entry from an earlier retained epoch is a
    // legitimate logical-ledger duplicate. Epoch placement of new appends is the
    // recorder's envelope guarantee, and epoch claims are recorder-signed and
    // independently verifiable against checkpoints and mirrors.
    if (entry.core.ledgerId !== submission.ledgerId ||
      entry.eventDigest !== eventDigest ||
      entry.core.eventDigest !== eventDigest ||
      canonicalizeJson(entry.core.event) !== canonicalizeJson(submission.producerEvent)) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.JOURNAL_FAILURE,
        'Recorder response does not bind the submitted frozen producer event',
      );
    }
    return entry;
  }
}

export function createAuditTrail(configuration: AuditTrailConfiguration): AuditTrailService {
  return new AuditTrailService(configuration);
}
