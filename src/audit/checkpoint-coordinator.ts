import { AUDIT_ERROR_CODES, AuditProtocolError } from './errors.js';
import type { AuditAnchorProvider } from './providers/anchor.js';
import type { AuditCheckpointObserverProvider } from './providers/observer.js';
import type {
  AuditAnchorReceipt,
  AuditLedgerRef,
  AuditObservationReceiptV1,
  SignedAuditCheckpointV1,
} from './types.js';

export interface AuditCheckpointCreator {
  createCheckpoint(ledger: AuditLedgerRef): Promise<SignedAuditCheckpointV1>;
}

export interface AuditCheckpointPublicationFailure {
  role: 'observer' | 'anchor';
  providerIndex: number;
  kind?: AuditAnchorReceipt['kind'];
  attempts: number;
  error: unknown;
}

export interface AuditCheckpointPublicationResult {
  checkpoint: SignedAuditCheckpointV1;
  observations: AuditObservationReceiptV1[];
  anchors: AuditAnchorReceipt[];
  failures: AuditCheckpointPublicationFailure[];
}

export interface AuditCheckpointCoordinatorOptions {
  checkpoints: AuditCheckpointCreator;
  observers?: readonly AuditCheckpointObserverProvider[];
  anchors?: readonly AuditAnchorProvider[];
  requirements?: {
    minimumObservers: number;
    requiredAnchorKinds: readonly AuditAnchorReceipt['kind'][];
  };
  maxPublishAttempts?: number;
  backoff?: (input: {
    role: AuditCheckpointPublicationFailure['role'];
    providerIndex: number;
    attempt: number;
    error: unknown;
  }) => Promise<void>;
  onPublished?: (result: AuditCheckpointPublicationResult) => Promise<void> | void;
}

/**
 * Coordinates post-commit checkpoint publication. A failed publication never
 * rolls back or rewrites the already signed checkpoint.
 */
export class AuditCheckpointCoordinator {
  private readonly observers: readonly AuditCheckpointObserverProvider[];
  private readonly anchors: readonly AuditAnchorProvider[];
  private readonly maxAttempts: number;

  constructor(private readonly options: AuditCheckpointCoordinatorOptions) {
    this.observers = options.observers ?? [];
    this.anchors = options.anchors ?? [];
    this.maxAttempts = options.maxPublishAttempts ?? 1;
    if (!Number.isSafeInteger(this.maxAttempts) || this.maxAttempts < 1) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.INVALID_CONFIGURATION,
        'Checkpoint publication attempts must be a positive safe integer',
      );
    }
    const requirements = options.requirements;
    if (requirements !== undefined &&
      (!Number.isSafeInteger(requirements.minimumObservers) ||
        requirements.minimumObservers < 0)) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.INVALID_CONFIGURATION,
        'Minimum checkpoint observers must be a non-negative safe integer',
      );
    }
  }

  async createAndPublish(ledger: AuditLedgerRef): Promise<AuditCheckpointPublicationResult> {
    const checkpoint = await this.options.checkpoints.createCheckpoint(ledger);
    const observations: AuditObservationReceiptV1[] = [];
    const anchors: AuditAnchorReceipt[] = [];
    const failures: AuditCheckpointPublicationFailure[] = [];

    await Promise.all(this.observers.map(async (provider, providerIndex) => {
      const outcome = await this.publishWithRetry(
        'observer',
        providerIndex,
        () => provider.publish(checkpoint),
      );
      if (outcome.ok) observations.push(outcome.value);
      else failures.push(outcome.failure);
    }));
    await Promise.all(this.anchors.map(async (provider, providerIndex) => {
      const outcome = await this.publishWithRetry(
        'anchor',
        providerIndex,
        () => provider.publish(checkpoint),
        provider.kind,
      );
      if (outcome.ok) anchors.push(outcome.value);
      else failures.push(outcome.failure);
    }));

    observations.sort((left, right) => left.core.observerId.localeCompare(right.core.observerId));
    anchors.sort((left, right) =>
      left.kind.localeCompare(right.kind) || left.providerId.localeCompare(right.providerId));
    failures.sort((left, right) =>
      left.role.localeCompare(right.role) || left.providerIndex - right.providerIndex);
    const result = { checkpoint, observations, anchors, failures };
    this.assertRequirements(result);
    await this.options.onPublished?.(result);
    return result;
  }

  private async publishWithRetry<T>(
    role: AuditCheckpointPublicationFailure['role'],
    providerIndex: number,
    publish: () => Promise<T>,
    kind?: AuditAnchorReceipt['kind'],
  ): Promise<
    | { ok: true; value: T }
    | { ok: false; failure: AuditCheckpointPublicationFailure }
  > {
    let lastError: unknown;
    for (let attempt = 1; attempt <= this.maxAttempts; attempt += 1) {
      try {
        return { ok: true, value: await publish() };
      } catch (error) {
        lastError = error;
        if (attempt < this.maxAttempts) {
          await this.options.backoff?.({ role, providerIndex, attempt, error });
        }
      }
    }
    return {
      ok: false,
      failure: {
        role,
        providerIndex,
        ...(kind === undefined ? {} : { kind }),
        attempts: this.maxAttempts,
        error: lastError,
      },
    };
  }

  private assertRequirements(result: AuditCheckpointPublicationResult): void {
    const requirements = this.options.requirements;
    if (requirements === undefined) return;
    const missingKinds = [...new Set(requirements.requiredAnchorKinds)].filter((kind) =>
      !result.anchors.some((receipt) => receipt.kind === kind));
    if (result.observations.length < requirements.minimumObservers || missingKinds.length > 0) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.CHECKPOINT_PUBLICATION_FAILED,
        'Signed checkpoint did not obtain the required external publication evidence',
        {
          checkpointDigest: result.checkpoint.checkpointDigest,
          requiredObservers: requirements.minimumObservers,
          publishedObservers: result.observations.length,
          missingAnchorKinds: missingKinds,
          failedProviders: result.failures.map(({ role, providerIndex, kind, attempts }) => ({
            role,
            providerIndex,
            ...(kind === undefined ? {} : { kind }),
            attempts,
          })),
        },
      );
    }
  }
}
