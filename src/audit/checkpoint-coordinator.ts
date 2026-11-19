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

/** Whether `receipt` is an observation of `checkpoint`, by its digest, ledger epoch and tree size. */
function isObservationOf(
  receipt: AuditObservationReceiptV1 | undefined,
  checkpoint: SignedAuditCheckpointV1,
): boolean {
  const core = receipt?.core;
  return core?.checkpointDigest === checkpoint.checkpointDigest &&
    core.ledgerId === checkpoint.core.ledgerId &&
    core.ledgerEpochId === checkpoint.core.ledgerEpochId &&
    core.treeSize === checkpoint.core.treeSize;
}

/** Whether `receipt` anchors `checkpoint`, and is of the kind its provider declares. */
function isAnchorReceiptOf(
  receipt: AuditAnchorReceipt | undefined,
  checkpoint: SignedAuditCheckpointV1,
  kind: AuditAnchorReceipt['kind'],
): boolean {
  return receipt?.checkpointDigest === checkpoint.checkpointDigest && receipt.kind === kind;
}

/**
 * A receipt that `matches` the published checkpoint; any other answer is a
 * failed publication, retried like a thrown one. A lagging or dishonest
 * service that answers with its receipt for an earlier checkpoint, or an
 * anchor that answers with a receipt of another kind, is never counted as
 * evidence for this one.
 */
async function receiptFor<T>(
  role: AuditCheckpointPublicationFailure['role'],
  publish: () => Promise<T>,
  matches: (receipt: T | undefined) => boolean,
): Promise<T> {
  const receipt = await publish();
  if (!matches(receipt)) {
    throw new AuditProtocolError(
      AUDIT_ERROR_CODES.CHECKPOINT_PUBLICATION_FAILED,
      `${role === 'observer' ? 'Observer' : 'Anchor'} answered with a receipt that is not for the published checkpoint`,
    );
  }
  return receipt;
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
        () => receiptFor('observer', () => provider.publish(checkpoint),
          (receipt) => isObservationOf(receipt, checkpoint)),
      );
      if (outcome.ok) observations.push(outcome.value);
      else failures.push(outcome.failure);
    }));
    await Promise.all(this.anchors.map(async (provider, providerIndex) => {
      const outcome = await this.publishWithRetry(
        'anchor',
        providerIndex,
        () => receiptFor('anchor', () => provider.publish(checkpoint),
          (receipt) => isAnchorReceiptOf(receipt, checkpoint, provider.kind)),
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
          try {
            await this.options.backoff?.({ role, providerIndex, attempt, error });
          } catch (backoffError) {
            return {
              ok: false,
              failure: {
                role,
                providerIndex,
                ...(kind === undefined ? {} : { kind }),
                attempts: attempt,
                error: new AggregateError(
                  [error, backoffError],
                  'Checkpoint publication backoff failed',
                ),
              },
            };
          }
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
