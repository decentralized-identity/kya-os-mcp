import type { AuditAnchorReceipt, SignedAuditCheckpointV1 } from '../types.js';

export interface AuditAnchorProvider {
  readonly capability: 'supporting-anchor';
  readonly kind: AuditAnchorReceipt['kind'];
  publish(checkpoint: SignedAuditCheckpointV1): Promise<AuditAnchorReceipt>;
  verify(
    checkpoint: SignedAuditCheckpointV1,
    receipt: AuditAnchorReceipt,
  ): Promise<boolean>;
}

/** Test/development adapter; production WORM/TSA/SCITT integrations implement the same port. */
export class MemorySupportingAnchorProvider implements AuditAnchorProvider {
  readonly capability = 'supporting-anchor' as const;
  readonly kind: AuditAnchorReceipt['kind'];

  constructor(private readonly config: {
    kind: AuditAnchorReceipt['kind'];
    providerId: string;
    clock: { now(): number };
  }) {
    this.kind = config.kind;
  }

  async publish(checkpoint: SignedAuditCheckpointV1): Promise<AuditAnchorReceipt> {
    return Object.freeze({
      schema: 'https://schema.kya-os.org/v1/protocol/audit/anchor-receipt/v1.0.0',
      kind: this.config.kind,
      providerId: this.config.providerId,
      checkpointDigest: checkpoint.checkpointDigest,
      issuedAt: this.config.clock.now(),
    });
  }

  async verify(
    checkpoint: SignedAuditCheckpointV1,
    receipt: AuditAnchorReceipt,
  ): Promise<boolean> {
    return receipt.kind === this.config.kind &&
      receipt.providerId === this.config.providerId &&
      receipt.checkpointDigest === checkpoint.checkpointDigest;
  }
}
