import { describe, expect, it, vi } from 'vitest';
import { AuditCheckpointCoordinator } from '../checkpoint-coordinator.js';
import type {
  AuditAnchorReceipt,
  AuditObservationReceiptV1,
  Digest,
  SignedAuditCheckpointV1,
} from '../types.js';

const digest = (character: string) => `sha256:${character.repeat(64)}` as Digest;

const checkpoint: SignedAuditCheckpointV1 = {
  core: {
    schema: 'https://schema.kya-os.org/v1/protocol/audit/checkpoint/v1.0.0',
    checkpointId: 'checkpoint:1', ledgerId: 'ledger', ledgerEpochId: 'epoch',
    treeSize: '1', firstSequence: '0', lastSequence: '0', rootDigest: digest('a'),
    headEntryDigest: digest('b'), previousCheckpointDigest: null,
    createdAt: 1_750_000_000_000,
    issuer: { did: 'did:key:zRecorder', kid: 'did:key:zRecorder#key', alg: 'EdDSA' },
    integritySuite: 'KYA-AUDIT-RFC9162-SHA256-JWS-2026',
  },
  checkpointDigest: digest('c'),
  jws: 'signed',
};

const observation: AuditObservationReceiptV1 = {
  core: {
    schema: 'https://schema.kya-os.org/v1/protocol/audit/observation/v1.0.0',
    observerId: 'monitor',
    observer: { did: 'did:key:zObserver', kid: 'did:key:zObserver#key', alg: 'EdDSA' },
    ledgerId: 'ledger', ledgerEpochId: 'epoch', checkpointDigest: digest('c'),
    treeSize: '1', observedAt: 1_750_000_000_001, previousObservationDigest: null,
  },
  observationDigest: digest('d'),
  jws: 'observed',
};

const anchor: AuditAnchorReceipt = {
  schema: 'https://schema.kya-os.org/v1/protocol/audit/anchor-receipt/v1.0.0',
  kind: 'worm', providerId: 'archive', checkpointDigest: digest('c'),
  issuedAt: 1_750_000_000_002,
};

describe('AuditCheckpointCoordinator', () => {
  it('publishes a committed checkpoint to independent observers and supporting anchors', async () => {
    const onPublished = vi.fn();
    const coordinator = new AuditCheckpointCoordinator({
      checkpoints: { createCheckpoint: async () => checkpoint },
      observers: [{
        capability: 'independent-observer', publish: async () => observation,
        latest: async () => ({ checkpoint, receipt: observation }),
        verifyObservation: async () => true,
      }],
      anchors: [{
        capability: 'supporting-anchor', kind: 'worm', publish: async () => anchor,
        verify: async () => true,
      }],
      requirements: { minimumObservers: 1, requiredAnchorKinds: ['worm'] },
      onPublished,
    });

    const result = await coordinator.createAndPublish({ ledgerId: 'ledger', ledgerEpochId: 'epoch' });
    expect(result.checkpoint).toBe(checkpoint);
    expect(result.observations).toEqual([observation]);
    expect(result.anchors).toEqual([anchor]);
    expect(result.failures).toEqual([]);
    expect(onPublished).toHaveBeenCalledOnce();
  });

  it('retries transient publication and fails closed when required evidence is unavailable', async () => {
    const publish = vi.fn().mockRejectedValue(new Error('observer offline'));
    const coordinator = new AuditCheckpointCoordinator({
      checkpoints: { createCheckpoint: async () => checkpoint },
      observers: [{
        capability: 'independent-observer', publish,
        latest: async () => null, verifyObservation: async () => false,
      }],
      anchors: [],
      requirements: { minimumObservers: 1, requiredAnchorKinds: [] },
      maxPublishAttempts: 3,
    });

    await expect(coordinator.createAndPublish({ ledgerId: 'ledger', ledgerEpochId: 'epoch' }))
      .rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_PUBLICATION_FAILED' });
    expect(publish).toHaveBeenCalledTimes(3);
  });

  it('captures a throwing backoff as a provider failure without abandoning sibling results', async () => {
    const publishedAnchor = vi.fn(async () => anchor);
    const coordinator = new AuditCheckpointCoordinator({
      checkpoints: { createCheckpoint: async () => checkpoint },
      observers: [{
        capability: 'independent-observer',
        publish: async () => { throw new Error('observer offline'); },
        latest: async () => null,
        verifyObservation: async () => false,
      }],
      anchors: [{
        capability: 'supporting-anchor', kind: 'worm', publish: publishedAnchor,
        verify: async () => true,
      }],
      maxPublishAttempts: 3,
      backoff: async () => { throw new Error('backoff unavailable'); },
    });

    const result = await coordinator.createAndPublish({ ledgerId: 'ledger', ledgerEpochId: 'epoch' });

    expect(result.anchors).toEqual([anchor]);
    expect(result.failures).toHaveLength(1);
    expect(result.failures[0]).toMatchObject({ role: 'observer', attempts: 1 });
    expect(result.failures[0]?.error).toBeInstanceOf(AggregateError);
    expect(publishedAnchor).toHaveBeenCalledOnce();
  });
});

describe('AuditCheckpointCoordinator: receipts for the checkpoint it published', () => {
  const ledger = { ledgerId: 'ledger', ledgerEpochId: 'epoch' };
  const observer = (publish: () => Promise<AuditObservationReceiptV1>) => ({
    capability: 'independent-observer' as const, publish,
    latest: async () => null, verifyObservation: async () => false,
  });
  const anchorProvider = (kind: AuditAnchorReceipt['kind'], publish: () => Promise<AuditAnchorReceipt>) => ({
    capability: 'supporting-anchor' as const, kind, publish, verify: async () => false,
  });
  const otherCheckpoint = (field: 'checkpointDigest' | 'treeSize' | 'ledgerId' | 'ledgerEpochId') =>
    field === 'checkpointDigest'
      ? { ...observation, core: { ...observation.core, checkpointDigest: digest('e') } }
      : { ...observation, core: { ...observation.core, [field]: field === 'treeSize' ? '2' : 'other' } };

  it('does not count an observation that names another checkpoint, tree size or ledger epoch', async () => {
    for (const field of ['checkpointDigest', 'treeSize', 'ledgerId', 'ledgerEpochId'] as const) {
      const coordinator = new AuditCheckpointCoordinator({
        checkpoints: { createCheckpoint: async () => checkpoint },
        observers: [observer(async () => otherCheckpoint(field))],
        requirements: { minimumObservers: 1, requiredAnchorKinds: [] },
      });
      const failure = await coordinator.createAndPublish(ledger).catch((error: unknown) => error);
      expect(failure, field).toMatchObject({
        code: 'AUDIT_CHECKPOINT_PUBLICATION_FAILED',
        details: { publishedObservers: 0, failedProviders: [{ role: 'observer', providerIndex: 0 }] },
      });
    }
  });

  it('does not count an anchor receipt for another checkpoint, or of a kind its provider is not', async () => {
    const coordinator = new AuditCheckpointCoordinator({
      checkpoints: { createCheckpoint: async () => checkpoint },
      anchors: [
        anchorProvider('worm', async () => ({ ...anchor, kind: 'rfc3161' })),
        anchorProvider('scitt', async () => ({ ...anchor, kind: 'scitt', checkpointDigest: digest('e') })),
      ],
      requirements: { minimumObservers: 0, requiredAnchorKinds: ['rfc3161', 'scitt'] },
    });
    await expect(coordinator.createAndPublish(ledger)).rejects.toMatchObject({
      code: 'AUDIT_CHECKPOINT_PUBLICATION_FAILED',
      details: {
        missingAnchorKinds: ['rfc3161', 'scitt'],
        failedProviders: [
          { role: 'anchor', providerIndex: 0, kind: 'worm' },
          { role: 'anchor', providerIndex: 1, kind: 'scitt' },
        ],
      },
    });
  });

  it('reports a receipt for another checkpoint as a failure, and never as evidence', async () => {
    const coordinator = new AuditCheckpointCoordinator({
      checkpoints: { createCheckpoint: async () => checkpoint },
      observers: [observer(async () => otherCheckpoint('checkpointDigest'))],
      anchors: [anchorProvider('worm', async () => ({ ...anchor, checkpointDigest: digest('e') }))],
    });
    const result = await coordinator.createAndPublish(ledger);
    expect(result.observations).toEqual([]);
    expect(result.anchors).toEqual([]);
    expect(result.failures.map(({ role, error }) => [role, (error as Error).message])).toEqual([
      ['anchor', 'Anchor answered with a receipt that is not for the published checkpoint'],
      ['observer', 'Observer answered with a receipt that is not for the published checkpoint'],
    ]);
  });

  it('retries a provider that first answers for another checkpoint', async () => {
    const publish = vi.fn()
      .mockResolvedValueOnce(otherCheckpoint('checkpointDigest'))
      .mockResolvedValueOnce(observation);
    const coordinator = new AuditCheckpointCoordinator({
      checkpoints: { createCheckpoint: async () => checkpoint },
      observers: [observer(publish)],
      requirements: { minimumObservers: 1, requiredAnchorKinds: [] },
      maxPublishAttempts: 2,
    });
    await expect(coordinator.createAndPublish(ledger)).resolves.toMatchObject({ observations: [observation] });
    expect(publish).toHaveBeenCalledTimes(2);
  });

  it('reports a malformed receipt as a failure', async () => {
    const coordinator = new AuditCheckpointCoordinator({
      checkpoints: { createCheckpoint: async () => checkpoint },
      observers: [observer(async () => ({}) as AuditObservationReceiptV1)],
      anchors: [anchorProvider('worm', async () => null as unknown as AuditAnchorReceipt)],
    });
    const result = await coordinator.createAndPublish(ledger);
    expect(result.failures.map(({ role }) => role)).toEqual(['anchor', 'observer']);
  });
});
