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
