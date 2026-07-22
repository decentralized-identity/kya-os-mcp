import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { CryptoProviderAuditHasher, type AuditSigner } from '../crypto.js';
import { AuditProtocolError } from '../errors.js';
import { MemoryAuditCheckpointObserver } from '../providers/observer.js';
import {
  MemorySupportingAnchorProvider,
  type AuditAnchorProvider,
} from '../providers/anchor.js';
import type { Digest, SignedAuditCheckpointV1 } from '../types.js';

class TestSigner implements AuditSigner {
  readonly ref = {
    did: 'did:key:zObserver',
    kid: 'did:key:zObserver#zObserver',
    alg: 'EdDSA' as const,
  };
  async sign(payload: Uint8Array): Promise<string> {
    return `observer.${Buffer.from(payload).toString('base64url')}.signature`;
  }
}

const hash = (character: string) => `sha256:${character.repeat(64)}` as Digest;

function checkpoint(treeSize: number, root = 'a'): SignedAuditCheckpointV1 {
  return {
    core: {
      schema: 'https://schema.kya-os.org/v1/protocol/audit/checkpoint/v1.0.0',
      checkpointId: `checkpoint_${treeSize}`,
      ledgerId: 'kya:tenant:prod:primary',
      ledgerEpochId: 'epoch_1',
      treeSize: String(treeSize),
      firstSequence: '0',
      lastSequence: String(treeSize - 1),
      rootDigest: hash(root),
      headEntryDigest: hash('b'),
      previousCheckpointDigest: null,
      createdAt: 1_750_000_000_000 + treeSize,
      issuer: {
        did: 'did:key:zRecorder',
        kid: 'did:key:zRecorder#zRecorder',
        alg: 'EdDSA',
      },
      integritySuite: 'KYA-AUDIT-RFC9162-SHA256-JWS-2026',
    },
    checkpointDigest: hash(root === 'a' ? 'c' : root),
    jws: 'checkpoint.signature',
  };
}

function observer() {
  const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
  let time = 1_750_000_000_000;
  return new MemoryAuditCheckpointObserver({
    observerId: 'independent-monitor-1',
    signer: new TestSigner(),
    hasher,
    clock: { now: () => time++ },
    verifyCheckpoint: async () => true,
    verifyConsistency: async () => true,
  });
}

describe('checkpoint observation and supporting anchors', () => {
  it('retains monotonic checkpoints and links observation receipts', async () => {
    const monitor = observer();
    const first = await monitor.publish(checkpoint(10));
    const second = await monitor.publish({
      ...checkpoint(20, 'd'),
      core: {
        ...checkpoint(20, 'd').core,
        previousCheckpointDigest: checkpoint(10).checkpointDigest,
      },
    });

    expect(first.core.previousObservationDigest).toBeNull();
    expect(second.core.previousObservationDigest).toBe(first.observationDigest);
    expect((await monitor.latest({
      ledgerId: 'kya:tenant:prod:primary',
      ledgerEpochId: 'epoch_1',
    }))?.receipt).toEqual(second);
  });

  it('rejects rollback and conflicting roots at the same observed tree size', async () => {
    const monitor = observer();
    await monitor.publish(checkpoint(10));

    await expect(monitor.publish(checkpoint(9))).rejects.toMatchObject<Partial<AuditProtocolError>>({
      code: 'AUDIT_CHECKPOINT_ROLLBACK',
    });
    await expect(monitor.publish(checkpoint(10, 'f'))).rejects
      .toMatchObject<Partial<AuditProtocolError>>({
        code: 'AUDIT_CHECKPOINT_CONFLICT',
      });
  });

  it('serializes concurrent publication so an observer cannot sign a split view', async () => {
    const monitor = observer();
    const [left, right] = await Promise.allSettled([
      monitor.publish(checkpoint(10, 'a')),
      monitor.publish(checkpoint(10, 'f')),
    ]);

    expect([left.status, right.status].sort()).toEqual(['fulfilled', 'rejected']);
    const rejected = left.status === 'rejected' ? left.reason : right.status === 'rejected'
      ? right.reason
      : undefined;
    expect(rejected).toMatchObject({ code: 'AUDIT_CHECKPOINT_CONFLICT' });
  });

  it('keeps WORM/time/SCITT adapters typed as supporting anchors, not observers', async () => {
    const anchor: AuditAnchorProvider = new MemorySupportingAnchorProvider({
      kind: 'worm',
      providerId: 'object-lock-1',
      clock: { now: () => 1_750_000_000_000 },
    });
    const receipt = await anchor.publish(checkpoint(10));

    expect(anchor.capability).toBe('supporting-anchor');
    expect(receipt.kind).toBe('worm');
    expect('previousObservationDigest' in receipt).toBe(false);
  });

  it('fails closed when checkpoint or consistency verification rejects observed history', async () => {
    const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
    const rejectingCheckpoint = new MemoryAuditCheckpointObserver({
      observerId: 'monitor-rejecting-checkpoint', signer: new TestSigner(), hasher,
      clock: { now: () => 1_750_000_000_000 },
      verifyCheckpoint: async () => false,
      verifyConsistency: async () => true,
    });
    await expect(rejectingCheckpoint.publish(checkpoint(10))).rejects.toMatchObject({
      code: 'AUDIT_CHECKPOINT_INVALID',
    });

    const rejectingConsistency = new MemoryAuditCheckpointObserver({
      observerId: 'monitor-rejecting-consistency', signer: new TestSigner(), hasher,
      clock: { now: () => 1_750_000_000_000 },
      verifyCheckpoint: async () => true,
      verifyConsistency: async () => false,
    });
    const first = checkpoint(10);
    await rejectingConsistency.publish(first);
    await expect(rejectingConsistency.publish({
      ...checkpoint(20, 'd'),
      core: { ...checkpoint(20, 'd').core, previousCheckpointDigest: first.checkpointDigest },
    })).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_CONFLICT' });
  });

  it('makes repeated publication idempotent and verifies only the retained observation', async () => {
    const monitor = observer();
    const observedCheckpoint = checkpoint(10);
    const first = await monitor.publish(observedCheckpoint);
    await expect(monitor.publish(structuredClone(observedCheckpoint))).resolves.toEqual(first);
    await expect(monitor.verifyObservation(observedCheckpoint, first)).resolves.toBe(true);
    await expect(monitor.verifyObservation(observedCheckpoint, {
      ...first, observationDigest: hash('f'),
    })).resolves.toBe(false);
  });
});
