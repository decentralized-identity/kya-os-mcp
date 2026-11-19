/**
 * Real fixtures for the observer contract: checkpoints one recorder key signed over a ledger
 * history, and over a rewritten history of the same ledger epoch, as a holder of that key could
 * sign. Also an in-memory observer wired as an independent observer should be: it verifies each
 * checkpoint's signature under the trust policy, and each extension by a consistency proof against
 * the tree it observed last.
 */

import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { AuditCheckpointBuilder, MemoryAuditCheckpointStore } from '../checkpoint.js';
import { CryptoProviderAuditHasher, type AuditSigner } from '../crypto.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import {
  MemoryAuditCheckpointObserver,
  type MemoryAuditCheckpointObserverConfig,
} from '../providers/observer.js';
import { AuditRecorderService } from '../recorder-service.js';
import type { AuditCheckpointProviderContractFixtures } from '../testing/provider-contracts.js';
import type { SignedAuditCheckpointV1 } from '../types.js';
import { AuditArtifactVerifier } from '../verifier.js';
import {
  policy,
  producerEvent,
  tenantRef,
  TestSignatureVerifier,
  TestSigner,
} from './audit-fixtures.js';

export const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
export const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };

class ObserverSigner implements AuditSigner {
  readonly ref = {
    did: 'did:key:zContractObserver',
    kid: 'did:key:zContractObserver#key',
    alg: 'EdDSA' as const,
  };
  async sign(payload: Uint8Array): Promise<string> {
    return `observer.${Buffer.from(payload).toString('base64url')}.signature`;
  }
}

/** A ledger history the recorder key signs, `events` events after its genesis, and its checkpoints. */
async function ledgerHistory(name: string, events: number) {
  const journal = new MemoryAuditJournal();
  const signer = new TestSigner();
  const recorder = new AuditRecorderService({
    ...ledger, tenantRef, binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'recorder-1',
    journal, signer, hasher, clock: { now: () => 1_750_000_001_000 },
  });
  const builder = new AuditCheckpointBuilder({
    journal, store: new MemoryAuditCheckpointStore(), signer, hasher,
    clock: { now: () => 1_750_000_002_000 },
  });
  let recorded = 0;
  const record = async (count: number): Promise<void> => {
    for (let index = 0; index < count; index += 1) {
      recorded += 1;
      await recorder.submitAuthenticated(
        { ledgerId: ledger.ledgerId, producerEvent: producerEvent(`${name}_${recorded}`, recorded), encryptedEvidence: [] },
        { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef },
      );
    }
  };
  await record(events);
  return { builder, record, checkpoint: () => builder.createCheckpoint(ledger) };
}

/**
 * The observer contract's fixtures. `first` is tree size 3; `rollback` (2), `next` (4) and
 * `gapped` (6) are checkpoints of the same history; `conflict` (3) and `fork` (4) are of a
 * rewritten history under the same key.
 */
export async function observerContractFixtures(): Promise<{
  fixtures: Required<AuditCheckpointProviderContractFixtures>;
  builders: AuditCheckpointBuilder[];
}> {
  const real = await ledgerHistory('real', 1);
  const rollback = await real.checkpoint();
  await real.record(1);
  const first = await real.checkpoint();
  await real.record(1);
  const next = await real.checkpoint();
  await real.record(2);
  const gapped = await real.checkpoint();
  const rewritten = await ledgerHistory('rewritten', 2);
  const conflict = await rewritten.checkpoint();
  await rewritten.record(1);
  const fork = await rewritten.checkpoint();
  return {
    fixtures: { first, next, conflict, rollback, gapped, fork },
    builders: [real.builder, rewritten.builder],
  };
}

/** Whether any of `builders` serves a consistency proof from `previous` that closes to `next`. */
async function consistent(
  builders: readonly AuditCheckpointBuilder[],
  previous: SignedAuditCheckpointV1,
  next: SignedAuditCheckpointV1,
): Promise<boolean> {
  for (const builder of builders) {
    try {
      const proof = await builder.consistencyProof(ledger, previous.core.treeSize, next);
      if (await builder.verifyConsistency({
        oldTreeSize: previous.core.treeSize, oldRoot: previous.core.rootDigest, checkpoint: next, proof,
      })) return true;
    } catch {
      // This history holds no tree that `next` signs; another may.
    }
  }
  return false;
}

/** An in-memory observer that checks signatures and consistency; `overrides` weaken it. */
export function checkingObserver(
  builders: readonly AuditCheckpointBuilder[],
  overrides: Partial<MemoryAuditCheckpointObserverConfig> = {},
): MemoryAuditCheckpointObserver {
  const verifier = new AuditArtifactVerifier({ hasher, signatures: new TestSignatureVerifier() });
  return new MemoryAuditCheckpointObserver({
    observerId: 'contract-observer',
    signer: new ObserverSigner(),
    hasher,
    clock: { now: () => 1_750_000_003_000 },
    verifyCheckpoint: async (checkpoint) =>
      (await verifier.verifySignedCheckpoint(checkpoint, policy)).verdict === 'valid',
    verifyConsistency: (previous, next) => consistent(builders, previous, next),
    ...overrides,
  });
}
