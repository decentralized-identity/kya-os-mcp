import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { CryptoProviderAuditHasher, type AuditSigner } from '../crypto.js';
import { MemoryAuditEvidenceProvider } from '../evidence.js';
import { MemorySupportingAnchorProvider } from '../providers/anchor.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { MemoryAuditCheckpointObserver } from '../providers/observer.js';
import {
  assertAuditProviderContract,
  evaluateAuditAnchorProviderContract,
  evaluateAuditEvidenceProviderContract,
  evaluateAuditJournalProviderContract,
  evaluateAuditObserverProviderContract,
} from '../testing/provider-contracts.js';
import type { Digest, SignedAuditCheckpointV1 } from '../types.js';

const digest = (character: string) => `sha256:${character.repeat(64)}` as Digest;
const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());

class ObserverSigner implements AuditSigner {
  readonly ref = {
    did: 'did:key:zContractObserver',
    kid: 'did:key:zContractObserver#key',
    alg: 'EdDSA' as const,
  };
  async sign(): Promise<string> {
    return 'observer-signature';
  }
}

function checkpoint(
  treeSize: number,
  checkpointDigest: Digest,
  previousCheckpointDigest: Digest | null,
  rootDigest = digest('a'),
): SignedAuditCheckpointV1 {
  return {
    core: {
      schema: 'https://schema.kya-os.org/v1/protocol/audit/checkpoint/v1.0.0',
      checkpointId: `contract-checkpoint-${treeSize}`,
      ledgerId: 'contract-ledger', ledgerEpochId: 'contract-epoch',
      treeSize: String(treeSize), firstSequence: '0', lastSequence: String(treeSize - 1),
      rootDigest, headEntryDigest: digest('b'), previousCheckpointDigest,
      createdAt: 1_750_000_000_000 + treeSize,
      issuer: { did: 'did:key:zRecorder', kid: 'did:key:zRecorder#key', alg: 'EdDSA' },
      integritySuite: 'KYA-AUDIT-RFC9162-SHA256-JWS-2026',
    },
    checkpointDigest,
    jws: 'checkpoint-signature',
  };
}

describe('audit provider contract kit', () => {
  it('holds the memory journal to the authoritative atomic append contract', async () => {
    const report = await evaluateAuditJournalProviderContract(() => new MemoryAuditJournal());
    expect(report.passed).toBe(true);
    expect(() => assertAuditProviderContract(report)).not.toThrow();
  });

  it('holds the memory evidence vault to integrity and retention contracts', async () => {
    const report = await evaluateAuditEvidenceProviderContract({
      hasher,
      createProvider: () => new MemoryAuditEvidenceProvider(hasher),
    });
    expect(report.passed).toBe(true);
  });

  it('keeps independent-observer and supporting-anchor contracts distinct', async () => {
    const first = checkpoint(10, digest('c'), null);
    const next = checkpoint(20, digest('d'), first.checkpointDigest, digest('e'));
    const conflict = checkpoint(10, digest('f'), null, digest('f'));
    const rollback = checkpoint(9, digest('9'), null, digest('9'));
    const observerReport = await evaluateAuditObserverProviderContract({
      fixtures: { first, next, conflict, rollback },
      createProvider: () => new MemoryAuditCheckpointObserver({
        observerId: 'contract-observer', signer: new ObserverSigner(), hasher,
        clock: { now: () => 1_750_000_001_000 },
        verifyCheckpoint: async () => true,
        verifyConsistency: async () => true,
      }),
    });
    const anchorReport = await evaluateAuditAnchorProviderContract({
      checkpoint: first,
      otherCheckpoint: next,
      createProvider: () => new MemorySupportingAnchorProvider({
        kind: 'worm', providerId: 'contract-archive',
        clock: { now: () => 1_750_000_001_000 },
      }),
    });
    expect(observerReport.passed).toBe(true);
    expect(anchorReport.passed).toBe(true);
  });
});
