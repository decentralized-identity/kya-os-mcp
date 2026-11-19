import type { AuditHasher } from '../crypto.js';
import type {
  AuditEvidenceProvider,
  EncryptedEvidenceInput,
} from '../providers/evidence.js';
import type { Digest, EvidenceRef } from '../types.js';
import {
  check,
  digest,
  expectContract,
  report,
  type AuditProviderContractCheck,
  type AuditProviderContractReport,
} from './contract-harness.js';

function contractEvidenceRef(
  ciphertextDigest: Digest,
  size: number,
  objectId = 'evi_contract',
): EvidenceRef {
  return {
    objectId,
    ciphertextDigest,
    mediaType: 'application/octet-stream',
    size: String(size),
    encryption: {
      suite: 'A256GCM', keyId: 'contract-key-v1', nonce: 'AAAAAAAAAAAAAAAA',
      aadDigest: digest('e'),
    },
  };
}

/** Executable contract for encrypted evidence/retention adapters. */
export async function evaluateAuditEvidenceProviderContract(input: {
  createProvider(): AuditEvidenceProvider | Promise<AuditEvidenceProvider>;
  hasher: AuditHasher;
}): Promise<AuditProviderContractReport> {
  const checks: AuditProviderContractCheck[] = [];
  const ciphertext = Uint8Array.of(1, 2, 3, 4);
  const ciphertextDigest = await input.hasher.sha256(ciphertext);
  const evidence: EncryptedEvidenceInput = {
    ref: contractEvidenceRef(ciphertextDigest, ciphertext.byteLength),
    ciphertext,
  };

  await check(checks, 'stores exact ciphertext idempotently and returns defensive bytes', async () => {
    const provider = await input.createProvider();
    await provider.putIfAbsent(evidence);
    await provider.putIfAbsent(evidence);
    const first = await provider.get(evidence.ref, { actor: 'contract', purpose: 'verification' });
    expectContract(first !== null && first[0] === 1, 'stored ciphertext was unavailable');
    first[0] = 255;
    const second = await provider.get(evidence.ref, { actor: 'contract', purpose: 'verification' });
    expectContract(second?.[0] === 1, 'provider leaked mutable ciphertext storage');
  });

  await check(checks, 'rejects opaque object identifier collisions', async () => {
    const provider = await input.createProvider();
    await provider.putIfAbsent(evidence);
    const otherBytes = Uint8Array.of(5, 6, 7);
    const collision: EncryptedEvidenceInput = {
      ref: contractEvidenceRef(
        await input.hasher.sha256(otherBytes),
        otherBytes.byteLength,
        evidence.ref.objectId,
      ),
      ciphertext: otherBytes,
    };
    let rejected = false;
    try {
      await provider.putIfAbsent(collision);
    } catch {
      rejected = true;
    }
    expectContract(rejected, 'object ID collision was accepted');
  });

  await check(checks, 'enforces legal hold before irreversible disposal', async () => {
    const provider = await input.createProvider();
    await provider.putIfAbsent(evidence);
    await provider.applyRetention({
      kind: 'legal_hold', ref: evidence.ref, holdId: 'hold-1', authorizedBy: 'contract',
    });
    let rejected = false;
    try {
      await provider.applyRetention({
        kind: 'dispose', ref: evidence.ref, authorizedBy: 'contract', reason: 'expired',
      });
    } catch {
      rejected = true;
    }
    expectContract(rejected, 'held evidence was disposed');
    await provider.applyRetention({
      kind: 'release_hold', ref: evidence.ref, holdId: 'hold-1', authorizedBy: 'contract',
    });
    const disposed = await provider.applyRetention({
      kind: 'dispose', ref: evidence.ref, authorizedBy: 'contract', reason: 'expired',
    });
    expectContract(disposed.state === 'disposed', 'released evidence was not disposed');
    expectContract(!(await provider.has(evidence.ref)), 'disposed ciphertext remains available');
  });

  return report('evidence', checks);
}
