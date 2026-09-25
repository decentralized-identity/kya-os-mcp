import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';
import { CryptoProviderAuditHasher, Rfc9162MerkleTree, type Digest } from '@kya-os/mcp/audit';
import { describe, expect, it, vi } from 'vitest';
import { createPartyAudit } from '../src/lib/party-audit.js';

async function fixture(count: number) {
  const key = await new NodeCryptoProvider().generateKeyPair();
  const did = generateDidKeyFromBase64(key.publicKey);
  const audit = await createPartyAudit({ did, kid: `${did}#${did.slice(8)}`,
    privateKeyBase64: key.privateKey, publicKeyBase64: key.publicKey });
  for (let n = 0; n < count; n++) {
    await audit.record({ eventType: 'authorization.denied',
      action: { category: 'authorization', name: 'place_order' }, outcome: 'denied',
      evidence: [], details: { family: 'authorization', phase: 'denied' } });
  }
  await audit.anchor();
  return audit;
}

describe('audit report Merkle work', () => {
  it('shares subtree hashing across inclusion proofs instead of rehashing the whole ledger for each leaf', async () => {
    const audit = await fixture(64);
    const hash = vi.spyOn(NodeCryptoProvider.prototype, 'hash');
    try {
      const report = await audit.report();
      expect(report.allIncluded).toBe(true);
      // Bound cryptographic work, not elapsed time, so this catches quadratic
      // growth reliably on both CI and a busy workshop laptop.
      expect(hash.mock.calls.length).toBeLessThan(report.entries.length * 32);
    } finally { hash.mockRestore(); }
  });

  it('preserves published SDK proofs and roots for an uneven tree, including a later checkpoint', async () => {
    const audit = await fixture(16);
    const sdk = new Rfc9162MerkleTree(new CryptoProviderAuditHasher(new NodeCryptoProvider()));
    for (let snapshot = 0; snapshot < 2; snapshot++) {
      const report = await audit.report();
      const leaves = report.entries.filter(row => row.anchored).map(row => row.entryDigest as Digest);
      expect(report.tree[0]!.hash).toBe(await sdk.root(leaves));
      expect(report.tree[0]!.hash).toBe(report.checkpoint!.rootDigest);
      for (const proof of report.inclusions) {
        expect(proof.auditPath).toEqual(await sdk.inclusionProof(leaves, proof.leafIndex));
        expect(await sdk.verifyInclusion({ leaf: leaves[proof.leafIndex]!, leafIndex: proof.leafIndex,
          treeSize: leaves.length, root: report.checkpoint!.rootDigest as Digest, auditPath: proof.auditPath as Digest[] })).toBe(true);
      }
      if (!snapshot) {
        await audit.record({ eventType: 'authorization.denied',
          action: { category: 'authorization', name: 'place_order' }, outcome: 'denied',
          evidence: [], details: { family: 'authorization', phase: 'denied' } });
        const pending = await audit.report();
        expect(pending.unanchored).toBe(1);
        expect(pending.tree[0]!.hash).toBe(report.tree[0]!.hash);
        await audit.anchor();
      }
    }
  });
});
