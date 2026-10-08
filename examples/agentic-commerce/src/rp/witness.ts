/**
 * The Responsible Party as an INDEPENDENT WITNESS of the merchant's audit
 * ledger — the SDK's `MemoryAuditCheckpointObserver`, keyed with the RP's own
 * did:web key.
 *
 * The merchant posts each signed RFC 9162 checkpoint here. The RP verifies the
 * checkpoint's digest and signature against the merchant's DID, checks that a
 * later checkpoint consistently EXTENDS the last one it saw (RFC 9162
 * consistency proof, not just the chain link), and answers with a signed
 * observation receipt. From then on the merchant cannot publish a different
 * history for that tree size without the receipt contradicting it.
 *
 * Trust boundary, honestly: this witness runs in the RP hub process for the
 * stage. In production it is any party the shopper and the merchant do not
 * share — the RP, a transparency log, an auditor.
 */
import { canonicalizeJSON, resolveDidKeySync } from '@kya-os/mcp';
import {
  AUDIT_DIGEST_DOMAINS,
  CompactJwsAuditSignatureVerifier,
  CompactJwsAuditSigner,
  CryptoProviderAuditHasher,
  MemoryAuditCheckpointObserver,
  Rfc9162MerkleTree,
  hashAuditValue,
  parseSignedAuditCheckpoint,
  type AuditMerkleConsistencyProofV1,
  type AuditObservationReceiptV1,
  type SignedAuditCheckpointV1,
  type SignerRef,
} from '@kya-os/mcp/audit';
import { NodeCryptoProvider } from '@kya-os/mcp';
import { signingKeyFor } from '../lib/keys.js';
import type { KeyedIdentity } from '../lib/wiring.js';

const encoder = new TextEncoder();

export interface WitnessRequest {
  checkpoint: SignedAuditCheckpointV1;
  /** Present when the RP has already observed an earlier tree size. */
  consistency?: { oldTreeSize: string; oldRoot: string; proof: AuditMerkleConsistencyProofV1 } | null;
}

export interface Witness {
  observer: SignerRef;
  /** Verify + record + sign. Throws with a reason on refusal. */
  observe(request: WitnessRequest): Promise<AuditObservationReceiptV1>;
  latest(ledgerId: string, ledgerEpochId: string): Promise<{ checkpoint: SignedAuditCheckpointV1; receipt: AuditObservationReceiptV1 } | null>;
  observations: number;
}

export async function createWitness(identity: KeyedIdentity, options: { observerId?: string; acceptIssuer?: () => string; clock?: { now(): number } } = {}): Promise<Witness> {
  const clock = options.clock ?? Date;
  const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
  const tree = new Rfc9162MerkleTree(hasher);
  const observer: SignerRef = { did: identity.did, kid: identity.kid, alg: 'EdDSA' };
  const signer = new CompactJwsAuditSigner(observer, await signingKeyFor(identity));

  // The merchant signs checkpoints with its did:key — decoded locally, no network.
  const merchantKeys = new CompactJwsAuditSignatureVerifier({
    resolve: async (ref) => {
      const doc = resolveDidKeySync(ref.did);
      const method = doc?.verificationMethod?.find((m) => m.id === ref.kid) ?? doc?.verificationMethod?.[0];
      return (method?.publicKeyJwk as never) ?? null;
    },
  });

  // Consistency proofs travel with the request; the SDK observer only sees
  // (previous, next), so park the proof by the next checkpoint's digest.
  const pendingProofs = new Map<string, WitnessRequest['consistency']>();
  let observations = 0;

  const memory = new MemoryAuditCheckpointObserver({
    observerId: options.observerId ?? `rp-witness:${identity.did}`,
    signer,
    hasher,
    clock,
    async verifyCheckpoint(checkpoint) {
      const parsed = parseSignedAuditCheckpoint(checkpoint); // schema, throws when malformed
      const accept = options.acceptIssuer?.();
      if (accept && parsed.core.issuer.did !== accept) return false;
      const digest = await hashAuditValue(hasher, AUDIT_DIGEST_DOMAINS.checkpoint, parsed.core);
      if (digest !== parsed.checkpointDigest) return false;
      return merchantKeys.verify(encoder.encode(canonicalizeJSON(parsed.core)), parsed.jws, parsed.core.issuer);
    },
    async verifyConsistency(previous, next) {
      const c = pendingProofs.get(next.checkpointDigest);
      if (!c || c.oldTreeSize !== previous.core.treeSize || c.oldRoot !== previous.core.rootDigest) return false;
      return tree.verifyConsistency({
        oldSize: Number(previous.core.treeSize),
        newSize: Number(next.core.treeSize),
        oldRoot: previous.core.rootDigest,
        newRoot: next.core.rootDigest,
        auditPath: c.proof.auditPath,
      });
    },
  });

  return {
    observer,
    get observations() { return observations; },
    async observe(request) {
      if (request.consistency) pendingProofs.set(request.checkpoint.checkpointDigest, request.consistency);
      try {
        const receipt = await memory.publish(request.checkpoint);
        observations += 1;
        return receipt;
      } finally {
        pendingProofs.delete(request.checkpoint.checkpointDigest);
      }
    },
    latest: (ledgerId, ledgerEpochId) => memory.latest({ ledgerId, ledgerEpochId }),
  };
}
