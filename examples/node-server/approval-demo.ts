/**
 * Demo approval-grant signing & verification for the step-up gate.
 *
 * withPolicyGate takes an `isValidApprovalSignature` verifier; the package ships
 * NO default one (it rejects all, fail-closed). This example provides a REAL
 * Ed25519 verifier (not `async () => true`) so the deny → step-up → approve flow
 * is end-to-end authentic: an approver signs the canonical grant with a did:key,
 * and the gate resolves that DID and verifies the signature. A forged grant fails.
 *
 * NOTE: the canonical-grant byte layout below is a DEMO convention. A normative,
 * shipped grant-signing helper is a tracked follow-up (see CHANGELOG known limits).
 */
import { canonicalize } from 'json-canonicalize';
import { NodeCryptoProvider } from './node-crypto.js';
import {
  extractPublicKeyFromDidKey,
  bytesToBase64,
  base64ToBytes,
  generateDidKeyFromBase64,
  type ApprovalGrant,
} from '@kya-os/mcp';

const crypto = new NodeCryptoProvider();

/** Bytes an approver signs over — every grant field except the signature. */
function canonicalGrantBytes(g: Omit<ApprovalGrant, 'signature'>): Uint8Array {
  return new TextEncoder().encode(
    canonicalize({
      approvalRequestId: g.approvalRequestId,
      approverDid: g.approverDid,
      decision: g.decision,
      requestHash: g.requestHash,
      ts: g.ts,
    }),
  );
}

/** Mint a fresh approver did:key and produce a signed ApprovalGrant bound to a requestHash. */
export async function mintSignedApproval(
  requestHash: string,
  opts: { decision?: 'approve' | 'deny'; approvalRequestId?: string } = {},
): Promise<{ grant: ApprovalGrant; approverDid: string }> {
  const kp = await crypto.generateKeyPair();
  const approverDid = generateDidKeyFromBase64(kp.publicKey);
  const unsigned: Omit<ApprovalGrant, 'signature'> = {
    approvalRequestId: opts.approvalRequestId ?? `appr-${requestHash.slice(-8)}`,
    approverDid,
    requestHash,
    decision: opts.decision ?? 'approve',
    ts: Math.floor(Date.now() / 1000),
  };
  const sig = await crypto.sign(canonicalGrantBytes(unsigned), kp.privateKey);
  return { grant: { ...unsigned, signature: bytesToBase64(sig) }, approverDid };
}

/**
 * Real `isValidApprovalSignature` for withPolicyGate: resolve the approver's
 * did:key and verify the grant's Ed25519 signature over the canonical bytes.
 */
export async function verifyApprovalGrantSignature(grant: ApprovalGrant): Promise<boolean> {
  try {
    const raw = extractPublicKeyFromDidKey(grant.approverDid);
    if (!raw) return false;
    const { signature, ...unsigned } = grant;
    return await crypto.verify(
      canonicalGrantBytes(unsigned),
      base64ToBytes(signature),
      bytesToBase64(raw),
    );
  } catch {
    return false;
  }
}
