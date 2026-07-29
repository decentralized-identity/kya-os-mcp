/**
 * KYA-OS Entity Card — stateless per-request holder-of-key proof (`org.kya-os/proof.v1`).
 *
 * The security-critical module, split into focused units re-exported here:
 *   - types      (./types):    CardProofMeta + the minting/verifying seams and result shapes.
 *   - signer     (./signer):   the default Ed25519 minting seam (jose, no mcp-i-core).
 *   - build      (./build):    buildCardProof — mint one proof under the SHIPPED `_meta` key.
 *   - verify     (./verify):   verifyCardProof — recompute every binding, fail-closed.
 *   - http-sig   (./http-sig): toHttpMessageSignature — the RFC 9421 sibling carrier.
 *   - canonical  (./canonical): computeRequestHash — JCS request binding (shared by both halves).
 *   - nonce-cache (./nonce-cache): the batteries-included ATOMIC replay seams (InMemoryNonceCache
 *                              + the NonceCacheProvider adapter) so the safe consume is the default.
 *
 * Distinct from — and orthogonal to — the legacy session-bound proof in `src/proof`: the card proof
 * rides its OWN `_meta['org.kya-os/request-proof']` key, separate from the legacy `org.kya-os/proof`, so
 * both regimes can run on one server without either guard seeing the other's proof.
 */

export * from './types.js';
export * from './signer.js';
export * from './build.js';
export * from './verify.js';
export * from './http-sig.js';
export * from './nonce-cache.js';
export { computeRequestHash, digestsEqual } from './canonical.js';
