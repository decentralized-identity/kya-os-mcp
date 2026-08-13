/**
 * The full verifier stack, wired for on-chain trust:
 *
 *   - issuer DID documents resolve from cheqd testnet (not our server)
 *   - Ed25519Signature2020 proofs verified over the JCS-canonicalized VC
 *   - revocation read from the on-chain StatusList2021 DLR, fail-closed
 *
 * Shared by verify-once.ts (the judge artifact) and the demo server. Every
 * piece is a published @kya-os/mcp@1.14.0 export: the verifier resolves
 * `publicKeyMultibase` verification methods natively (no JWK-synthesizing
 * resolver wrapper), and CheqdStatusListResolver ships in
 * '@kya-os/mcp/cheqd' (no vendored resolver).
 */
import {
  DelegationCredentialVerifier,
  canonicalizeJSON,
  base64urlDecodeToBytes,
  bytesToBase64,
  type DelegationCredential,
  type DIDResolver,
} from '@kya-os/mcp';
import { CheqdStatusListResolver } from '@kya-os/mcp/cheqd';
import {
  cryptoProvider,
  gzipDecompressor,
  makeFetchProvider,
} from './wiring.js';

/** The plain DID resolver over the fetch provider — cheqd DIDs on-chain. */
export function makeDidResolver(fetchProvider: ReturnType<typeof makeFetchProvider>): DIDResolver {
  return {
    resolve: (did: string) => fetchProvider.resolveDID(did),
  };
}

export function buildOnChainVerifier(options: { issuerDid: string; cacheTtlMs?: number }) {
  const fetchProvider = makeFetchProvider();
  const didResolver = makeDidResolver(fetchProvider);

  const statusListResolver = new CheqdStatusListResolver({
    fetchProvider,
    didResolver,
    cryptoProvider,
    expectedIssuerDid: options.issuerDid,
    decompressor: gzipDecompressor,
    cacheTtlMs: options.cacheTtlMs ?? 0,
  });

  /**
   * Ed25519Signature2020 over the canonicalized VC minus proof. The verifier
   * has already resolved the issuer's DID document ON-CHAIN and picked the
   * proof's verification method — `publicKeyJwk` here is the shipped lookup's
   * JWK (synthesized from cheqd's publicKeyMultibase when needed); this
   * function only checks the raw signature against it.
   */
  const signatureVerifier = async (vc: DelegationCredential, publicKeyJwk: unknown) => {
    try {
      const proof = vc.proof;
      if (!proof?.proofValue) return { valid: false, reason: 'missing proofValue' };

      const jwk = publicKeyJwk as { x?: string } | undefined;
      if (!jwk?.x) return { valid: false, reason: 'verification method has no Ed25519 public key' };

      const unsigned: Record<string, unknown> = { ...vc };
      delete unsigned['proof'];
      const data = new TextEncoder().encode(canonicalizeJSON(unsigned));
      const signature = base64urlDecodeToBytes(proof.proofValue);
      const publicKeyBase64 = bytesToBase64(base64urlDecodeToBytes(jwk.x));

      if (await cryptoProvider.verify(data, signature, publicKeyBase64)) {
        return { valid: true };
      }
      return { valid: false, reason: 'signature does not verify against the issuer DID document' };
    } catch (err) {
      return { valid: false, reason: `signature check error: ${err instanceof Error ? err.message : String(err)}` };
    }
  };

  const verifier = new DelegationCredentialVerifier({
    didResolver,
    signatureVerifier,
    statusListResolver,
  });

  return { verifier, statusListResolver, fetchProvider };
}
