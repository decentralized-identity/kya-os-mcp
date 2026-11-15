/**
 * The shapes `ProofVerifier` (`./verifier.ts`) takes and returns: its configuration, the signer
 * binding a caller may ask of a proof, and the result of a verification. `./verifier.ts` re-exports
 * them, so imports from there are unchanged.
 */

import type { ClockProvider, CryptoProvider, FetchProvider, NonceCacheProvider } from "../providers/base.js";
import type { ProofVerificationErrorCode } from "./errors.js";

export interface ProofVerificationResult {
  valid: boolean;
  reason?: string;
  error?: Error;
  errorCode?: ProofVerificationErrorCode;
  details?: Record<string, unknown>;
}

/** Who a verified proof must come from and be addressed to. */
export interface ProofVerificationOptions {
  /** `meta.did` must equal this: the signer the caller expects (e.g. the server it called). */
  expectedDid?: string;
  /** `meta.audience` must equal this, or be one of the array (DID rotation, multi-DID servers). */
  expectedAudience?: string | string[];
}

export interface ProofVerifierConfig {
  cryptoProvider: CryptoProvider;
  clockProvider: ClockProvider;
  nonceCacheProvider: NonceCacheProvider;
  fetchProvider: FetchProvider;
  timestampSkewSeconds?: number;
  /**
   * Minimum retention in seconds; raised to cover the proof's accepted lifetime
   * and supported skew updates. 0 keeps each nonce for that window only.
   */
  nonceTtlSeconds?: number;
  /**
   * Refuse nonce caches without an atomic `consume()` instead of falling back
   * to `has()` then `add()`. The constructor throws for such a cache.
   */
  requireAtomicNonce?: boolean;
}
