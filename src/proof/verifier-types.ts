/**
 * The shapes `ProofVerifier` (`./verifier.ts`) takes and returns: its configuration, the signer
 * binding a caller may ask of a proof, and the result of a verification. `./verifier.ts` re-exports
 * them, so imports from there are unchanged.
 */

import type { ClockProvider, CryptoProvider, FetchProvider, NonceCacheProvider } from "../providers/base.js";
import type { ProofMeta } from "../types/protocol.js";
import type { ProofVerificationErrorCode } from "./errors.js";

export interface ProofVerificationResult {
  valid: boolean;
  /**
   * On a valid result, the proof's meta as its signature covers it (SPEC §7.4): read this, not
   * the meta of the proof as received. A member no signature covers is not in it, and an optional
   * claim written as "" is absent.
   */
  meta?: ProofMeta;
  reason?: string;
  error?: Error;
  errorCode?: ProofVerificationErrorCode;
  /** For `CONTENT_BINDING_MISMATCH`, `OUTCOME_MISMATCH` and `DELEGATION_BINDING_MISMATCH`, a `ProofBindingMismatch`. */
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
  /**
   * How long, in milliseconds, `fetchProvider.resolveDID` may take to answer: a number greater than
   * 0 and at most 2,147,483,647. Default 5,000. Any other value throws a `TypeError` naming the option.
   */
  dependencyTimeoutMs?: number;
}
