/**
 * KYA-OS Middleware — delegation verification plumbing.
 *
 * Builds the DID resolver, the embedded-proof signature verifier, the
 * `DelegationCredentialVerifier`, and the framework-agnostic chain-validation
 * adapter (chain-enforcement.ts) once per middleware instance. Extracted from
 * `wrapWithDelegation` so the gate module holds only the request flow.
 */

import { createDidKeyResolver } from "../delegation/did-key-resolver.js";
import { createDidWebResolver } from "../delegation/did-web-resolver.js";
import {
  buildDidResolverRegistry,
} from "../delegation/did-resolver-registry.js";
import { getDidMethod } from "../utils/did-helpers.js";
import {
  DelegationCredentialVerifier,
  type DIDResolver,
  type SignatureVerificationFunction,
} from "../delegation/vc-verifier.js";
import {
  validateDelegationChain as validateDelegationChainCore,
  type ChainValidationResult,
} from "../delegation/chain-enforcement.js";
import { RuntimeFetchProvider } from "../providers/runtime-fetch.js";
import { canonicalizeJSON, parseVCJWT } from "../delegation/utils.js";
import { base64urlDecodeToBytes, bytesToBase64 } from "../utils/base64.js";
import {
  createNeedsAuthorizationError,
  readCredentialProofValue,
  type DelegationCredential,
} from "../types/protocol.js";
import { logger } from "../logging/index.js";
import { TtlCache } from "../utils/ttl-cache.js";
import type {
  KyaOsChallengeFormatter,
  KyaOsToolHandler,
  KyaOsToolResult,
} from "./with-kya-os.types.js";
import type { MiddlewareDeps } from "./with-kya-os.deps.js";
import { sanitizeForMessage } from "./with-kya-os.helpers.js";
import { withoutOutcomeMeta } from "./with-kya-os.session.js";

/** Per-tool delegation-gate config shared by the gate + its challenge builder. */
export interface DelegationGateConfig {
  scopeId: string;
  consentUrl: string;
  formatChallenge?: KyaOsChallengeFormatter;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * The challenge result a `formatChallenge` hook returned, in either form: its
 * content alone (an array), or content with `structuredContent`, `isError` and
 * `_meta`. All of it is set before the challenge is signed. The `_meta`
 * members only the middleware may set are dropped, never trusted. Undefined
 * for a value of neither form.
 */
function toChallengeResult(formatted: unknown): KyaOsToolResult | undefined {
  if (Array.isArray(formatted)) return { content: formatted };
  if (!isRecord(formatted) || !Array.isArray(formatted.content)) return undefined;
  const { content, structuredContent, isError, _meta } = formatted;
  return withoutOutcomeMeta({
    content,
    ...(isRecord(structuredContent) ? { structuredContent } : {}),
    ...(typeof isError === "boolean" ? { isError } : {}),
    ...(isRecord(_meta) ? { _meta } : {}),
  });
}

/**
 * Outcome of authenticating a presented delegation. On success the caller gets
 * the normalized credential and its wire form; on failure a sanitizable reason
 * plus the best-effort parsed credential (for audit references), if any.
 */
export type DelegationCheck =
  | { valid: true; vc: DelegationCredential; isJwt: boolean; expiresAt?: number }
  | { valid: false; reason: string; vc?: DelegationCredential };

export interface DelegationVerification {
  /**
   * Authenticate and normalize a presented `_kyaos_delegation`, in either wire
   * form, into a single verified credential. A VC-JWT **string** is verified by
   * its compact-JWS ENVELOPE signature against the issuer's published key; an
   * **object** is verified by its embedded Data-Integrity proof. Both then run
   * the full chain / scope-superset / expiry / status / revocation walk. Owning
   * the `skipSignature` decision here (never at the call site) is what stops a
   * JWT envelope from being silently skipped. Returns a {@link DelegationCheck},
   * never throws on normal or structurally-malformed input.
   */
  verifyDelegation(delegationArg: unknown): Promise<DelegationCheck>;
  /** A structured `{ error, reason }` tool response with a sanitized reason. */
  buildDelegationErrorResponse(
    error: string,
    reason: string,
  ): Awaited<ReturnType<KyaOsToolHandler>>;
  /**
   * Build the signed-later `needs_authorization` challenge for a call that
   * arrived without a delegation or resolvable grant: a fresh resume token, a
   * 5-minute expiry, and the result to emit (respecting `config.formatChallenge`,
   * which falls back to the default JSON challenge if it throws or returns
   * neither content nor a challenge result).
   */
  buildNeedsAuthorizationChallenge(
    toolName: string,
    config: DelegationGateConfig,
  ): Promise<{
    challenge: KyaOsToolResult;
    message: string;
  }>;
}

export function createDelegationVerification(
  deps: MiddlewareDeps,
): DelegationVerification {
  const { identity, cryptoProvider, delegationConfig } = deps;

  const didKeyResolver = createDidKeyResolver();
  const fetchProvider =
    delegationConfig?.fetchProvider ??
    (typeof globalThis.fetch === "function"
      ? new RuntimeFetchProvider()
      : undefined);
  const didWebResolver = fetchProvider
    ? createDidWebResolver(fetchProvider)
    : undefined;
  const configuredDidResolvers = buildDidResolverRegistry(
    delegationConfig?.didResolvers,
    fetchProvider,
  );
  const didResolver: DIDResolver = {
    async resolve(did: string) {
      const customResolver = delegationConfig?.didResolver;
      if (customResolver) {
        const resolved = await customResolver.resolve(did);
        if (resolved) {
          return resolved;
        }
      }

      const method = getDidMethod(did);
      const configuredResolver = method ? configuredDidResolvers[method] : undefined;
      if (configuredResolver) {
        try {
          const resolved = await configuredResolver.resolve(did);
          if (resolved) {
            return resolved;
          }
        } catch {
          return null;
        }
      }

      if (did.startsWith("did:key:")) {
        return didKeyResolver.resolve(did);
      }

      if (did.startsWith("did:web:")) {
        return didWebResolver?.resolve(did) ?? null;
      }

      return null;
    },
  };

  const signatureVerifier: SignatureVerificationFunction = async (
    vc: DelegationCredential,
    publicKeyJwk: unknown,
  ): Promise<{ valid: boolean; reason?: string }> => {
    const proof = vc.proof;
    if (!proof) {
      return { valid: false, reason: "Missing proof" };
    }

    const proofValue = readCredentialProofValue(proof as Record<string, unknown>);
    if (!proofValue) {
      return { valid: false, reason: "Missing proofValue in proof" };
    }

    // Reconstruct the unsigned VC (without proof) for signature verification
    const vcRecord = vc as Record<string, unknown>;
    const vcWithoutProof: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(vcRecord)) {
      if (k !== "proof") vcWithoutProof[k] = v;
    }
    const canonical = canonicalizeJSON(vcWithoutProof);
    const data = new TextEncoder().encode(canonical);

    // Decode signature from base64url proof value
    const sigBytes = base64urlDecodeToBytes(proofValue);

    // Get public key from JWK (x is base64url-encoded raw key bytes)
    const jwk = publicKeyJwk as { x?: string };
    if (!jwk.x) {
      return { valid: false, reason: "No x field in publicKeyJwk" };
    }

    // Convert base64url key to standard base64 for the crypto provider
    const pubKeyBytes = base64urlDecodeToBytes(jwk.x);
    const pubKeyBase64 = bytesToBase64(pubKeyBytes);

    const valid = await cryptoProvider.verify(data, sigBytes, pubKeyBase64);
    return {
      valid,
      reason: valid ? undefined : "Signature verification failed",
    };
  };

  const verifier = new DelegationCredentialVerifier({
    didResolver,
    signatureVerifier,
    statusListResolver: delegationConfig?.statusListResolver,
    cacheTtl: delegationConfig?.verificationCache?.ttlMs,
    maxCacheSize: delegationConfig?.verificationCache?.maxEntries,
  });

  const buildDelegationErrorResponse = (
    error: string,
    reason: string,
  ): Awaited<ReturnType<KyaOsToolHandler>> => ({
    content: [
      {
        type: "text" as const,
        text: JSON.stringify({ error, reason: sanitizeForMessage(reason) }),
      },
    ],
    isError: true,
  });

  const trustedRootIssuers = delegationConfig?.trustedRootIssuers;
  if (trustedRootIssuers === undefined) {
    logger.warn(
      "[kya-os] delegation.trustedRootIssuers is not set, so a delegation from any issuer is " +
        "accepted, including one an agent signs for itself. Set it to the DIDs allowed to grant authority.",
    );
  }

  // Refused at startup: a bad value would otherwise boot cleanly and then deny
  // every delegated call, echoing the config detail back to the caller.
  const maxChainLength = delegationConfig?.maxChainLength;
  if (maxChainLength !== undefined && (!Number.isInteger(maxChainLength) || maxChainLength < 1)) {
    throw new RangeError(
      `[kya-os] delegation.maxChainLength must be a positive integer (got ${String(maxChainLength)})`,
    );
  }

  // Root credentials whose claimed issuerDid is not their signer are accepted
  // for compatibility but reported: each distinct message at most once an hour,
  // with the oldest evicted first so the set stays bounded.
  const reportedChainWarnings = new TtlCache<true>({ ttlMs: 60 * 60 * 1000, maxEntries: 256 });
  const reportChainWarnings = (warnings: readonly string[] | undefined): void => {
    for (const warning of warnings ?? []) {
      if (reportedChainWarnings.get(warning)) continue;
      reportedChainWarnings.set(warning, true);
      logger.warn(`[kya-os] ${sanitizeForMessage(warning)}`);
    }
  };

  const validateDelegationChain = async (
    leafCredential: DelegationCredential,
    options?: { skipSignature?: boolean },
  ): Promise<ChainValidationResult> => {
    const result = await validateDelegationChainCore(
      leafCredential,
      {
        serverDid: identity.did,
        verifier,
        resolveDelegationChain: delegationConfig?.resolveDelegationChain,
        statusListConfigured: !!delegationConfig?.statusListResolver,
        revocationChecker: delegationConfig?.revocationChecker,
        ...(trustedRootIssuers !== undefined ? { trustedRootIssuers } : {}),
        ...(maxChainLength !== undefined ? { maxChainLength } : {}),
      },
      options,
    );
    if (result.valid) reportChainWarnings(result.warnings);
    return result;
  };

  async function verifyDelegation(
    delegationArg: unknown,
  ): Promise<DelegationCheck> {
    // Normalize to a DelegationCredential, authenticating by wire form. A VC-JWT
    // string carries its signature in the compact-JWS ENVELOPE; an object carries
    // an embedded Data-Integrity proof (verified inside validateDelegationChain).
    let vc: DelegationCredential;
    let isJwt = false;
    let jwtExpiresAt: number | undefined;

    if (typeof delegationArg === "string") {
      const parsed = parseVCJWT(delegationArg);
      if (!parsed || !parsed.payload.vc) {
        return { valid: false, reason: "Invalid VC-JWT format" };
      }
      // Envelope-first: verify the JWT signature against the issuer's published
      // key BEFORE the chain runs with skipSignature. Reuses the vetted verifier
      // (EdDSA-pinned compact-JWS + iss/issuer consistency; fail-closed). Status
      // is checked once by the chain walk below, so skip it here.
      const envelope = await verifier.verifyDelegationJwt(delegationArg, {
        skipStatus: true,
      });
      if (!envelope.valid) {
        return {
          valid: false,
          reason: envelope.reason ?? "VC-JWT envelope signature is not valid",
          vc: parsed.payload.vc as DelegationCredential,
        };
      }
      // This exact JWT's optional exp has passed the envelope verifier's live
      // time checks. Preserve its narrower deadline when caching the grant.
      jwtExpiresAt = parsed.payload.exp !== undefined ? parsed.payload.exp * 1000 : undefined;
      vc = parsed.payload.vc as DelegationCredential;
      // A JWT has no embedded `proof`; add a marker so basic validation (which
      // requires proof presence) passes. The already-verified envelope is the
      // real proof, so the chain walk runs with skipSignature (below).
      if (!vc.proof) {
        vc = { ...vc, proof: { type: "JwtProof2020", jwt: delegationArg } };
      }
      isJwt = true;
    } else {
      vc = delegationArg as DelegationCredential;
    }

    // Chain / scope-superset / expiry / status / revocation. skipSignature is
    // true ONLY for a JWT (its envelope, verified above, is the proof); an object
    // keeps it false so validateDelegationChain verifies the embedded proof.
    // That call never throws on normal/malformed input; this backstop catches
    // only a truly unexpected throw (hostile getter/Proxy, provider fault) and
    // returns a GENERIC reason so no internal detail leaks to the client/proof.
    let chain: ChainValidationResult;
    try {
      chain = await validateDelegationChain(vc, { skipSignature: isJwt });
    } catch (error) {
      logger.error("[kya-os] Unexpected error verifying delegation", {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });
      chain = {
        valid: false,
        reason: "Delegation credential could not be verified",
      };
    }

    if (!chain.valid) {
      return {
        valid: false,
        reason: chain.reason ?? "Unknown delegation validation error",
        vc,
      };
    }
    const expiresAt = jwtExpiresAt === undefined
      ? chain.expiresAt
      : Math.min(jwtExpiresAt, chain.expiresAt ?? jwtExpiresAt);
    return {
      valid: true,
      vc,
      isJwt,
      ...(expiresAt !== undefined ? { expiresAt } : {}),
    };
  }

  async function buildNeedsAuthorizationChallenge(
    toolName: string,
    config: DelegationGateConfig,
  ): Promise<{
    challenge: KyaOsToolResult;
    message: string;
  }> {
    const tokenBytes = await cryptoProvider.randomBytes(16);
    const hex = Array.from(tokenBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const resumeToken = [
      hex.slice(0, 8),
      hex.slice(8, 12),
      hex.slice(12, 16),
      hex.slice(16, 20),
      hex.slice(20),
    ].join("-");
    const expiresAt = Math.floor(Date.now() / 1000) + 300;

    const authError = createNeedsAuthorizationError({
      message: `Tool "${toolName}" requires delegation with scope: ${config.scopeId}`,
      authorizationUrl: config.consentUrl,
      resumeToken,
      expiresAt,
      scopes: [config.scopeId],
    });

    // config.formatChallenge lets a server render the challenge (e.g. a markdown
    // link for LLM clients, or an error result with structuredContent) BEFORE
    // it is signed, so the proof binds exactly what the client receives. A
    // throwing hook, or one returning neither form, gets the default challenge.
    const defaultChallenge = (): KyaOsToolResult => ({
      content: [{ type: "text", text: JSON.stringify(authError) }],
    });
    let challenge = defaultChallenge();
    if (config.formatChallenge) {
      try {
        const formatted = toChallengeResult(config.formatChallenge(authError));
        if (formatted) {
          challenge = formatted;
        } else {
          logger.error(
            "[kya-os] formatChallenge returned neither content nor a challenge result; using the default challenge",
            { tool: toolName },
          );
        }
      } catch (error) {
        logger.error("[kya-os] formatChallenge threw; using the default challenge", {
          tool: toolName,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
    return { challenge, message: authError.message };
  }

  return {
    verifyDelegation,
    buildDelegationErrorResponse,
    buildNeedsAuthorizationChallenge,
  };
}
