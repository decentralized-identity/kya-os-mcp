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
import { validateDelegationChain as validateDelegationChainCore } from "../delegation/chain-enforcement.js";
import { RuntimeFetchProvider } from "../providers/runtime-fetch.js";
import { canonicalizeJSON } from "../delegation/utils.js";
import { base64urlDecodeToBytes, bytesToBase64 } from "../utils/base64.js";
import {
  createNeedsAuthorizationError,
  readCredentialProofValue,
  type DelegationCredential,
  type NeedsAuthorizationError,
} from "../types/protocol.js";
import { logger } from "../logging/index.js";
import type { KyaOsToolHandler } from "./with-kya-os.types.js";
import type { MiddlewareDeps } from "./with-kya-os.deps.js";
import { sanitizeForMessage } from "./with-kya-os.helpers.js";

/** Per-tool delegation-gate config shared by the gate + its challenge builder. */
export interface DelegationGateConfig {
  scopeId: string;
  consentUrl: string;
  formatChallenge?: (
    challenge: NeedsAuthorizationError,
  ) => Array<{ type: "text"; text: string }>;
}

export interface DelegationVerification {
  /**
   * Thin adapter over the framework-agnostic core (chain-enforcement.ts): binds
   * the host's injected verifier + server DID + resolver + the optional
   * graph-backed RevocationChecker. Returns `{ valid, reason }`, never throws on
   * normal or structurally-malformed credentials.
   */
  validateDelegationChain(
    leafCredential: DelegationCredential,
    options?: { skipSignature?: boolean },
  ): Promise<{ valid: boolean; reason?: string }>;
  /** A structured `{ error, reason }` tool response with a sanitized reason. */
  buildDelegationErrorResponse(
    error: string,
    reason: string,
  ): Awaited<ReturnType<KyaOsToolHandler>>;
  /**
   * Build the signed-later `needs_authorization` challenge for a call that
   * arrived without a delegation or resolvable grant: a fresh resume token, a
   * 5-minute expiry, and the emitted content (respecting `config.formatChallenge`,
   * which falls back to the default JSON challenge if it throws).
   */
  buildNeedsAuthorizationChallenge(
    toolName: string,
    config: DelegationGateConfig,
  ): Promise<{
    challengeContent: Array<{ type: "text"; text: string }>;
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

  const validateDelegationChain = (
    leafCredential: DelegationCredential,
    options?: { skipSignature?: boolean },
  ): Promise<{ valid: boolean; reason?: string }> =>
    validateDelegationChainCore(
      leafCredential,
      {
        serverDid: identity.did,
        verifier,
        resolveDelegationChain: delegationConfig?.resolveDelegationChain,
        statusListConfigured: !!delegationConfig?.statusListResolver,
        revocationChecker: delegationConfig?.revocationChecker,
      },
      options,
    );

  async function buildNeedsAuthorizationChallenge(
    toolName: string,
    config: DelegationGateConfig,
  ): Promise<{
    challengeContent: Array<{ type: "text"; text: string }>;
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
    // link for LLM clients) BEFORE it is signed, so the proof binds exactly what
    // the client receives. A throwing hook falls back to the default challenge.
    const defaultChallengeContent = [
      { type: "text" as const, text: JSON.stringify(authError) },
    ];
    let challengeContent = defaultChallengeContent;
    if (config.formatChallenge) {
      try {
        challengeContent = config.formatChallenge(authError);
      } catch (error) {
        logger.error("[kya-os] formatChallenge threw; using the default challenge", {
          tool: toolName,
          error: error instanceof Error ? error.message : String(error),
        });
        challengeContent = defaultChallengeContent;
      }
    }
    return { challengeContent, message: authError.message };
  }

  return {
    validateDelegationChain,
    buildDelegationErrorResponse,
    buildNeedsAuthorizationChallenge,
  };
}
