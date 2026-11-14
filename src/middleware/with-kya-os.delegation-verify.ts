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
import { dependencyTimeout } from "../utils/deadline.js";
import {
  buildDidResolverRegistry,
} from "../delegation/did-resolver-registry.js";
import { getDidMethod } from "../utils/did-helpers.js";
import {
  DelegationCredentialVerifier,
  type DIDResolver,
} from "../delegation/vc-verifier.js";
import {
  validateDelegationChain as validateDelegationChainCore,
  type ChainValidationResult,
} from "../delegation/chain-enforcement.js";
import { RuntimeFetchProvider } from "../providers/runtime-fetch.js";
import { credentialIssuerDid, credentialIssuerRefusal } from "../delegation/credential-issuer.js";
import { readsVcJwtClaims } from "../delegation/delegation-ref.js";
import { assertTrustedRootIssuers } from "../delegation/root-admission.js";
import { parseVCJWT } from "../delegation/utils.js";
import { embeddedSignatureVerifier } from "../delegation/embedded-signature.js";
import { createDelegationDescriber, type DelegationRecords } from "./with-kya-os.delegation-records.js";
import {
  checkPresentation,
  readOnce,
  UNVERIFIABLE_DELEGATION,
  verifyEnvelope,
  type Authenticated,
  type DelegationCheck,
} from "./with-kya-os.delegation-check.js";
import {
  createNeedsAuthorizationError,
  type DelegationCredential,
} from "../types/protocol.js";
import { logger } from "../logging/index.js";
import { TtlCache } from "../utils/ttl-cache.js";
import { isRecord } from "../utils/guards.js";
import type {
  KyaOsChallengeFormatter,
  KyaOsToolHandler,
  KyaOsToolResult,
} from "./with-kya-os.types.js";
import type { MiddlewareDeps } from "./with-kya-os.deps.js";
import { sanitizeForMessage } from "./with-kya-os.helpers.js";
import { withoutOutcomeMeta } from "./with-kya-os.session.js";
import { isEncodableDelegation, UNENCODABLE_DELEGATION_REASON } from "./with-kya-os.delegation-encoding.js";

/** Per-tool delegation-gate config shared by the gate + its challenge builder. */
export interface DelegationGateConfig {
  scopeId: string;
  consentUrl: string;
  formatChallenge?: KyaOsChallengeFormatter;
}

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

export type { DelegationCheck, DelegationRecords };

/** The JWT a delegation `check` verified arrived as, or `undefined` for one with a Data Integrity proof. */
function arrivedAsJwt(check: { isJwt: boolean }, delegationArg: unknown): string | undefined {
  return check.isJwt ? delegationArg as string : undefined;
}

export interface DelegationVerification {
  /**
   * Authenticate and normalize a presented `_kyaos_delegation`, in either wire
   * form, into a single verified credential. A VC-JWT **string** is verified by
   * its compact-JWS ENVELOPE signature against the issuer's published key; an
   * **object** is verified by its embedded Data-Integrity proof. Both then run
   * the full chain / scope-superset / expiry / status / revocation walk. The
   * chain admits the root by the issuer it names before verifying any
   * signature, and the leaf is always authenticated in its own wire form.
   * Returns a {@link DelegationCheck}, never throws on normal or
   * structurally-malformed input.
   */
  verifyDelegation(delegationArg: unknown): Promise<DelegationCheck>;
  /**
   * {@link verifyDelegation}, for a caller that hands the credential's values on, as the gate and
   * a session grant do: it also refuses a credential holding one that has no RFC 8785 encoding
   * (./with-kya-os.delegation-encoding.ts), with the records of what was presented.
   */
  verifyEncodableDelegation(delegationArg: unknown): Promise<DelegationCheck>;
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

  // Refused at startup, before anything that waits is built.
  const dependencyTimeoutMs = dependencyTimeout(delegationConfig?.dependencyTimeoutMs, "delegation.");
  const didKeyResolver = createDidKeyResolver();
  const fetchProvider =
    delegationConfig?.fetchProvider ??
    (typeof globalThis.fetch === "function"
      ? new RuntimeFetchProvider({ dependencyTimeoutMs })
      : undefined);
  const didWebResolver = fetchProvider
    ? createDidWebResolver(fetchProvider, { dependencyTimeoutMs })
    : undefined;
  const configuredDidResolvers = buildDidResolverRegistry(
    delegationConfig?.didResolvers,
    fetchProvider,
    { dependencyTimeoutMs },
  );
  const didResolver: DIDResolver = {
    async resolve(did: string) {
      // The verifier stops waiting at its deadline, so no further resolver is asked once it has passed.
      const deadline = Date.now() + dependencyTimeoutMs;
      const customResolver = delegationConfig?.didResolver;
      if (customResolver) {
        const resolved = await customResolver.resolve(did);
        if (resolved) {
          return resolved;
        }
      }

      const method = getDidMethod(did);
      const configuredResolver = method && Date.now() < deadline ? configuredDidResolvers[method] : undefined;
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

      if (did.startsWith("did:web:") && Date.now() < deadline) {
        return didWebResolver?.resolve(did) ?? null;
      }

      return null;
    },
  };

  const verifier = new DelegationCredentialVerifier({
    didResolver,
    signatureVerifier: embeddedSignatureVerifier(cryptoProvider),
    statusListResolver: delegationConfig?.statusListResolver,
    cacheTtl: delegationConfig?.verificationCache?.ttlMs,
    maxCacheSize: delegationConfig?.verificationCache?.maxEntries,
    dependencyTimeoutMs,
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
  assertTrustedRootIssuers(trustedRootIssuers, "delegation.");
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

  // A root whose claimed issuerDid is not its signer, and a re-delegation that
  // is wider than its parent (attenuationWarnings), are accepted
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

  const resolveDelegationChain = delegationConfig?.resolveDelegationChain;

  /**
   * The chain walk over one presentation, with what it examined: the
   * ancestors it reached, root first, then the presented credential when it
   * got that far.
   *
   * Each value the resolver returns is read as the presentation is (see
   * {@link readOnce}), in every configuration, as soon as it is returned and
   * before anything else reads it. One that is not read refuses the chain
   * before any of it is verified, and `unreadAncestor` says so.
   */
  const validateDelegationChain = async (
    leafCredential: DelegationCredential,
    jwt?: string,
  ): Promise<{ chain: ChainValidationResult; examined: readonly unknown[]; unreadAncestor?: true }> => {
    let unreadAncestor = false;
    const snapshotAncestor = (ancestor: DelegationCredential): DelegationCredential => {
      const read = readOnce(ancestor);
      if ("copy" in read) return read.copy as DelegationCredential;
      unreadAncestor = true;
      throw new TypeError(`A resolved ancestor ${read.unread}`);
    };
    let envelopeFailure: string | undefined;
    const walked = await validateDelegationChainCore(
      leafCredential,
      {
        serverDid: identity.did,
        verifier: jwt === undefined ? verifier : {
          verifyDelegationCredential: async (credential, options) => {
            if (credential !== leafCredential) {
              return verifier.verifyDelegationCredential(credential, options);
            }
            // The chain has admitted the claimed root. Verify the actual JWT
            // envelope here, including live time and status checks. Never grant
            // a JWT leaf the embedded-proof skipSignature privilege. A refused
            // envelope gives its own reason; a failed status check reads as any
            // credential's does, `Delegation <id> invalid: <reason>`. The
            // envelope is read as the chain digest reads it (see verifyEnvelope).
            const envelope = await verifyEnvelope(verifier, jwt, {});
            if (!envelope.valid && (envelope.stage === "basic" || envelope.stage === "signature")) {
              envelopeFailure = envelope.reason ?? "VC-JWT envelope signature is not valid";
            }
            return envelope;
          },
        },
        ...(resolveDelegationChain !== undefined ? { resolveDelegationChain } : {}),
        snapshotAncestor,
        statusListConfigured: !!delegationConfig?.statusListResolver,
        revocationChecker: delegationConfig?.revocationChecker,
        ...(trustedRootIssuers !== undefined ? { trustedRootIssuers } : {}),
        ...(maxChainLength !== undefined ? { maxChainLength } : {}),
        dependencyTimeoutMs,
      },
    );
    const chain = !walked.valid && envelopeFailure !== undefined ? { ...walked, reason: envelopeFailure } : walked;
    if (chain.valid) reportChainWarnings(chain.warnings);
    return { chain, examined: chain.evaluated ?? [], ...(unreadAncestor ? { unreadAncestor: true as const } : {}) };
  };

  const describer = createDelegationDescriber(deps);
  const verifyDelegation = (delegationArg: unknown): Promise<DelegationCheck> =>
    checkPresentation(delegationArg, authenticate, describer);

  /** Authenticate a presentation, and report what the verdict was reached on. */
  async function authenticate(delegationArg: unknown): Promise<Authenticated> {
    // Normalize to a DelegationCredential, authenticating by wire form. A VC-JWT
    // string carries its signature in the compact-JWS ENVELOPE; an object carries
    // an embedded Data-Integrity proof (verified inside validateDelegationChain).
    let vc: DelegationCredential;
    let isJwt = false;
    let jwtExpirySeconds: unknown;

    if (typeof delegationArg === "string") {
      const parsed = parseVCJWT(delegationArg);
      // parseVCJWT repairs a payload that is not well-formed UTF-8, and SPEC §7.8 does not read
      // one: a VC-JWT acted on here must also show the id it is recorded by.
      if (!parsed?.payload?.vc || !readsVcJwtClaims(delegationArg)) {
        return { verdict: { valid: false, reason: "Invalid VC-JWT format" }, ancestors: [] };
      }
      // Parse only here. The chain must admit the claimed root before any
      // issuer document is resolved, including the JWT leaf's. The verifier
      // authenticates the envelope and checks these time claims in the walk.
      jwtExpirySeconds = parsed.payload.exp;
      vc = parsed.payload.vc as DelegationCredential;
      // Admission reads this claim before the envelope verifier. Preserve the
      // JWT basic-stage diagnostic when it cannot name an issuer at all.
      const issuerFailure = credentialIssuerRefusal(vc);
      if (issuerFailure) return { verdict: { valid: false, reason: issuerFailure, vc }, ancestors: [] };
      // Preserve the normalized credential's proof marker. It is never used as
      // evidence: the leaf verifier receives the original compact JWT below.
      if (!vc.proof) {
        vc = { ...vc, proof: { type: "JwtProof2020", jwt: delegationArg } };
      }
      isJwt = true;
    } else {
      vc = delegationArg as DelegationCredential;
    }

    // Chain / scope-superset / expiry / status / revocation. The leaf's wire
    // form selects its verifier; ancestors always use their embedded proofs.
    // That call never throws on normal/malformed input; this backstop catches
    // only a truly unexpected throw (a provider fault: what is verified is
    // plain data, so nothing in it can throw) and returns a GENERIC reason so
    // no internal detail leaks to the client/proof.
    let chain: ChainValidationResult;
    let examined: readonly unknown[] = [];
    let unreadAncestor: true | undefined;
    try {
      ({ chain, examined, unreadAncestor } = await validateDelegationChain(vc, isJwt ? delegationArg as string : undefined));
    } catch (error) {
      logger.error("[kya-os] Unexpected error verifying delegation", {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });
      chain = {
        valid: false,
        reason: UNVERIFIABLE_DELEGATION,
      };
    }

    // The walk lists what it reached, the presented credential last when it
    // got that far. The records take that credential as it was presented.
    const ancestors = examined.filter((credential) => credential !== vc);
    if (!chain.valid) {
      return {
        verdict: {
          valid: false,
          reason: chain.reason ?? "Unknown delegation validation error",
          vc,
        },
        ancestors,
        ...(unreadAncestor ? { unreadAncestor } : {}),
      };
    }
    // Only use the time claim after the envelope verifier has accepted it as
    // a finite NumericDate. Never coerce attacker-supplied objects to numbers.
    const jwtExpiresAt = typeof jwtExpirySeconds === "number" ? jwtExpirySeconds * 1000 : undefined;
    const expiresAt = jwtExpiresAt === undefined
      ? chain.expiresAt
      : Math.min(jwtExpiresAt, chain.expiresAt ?? jwtExpiresAt);
    // The chain validated, so the walk verified its root's signature under a key of the issuer
    // the root names, and trustedRootIssuers admitted that issuer: the Responsible Party. A root
    // that named none did not validate, so this refusal is never reached and only keeps the type.
    const rootIssuer = credentialIssuerDid(chain.evaluated?.[0] ?? vc);
    if (rootIssuer === undefined) {
      return { verdict: { valid: false, reason: UNVERIFIABLE_DELEGATION, vc }, ancestors };
    }
    return {
      verdict: { valid: true, vc, isJwt, rootIssuer, ...(expiresAt !== undefined ? { expiresAt } : {}) },
      ancestors,
    };
  }

  async function verifyEncodableDelegation(delegationArg: unknown): Promise<DelegationCheck> {
    const check = await verifyDelegation(delegationArg);
    // Decided INSIDE this trust boundary, so a successful check cannot hand the gate a credential
    // holding a value that later throws while being encoded. Never repair signed credential data.
    if (!check.valid || isEncodableDelegation(check.vc, arrivedAsJwt(check, delegationArg))) return check;
    const { evidence, chainEvidence } = check;
    return { valid: false, reason: UNENCODABLE_DELEGATION_REASON, vc: check.vc, evidence, chainEvidence };
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
    verifyEncodableDelegation,
    buildDelegationErrorResponse,
    buildNeedsAuthorizationChallenge,
  };
}
