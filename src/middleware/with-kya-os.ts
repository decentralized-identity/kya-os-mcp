/**
 * KYA-OS Middleware — Core Implementation
 *
 * Adds identity, session management, and proof generation to MCP servers.
 *
 * For most use cases, prefer the high-level `withKyaOs()` adapter from
 * `./with-kya-os-server.ts` which (by default) auto-registers the handshake
 * tool and auto-attaches proofs to all tool responses:
 *
 *   import { withKyaOs } from '@kya-os/mcp';
 *   await withKyaOs(server, { crypto: new NodeCryptoProvider() });
 *
 * `createKyaOsMiddleware()` in this file is the lower-level API used
 * internally by `withKyaOs()` and for advanced use cases like the
 * low-level `Server` API or custom request handler patterns.
 */

import {
  type CryptoProvider,
  type FetchProvider,
  type NonceCacheProvider,
} from "../providers/base.js";
import { RuntimeFetchProvider, NoopFetchProvider } from "../providers/runtime-fetch.js";
import { AuditLogProvider, NoopAuditLogProvider } from "../providers/audit-log.js";
import { GrantStore, MemoryGrantStore, type Grant } from "../providers/grant-store.js";
import {
  SessionManager,
  type SessionConfig,
  type HandshakeResult,
} from "../session/manager.js";
import {
  ProofGenerator,
  KYA_OS_PROOF_META_KEY,
  LEGACY_PROOF_META_KEY,
  type ProofAgentIdentity,
  type ToolRequest,
  type ToolResponse,
} from "../proof/generator.js";
import { validateHandshakeFormat } from "../session/manager.js";
import {
  DelegationCredentialVerifier,
  type DIDResolver,
  type SignatureVerificationFunction,
  type StatusListResolver,
} from "../delegation/vc-verifier.js";
import { createDidKeyResolver } from "../delegation/did-key-resolver.js";
import {
  assertHolderBinding,
  isHolderBindingApplicable,
  isKyaOsControlArg,
  toHolderBindingRequest,
} from "../delegation/holder-binding.js";
import { ProofVerifier } from "../proof/verifier.js";
import { SystemClockProvider } from "../providers/system-clock.js";
import { MemoryNonceCacheProvider } from "../providers/memory.js";
import { scopeSatisfies } from "../delegation/scope-matcher.js";
import { createDidWebResolver } from "../delegation/did-web-resolver.js";
import {
  buildDidResolverRegistry,
  type DIDResolverRegistry,
} from "../delegation/did-resolver-registry.js";
import { getDidMethod } from "../utils/did-helpers.js";
import {
  validateDelegationChain as validateDelegationChainCore,
  getDelegationScopes,
  type RevocationChecker,
} from "../delegation/chain-enforcement.js";
import {
  createNeedsAuthorizationError,
  type DelegationCredential,
  type DetachedProof,
  type NeedsAuthorizationError,
} from "../types/protocol.js";
import { logger } from "../logging/index.js";
import { KYA_OS_ERROR_CODES } from "../errors.js";
import { canonicalizeJSON, parseVCJWT } from "../delegation/utils.js";
import { base64urlDecodeToBytes, base64urlEncodeFromBytes, bytesToBase64 } from "../utils/base64.js";
import { sanitizeForMessage } from "./with-kya-os.helpers.js";
import {
  KYA_OS_ACTIONS,
  type KyaOsAction,
  type KyaOsConfig,
  type KyaOsToolHandler,
  type KyaOsToolDefinition,
  type KyaOsCallContext,
  type KyaOsMiddleware,
  type PolicyGateOptions,
} from "./with-kya-os.types.js";
import type { MiddlewareDeps } from "./with-kya-os.deps.js";
import { createGrantResolution } from "./with-kya-os.grants.js";
import { createPolicyGate } from "./with-kya-os.policy-gate.js";

// The public type surface lives in `./with-kya-os.types.ts`; re-export it here so
// `import { KyaOsConfig, ... } from './with-kya-os'` continues to resolve unchanged.
export * from "./with-kya-os.types.js";

/**
 * Create KYA-OS middleware for a standard MCP SDK Server.
 *
 * For most use cases, prefer {@link withKyaOs} from `./with-kya-os-server.ts`
 * which wraps this function and (by default) auto-registers handshake +
 * auto-attaches proofs.
 *
 * Use `createKyaOsMiddleware` directly when:
 * - You use the low-level `Server` API (not `McpServer`)
 * - You need custom request handler patterns
 * - You want per-tool control over proof/delegation wrapping
 *
 * @param config - Agent identity and session configuration
 * @param cryptoProvider - Platform-specific crypto implementation
 * @returns Middleware components for session management and proof generation
 *
 * @remarks
 * **Session resolution**: proof generation resolves the session from the explicit
 * `sessionId` threaded into each wrapper. A single-process `activeSessionId`
 * fallback (the established handshake/auto session) is consulted ONLY when no
 * sessionId was threaded — e.g. non-KYA-OS clients (MCP Inspector) and the
 * transport auto-proof path; a KYA-OS-aware call never depends on it. By default
 * sessions live in an in-memory Map; for multi-instance deployments inject a
 * durable `SessionStore` via `config.session.sessionStore`.
 */

export function createKyaOsMiddleware(
  config: KyaOsConfig,
  cryptoProvider: CryptoProvider,
): KyaOsMiddleware {
  const identity: ProofAgentIdentity = {
    did: config.identity.did,
    kid: config.identity.kid,
    privateKey: config.identity.privateKey,
    publicKey: config.identity.publicKey,
  };

  // One replay-protection store, shared by the handshake and holder binding.
  // Defaults to in-memory; SessionManager.cleanup() drives its expiry sweep.
  const nonceCache = config.nonceCache ?? new MemoryNonceCacheProvider();

  const sessionManager = new SessionManager(cryptoProvider, {
    ...config.session,
    serverDid: identity.did,
    nonceCache,
  });

  const proofGenerator = new ProofGenerator(identity, cryptoProvider);
  const delegationConfig = config.delegation;
  const auditLog = config.auditLog ?? new NoopAuditLogProvider();

  // Emit the proof under the legacy bare key as well, by default, for pre-1.1
  // back-compat. The value is identical under both keys and `_meta` is never
  // hashed (§7.6), so the mirror is purely additive.
  const emitLegacyProofKey = config.emitLegacyProofKey ?? true;

  /**
   * Place a detached proof into a `_meta` object: always under the namespaced
   * key, and (when {@link emitLegacyProofKey}) mirrored under the legacy bare
   * key. The single place both emit paths build `_meta`, so they cannot drift.
   */
  const withProofMeta = (
    base: Record<string, unknown>,
    proof: DetachedProof,
  ): Record<string, unknown> => ({
    ...base,
    [KYA_OS_PROOF_META_KEY]: proof,
    ...(emitLegacyProofKey ? { [LEGACY_PROOF_META_KEY]: proof } : {}),
  });

  // Durable grant store for the no-paste retry. Defaults to in-memory; inject a
  // shared, durable store for multi-instance / restart survival (mirrors the
  // nonceCache precedent and its production warning).
  const grantStore = config.grantStore ?? new MemoryGrantStore();
  if (!config.grantStore) {
    logger.warn(
      "[kya-os] Using MemoryGrantStore — grants are lost on restart and not " +
        "shared across instances. Inject a Redis / Durable Object / DB-backed " +
        "GrantStore via config.grantStore for production / multi-instance use.",
    );
  }

  // Holder binding (spec §11.8). Built once so all tools share one replay cache.
  // The verifier derives the subject key from the did:key DID directly, so its
  // fetchProvider is unused on the phase-1 path — a never-called stub keeps
  // enforcement active even where a runtime fetch is absent.
  const holderBindingMode = delegationConfig?.holderBinding ?? "off";
  const holderBindingVerifier =
    holderBindingMode === "off"
      ? undefined
      : new ProofVerifier({
          cryptoProvider,
          clockProvider: new SystemClockProvider(),
          nonceCacheProvider: nonceCache,
          fetchProvider:
            delegationConfig?.fetchProvider ??
            (typeof globalThis.fetch === "function"
              ? new RuntimeFetchProvider()
              : new NoopFetchProvider()),
        });

  // The constructed collaborators, threaded into each sub-factory.
  const deps: MiddlewareDeps = {
    identity,
    config,
    cryptoProvider,
    sessionManager,
    proofGenerator,
    auditLog,
    grantStore,
    delegationConfig,
    holderBindingMode,
    holderBindingVerifier,
    emitLegacyProofKey,
  };

  // Durable-grant resolution (the no-paste retry). Depends only on the immutable
  // deps above, so it lifts out cleanly with no shared session state.
  const { resolveExistingGrant, bindGrantOnSuccess } =
    createGrantResolution(deps);

  // Single-process fallback for the established (handshake or auto) session, used
  // ONLY when no sessionId was threaded into the wrapper — e.g. non-KYA-OS clients
  // (MCP Inspector) and the transport auto-proof path, which never thread one. The
  // PRIMARY resolver is the explicit `sessionId` parameter, so a KYA-OS-aware call
  // never depends on this fallback. The per-session proof nonce lives on the
  // session record (`session.nonce`), so no separate nonce map is needed.
  let activeSessionId: string | undefined;

  const handshakeTool: KyaOsToolDefinition = {
    name: "_kyaos_handshake",
    description:
      "KYA-OS identity handshake — establishes a cryptographic session",
    inputSchema: {
      type: "object",
      properties: {
        nonce: { type: "string", description: "Client-generated unique nonce" },
        audience: {
          type: "string",
          description: "Intended audience (server DID or URL)",
        },
        timestamp: { type: "number", description: "Unix epoch seconds" },
        agentDid: {
          type: "string",
          description: "Client agent DID (optional)",
        },
      },
      required: ["nonce", "audience", "timestamp"],
    },
  };

  const kyaOsTool: KyaOsToolDefinition = {
    name: "_kyaos",
    description:
      "KYA-OS protocol — identity verification, session handshake, and server metadata",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: [...KYA_OS_ACTIONS],
          description: "Protocol operation to perform",
        },
        nonce: { type: "string", description: "Client-generated unique nonce" },
        audience: {
          type: "string",
          description: "Intended audience (server DID or URL)",
        },
        timestamp: { type: "number", description: "Unix epoch seconds" },
        agentDid: {
          type: "string",
          description: "Client agent DID (optional)",
        },
      },
      required: ["action"],
    },
  };

  async function handleHandshake(args: Record<string, unknown>): Promise<{
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  }> {
    if (!validateHandshakeFormat(args)) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              success: false,
              error: {
                code: KYA_OS_ERROR_CODES.handshake_failed,
                message:
                  "Invalid handshake format: requires nonce (string), audience (string), and timestamp (positive integer)",
              },
            }),
          },
        ],
        isError: true,
      };
    }

    const result: HandshakeResult =
      await sessionManager.validateHandshake(args);

    // Cache the established session as the single-process fallback for callers
    // that do not thread a sessionId (e.g. the transport auto-proof path).
    if (result.success && result.session) {
      activeSessionId = result.session.sessionId;
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: result.success,
            ...(result.session && {
              sessionId: result.session.sessionId,
              serverDid: identity.did,
              serverKid: identity.kid,
            }),
            ...(result.error && { error: result.error }),
          }),
        },
      ],
      ...(result.error && { isError: true }),
    };
  }

  async function handleIdentity(): Promise<{
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  }> {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            did: identity.did,
            kid: identity.kid,
            name: config.identity.agentName ?? identity.did,
            capabilities: ["handshake", "signing", "verification"],
            protocolVersion: "1.0.0",
            clockSkewSeconds: sessionManager.getStats().config.timestampSkewSeconds,
          }),
        },
      ],
    };
  }

  async function handleKyaOs(args: Record<string, unknown>): Promise<{
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  }> {
    const action =
      typeof args.action === "string"
        ? (args.action as KyaOsAction)
        : undefined;

    switch (action) {
      case "handshake":
        return handleHandshake(args);

      case "identity":
        return handleIdentity();

      case "reputation":
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: false,
                error: {
                  code: KYA_OS_ERROR_CODES.runtime_error,
                  message:
                    'action: "reputation" is not yet implemented.',
                },
              }),
            },
          ],
          isError: true,
        };

      default:
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: false,
                error: {
                  code: KYA_OS_ERROR_CODES.invalid_request,
                  message: `Unknown _kyaos action: "${action ?? "(missing)"}". Valid actions: ${KYA_OS_ACTIONS.join(", ")}`,
                },
              }),
            },
          ],
          isError: true,
        };
    }
  }

  /**
   * Auto-create a session for proof generation when no handshake has occurred.
   * In production, KYA-OS-aware runtimes should execute handshake before tool calls.
   * This convenience mode allows non-KYA-OS clients (like MCP Inspector) to
   * still see proofs without manual handshake.
   *
   * SINGLE-SESSION ONLY: the auto-proof transport path does not thread a
   * sessionId, so it relies on the shared `activeSessionId`. That is only an
   * unambiguous attribution when exactly one session exists. With multiple
   * concurrent sessions and no threaded id, borrowing `activeSessionId` would
   * sign the proof with another client's session/nonce/audience — so this
   * refuses to borrow and returns undefined (the caller skips the proof). The
   * `autoSession` create path is unaffected (it makes the single session).
   */
  async function ensureSession(): Promise<string | undefined> {
    if (activeSessionId) {
      const existing = await sessionManager.getSession(activeSessionId);
      if (existing) {
        if (sessionManager.getStats().activeSessions <= 1) {
          return activeSessionId;
        }
        // Ambiguous: more than one session and none threaded — do NOT borrow.
        logger.warn(
          "[kya-os] Multiple sessions active and no sessionId threaded; skipping " +
            "proof attribution to avoid signing with another client's session. " +
            "Thread the sessionId (the auto-proof path is single-session only).",
        );
        return undefined;
      }
    }

    if (!config.autoSession) return undefined;

    // Generate a server-side session with cryptographically random nonce (SPEC.md §4)
    const nonceBytes = await cryptoProvider.randomBytes(16);
    const nonce = base64urlEncodeFromBytes(nonceBytes);
    const timestamp = Math.floor(Date.now() / 1000);

    const result = await sessionManager.validateHandshake({
      nonce,
      audience: identity.did,
      timestamp,
    });

    if (result.success && result.session) {
      activeSessionId = result.session.sessionId;
      return activeSessionId;
    }

    return undefined;
  }

  function wrapWithProof<T extends Record<string, unknown> = Record<string, unknown>>(
    toolName: string,
    handler: KyaOsToolHandler<T>,
  ): KyaOsToolHandler {
    return async (
      args: Record<string, unknown>,
      sessionId?: string,
      context?: KyaOsCallContext,
    ) => {
      const result = await handler(args as T, sessionId, context);

      if (result.isError) {
        return result;
      }

      // Resolve session: explicit param → active session → auto-create
      const resolvedSessionId = sessionId ?? await ensureSession();
      if (!resolvedSessionId) {
        return result;
      }

      const session = await sessionManager.getSession(resolvedSessionId);
      if (!session) {
        return result;
      }

      try {
        const request: ToolRequest = { method: toolName, params: args };
        const response: ToolResponse = { data: result.content };

        const proof = await proofGenerator.generateProof(
          request,
          response,
          session,
          { scopeId: context?.scopeId },
        );

        // Attach proof under the namespaced _meta key (rendered by MCP
        // Inspector, invisible to LLMs), plus the legacy bare key when enabled.
        // Other _meta keys may coexist (SEP-414).
        result._meta = withProofMeta({}, proof);

        // Hand the verified call to the audit sink. A sink failure MUST NOT
        // break the tool response, so it is logged and swallowed.
        try {
          await auditLog.logAuditRecord({
            identity: { did: identity.did, kid: identity.kid },
            session: { sessionId: session.sessionId, audience: session.audience },
            requestHash: proof.meta.requestHash,
            responseHash: proof.meta.responseHash,
            verified: "yes",
            scopeId: proof.meta.scopeId,
          });
        } catch (auditError) {
          logger.error("[kya-os] Audit log failed", {
            tool: toolName,
            error:
              auditError instanceof Error
                ? auditError.message
                : String(auditError),
          });
        }
      } catch (error) {
        logger.error("[kya-os] Proof generation failed", {
          tool: toolName,
          error: error instanceof Error ? error.message : String(error),
        });
        result._meta = {
          proofError: "Proof generation failed — response is unproven",
        };
      }

      return result;
    };
  }

  /**
   * Attach a signed proof recording an authorization OUTCOME to a response, so
   * rejected or pending privileged attempts leave a verifiable, non-repudiable
   * forensic record (these previously produced no proof). Used for `denied`,
   * `step_up_required`, and `needs_authorization` outcomes.
   *
   * When `responseData` is provided (e.g. the `needs_authorization` challenge
   * content), the proof binds a `responseHash` over it — so the signed proof
   * also attests the response body (notably the consent `authorizationUrl`),
   * letting a verifier detect a tampered/MITM-swapped URL. Pure denials and
   * step-ups pass no `responseData` (there is no response body to bind).
   *
   * Best-effort: if no session can be resolved or proof generation fails, the
   * original response is returned unchanged.
   */
  async function attachOutcomeProof(
    response: Awaited<ReturnType<KyaOsToolHandler>>,
    toolName: string,
    args: Record<string, unknown>,
    sessionId: string | undefined,
    reason: string,
    outcome: "denied" | "step_up_required" | "needs_authorization" = "denied",
    paramsOverride?: Record<string, unknown>,
    responseData?: unknown,
  ): Promise<Awaited<ReturnType<KyaOsToolHandler>>> {
    try {
      const resolvedSessionId = sessionId ?? (await ensureSession());
      if (!resolvedSessionId) return response;
      const session = await sessionManager.getSession(resolvedSessionId);
      if (!session) return response;

      // Prefer the caller's already-stripped args so the signed requestHash
      // matches the needs_approval / resumeToken requestHash exactly.
      let cleanArgs: Record<string, unknown>;
      if (paramsOverride !== undefined) {
        cleanArgs = paramsOverride;
      } else {
        cleanArgs = {};
        for (const [k, v] of Object.entries(args)) {
          if (k !== "_kyaos_delegation") cleanArgs[k] = v;
        }
      }

      const request: ToolRequest = { method: toolName, params: cleanArgs };
      const proofResponse: ToolResponse | undefined =
        responseData !== undefined ? { data: responseData } : undefined;
      const proof = await proofGenerator.generateProof(request, proofResponse, session, {
        outcome,
        reason: sanitizeForMessage(reason),
      });
      response._meta = withProofMeta(
        (response._meta as Record<string, unknown> | undefined) ?? {},
        proof,
      );
    } catch (error) {
      logger.error("[kya-os] Outcome proof generation failed", {
        tool: toolName,
        error: error instanceof Error ? error.message : String(error),
      });
    }
    return response;
  }

  function wrapWithDelegation(
    toolName: string,
    config: {
      scopeId: string;
      consentUrl: string;
      formatChallenge?: (
        challenge: NeedsAuthorizationError,
      ) => Array<{ type: "text"; text: string }>;
    },
    handler: KyaOsToolHandler,
  ): KyaOsToolHandler {
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

      const proofValue = proof["proofValue"] as string | undefined;
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

    // Thin adapter over the framework-agnostic core (E3.1 · chain-enforcement.ts).
    // The walk/attenuation/audience/§11.6/revocation rules live in one place;
    // this binds the host's injected verifier + server DID + resolver + the
    // optional graph-backed RevocationChecker.
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

    return async (
      args: Record<string, unknown>,
      sessionId?: string,
    ) => {
      const delegationArg = args["_kyaos_delegation"];

      if (delegationArg === undefined || delegationArg === null) {
        // No delegation pasted — a durable grant may already authorize this call
        // (the no-paste retry), even on a fresh instance with empty memory.
        // Holder-of-key first (agent-anchored, proof-gated), then the session
        // bearer capability. On a hit, skip the challenge and run the handler
        // with exactly the call shape a verified delegation would have produced.
        const existingGrant = await resolveExistingGrant(
          toolName,
          args,
          sessionId,
          config.scopeId,
        );
        if (existingGrant) {
          const grantArgs: Record<string, unknown> = {};
          for (const [k, v] of Object.entries(args)) {
            if (!isKyaOsControlArg(k)) grantArgs[k] = v;
          }
          logger.debug(
            `[kya-os] Grant resolved for "${toolName}" (scope "${config.scopeId}") — no re-paste required`,
          );
          return handler(grantArgs, sessionId, { scopeId: config.scopeId });
        }

        // No delegation provided — return needs_authorization response
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

        // Sign the challenge (outcome=needs_authorization). The proof binds a
        // responseHash over the EMITTED challenge content — including the
        // authorizationUrl. A verifier that recomputes the response hash over the
        // content it received (ProofVerifier.verifyProof(proof, jwk, { request,
        // response })) thereby detects a tampered/MITM-swapped consent URL; the
        // signature alone proves authenticity, not content-match. config.format-
        // Challenge lets a server render the challenge (e.g. a markdown link for
        // LLM clients) BEFORE signing, so the proof binds exactly what the client
        // receives. A throwing hook falls back to the default challenge (never
        // -32603). Best-effort: attachOutcomeProof no-ops if no session resolves.
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
        return attachOutcomeProof(
          { content: challengeContent },
          toolName,
          args,
          sessionId,
          authError.message,
          "needs_authorization",
          undefined,
          challengeContent,
        );
      }

      // Accept delegation as either a JSON object (embedded proof) or a
      // VC-JWT string (compact JWT). The Cloudflare consent service issues
      // VC-JWTs; examples use embedded proofs. Support both transparently.
      let vc: DelegationCredential;
      let isVCJWT = false;
      if (typeof delegationArg === "string") {
        const parsed = parseVCJWT(delegationArg);
        if (!parsed || !parsed.payload.vc) {
          return attachOutcomeProof(
            buildDelegationErrorResponse(
              KYA_OS_ERROR_CODES.delegation_invalid,
              "Invalid VC-JWT format",
            ),
            toolName,
            args,
            sessionId,
            "Invalid VC-JWT format",
          );
        }
        vc = parsed.payload.vc as DelegationCredential;
        // VC-JWTs don't have an embedded proof — the JWT signature is the
        // proof. Add a marker so basic validation (which checks for proof
        // presence) passes. The actual signature is in the JWT envelope.
        if (!vc.proof) {
          vc = { ...vc, proof: { type: 'JwtProof2020', jwt: delegationArg } };
        }
        isVCJWT = true;
      } else {
        vc = delegationArg as DelegationCredential;
      }

      // For VC-JWTs the embedded-signature check is skipped (the JWT envelope
      // signature is the proof); schema/expiry/status/scope checks still apply.
      // validateDelegationChain performs the shape check and returns
      // { valid, reason } for malformed input, never throwing on normal or
      // structurally-malformed credentials. This try/catch is therefore a PURE
      // BACKSTOP — it fires only on a truly unexpected throw (e.g. a hostile
      // getter/Proxy accessor or a provider fault): it logs the detail
      // server-side and returns a GENERIC reason, so no internal/implementation
      // detail (stack, raw error text) leaks to the client or the signed proof.
      const verificationResult = await (async (): Promise<{
        valid: boolean;
        reason?: string;
      }> => {
        try {
          return await validateDelegationChain(vc, { skipSignature: isVCJWT });
        } catch (error) {
          logger.error("[kya-os] Unexpected error verifying delegation", {
            tool: toolName,
            error: error instanceof Error ? error.message : String(error),
            stack: error instanceof Error ? error.stack : undefined,
          });
          return { valid: false, reason: "Delegation credential could not be verified" };
        }
      })();

      if (!verificationResult.valid) {
        const reason = verificationResult.reason ?? "Unknown delegation validation error";
        logger.warn(
          `[kya-os] Delegation verification failed for "${toolName}": ${sanitizeForMessage(reason)}`,
        );
        return attachOutcomeProof(
          buildDelegationErrorResponse(KYA_OS_ERROR_CODES.delegation_invalid, reason),
          toolName,
          args,
          sessionId,
          reason,
        );
      }

      // Holder binding (spec §11.8): the delegation is valid, but a valid
      // *credential* is a bearer token until we also prove the caller holds the
      // delegation SUBJECT's key. Opt-in via `delegation.holderBinding`. did:key
      // subjects are bound here; did:web is deferred to cnf binding (phase 2) and
      // logged, never rejected. Runs after identity is established, before scope.
      if (holderBindingMode !== "off" && holderBindingVerifier) {
        const subjectDid = vc.credentialSubject?.id;
        if (subjectDid && isHolderBindingApplicable(subjectDid)) {
          const proofArg = args["_kyaos_proof"];
          if (proofArg === undefined) {
            const reason =
              "Holder-of-key proof (_kyaos_proof) is required for this delegation subject";
            logger.warn(
              `[kya-os] Holder binding: "${toolName}" called without _kyaos_proof`,
            );
            if (holderBindingMode === "enforce") {
              return attachOutcomeProof(
                buildDelegationErrorResponse(
                  KYA_OS_ERROR_CODES.holder_binding_failed,
                  reason,
                ),
                toolName,
                args,
                sessionId,
                reason,
              );
            }
          } else {
            let parsedProof: unknown = proofArg;
            if (typeof proofArg === "string") {
              try {
                parsedProof = JSON.parse(proofArg);
              } catch {
                parsedProof = {};
              }
            }
            const binding = await assertHolderBinding({
              proof: parsedProof as DetachedProof,
              subjectDid,
              request: toHolderBindingRequest(toolName, args),
              expectedAudience: identity.did,
              proofVerifier: holderBindingVerifier,
            });
            if (binding.status !== "bound") {
              const reason =
                binding.reason ??
                "Holder-of-key proof did not bind the delegation subject";
              logger.warn(
                `[kya-os] Holder binding ${binding.status} for "${toolName}": ${sanitizeForMessage(reason)}`,
              );
              if (holderBindingMode === "enforce") {
                return attachOutcomeProof(
                  buildDelegationErrorResponse(
                    KYA_OS_ERROR_CODES.holder_binding_failed,
                    reason,
                  ),
                  toolName,
                  args,
                  sessionId,
                  reason,
                );
              }
            }
          }
        } else if (subjectDid) {
          // Non-did:key subject — phase 1 cannot pin its key; defer to cnf
          // binding (phase 2) rather than reject legitimate traffic.
          logger.warn(
            `[kya-os] Holder binding: subject "${subjectDid}" is not did:key; deferring to cnf binding (phase 2)`,
          );
        }
      }

      // Safe to call directly: the structural guard + validateDelegationChain
      // above guarantee a well-formed credential here, and scopeSatisfies is
      // bounded (ReDoS-guarded) and returns rather than throws.
      const scopeResult = scopeSatisfies(config.scopeId, vc);
      if (scopeResult.usedNonExactMatcher) {
        logger.warn(
          `[kya-os] Scope "${config.scopeId}" for "${toolName}" granted via a non-exact ` +
            `(prefix/regex) matcher. Verify this is intended — non-exact matchers widen authority.`,
        );
      }
      if (!scopeResult.satisfied) {
        const reason = `Required scope "${config.scopeId}" not in delegation scopes`;
        logger.warn(
          `[kya-os] Delegation missing required scope "${config.scopeId}" for "${toolName}"`,
        );
        return attachOutcomeProof(
          buildDelegationErrorResponse(KYA_OS_ERROR_CODES.insufficient_scope, reason),
          toolName,
          args,
          sessionId,
          reason,
        );
      }

      // Strip the reserved _kyaos* control namespace before passing to the
      // handler — same predicate the bound request hash uses, so the handler
      // receives exactly the call the subject signed (no smuggled control arg).
      const cleanArgs: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(args)) {
        if (!isKyaOsControlArg(k)) cleanArgs[k] = v;
      }

      // Mint a durable grant from this verified delegation so the next call —
      // on any instance — resolves via resolveExistingGrant with no re-paste.
      await bindGrantOnSuccess(vc, delegationArg, isVCJWT, sessionId, config.scopeId);

      logger.debug(
        `[kya-os] Delegation verified for "${toolName}", scope "${config.scopeId}"`,
      );
      return handler(cleanArgs, sessionId, { scopeId: config.scopeId });
    };
  }

  const { withPolicyGate } = createPolicyGate(deps, { attachOutcomeProof });

  return {
    identity: config.identity,
    sessionManager,
    proofGenerator,
    kyaOsTool,
    handshakeTool,
    handleKyaOs,
    handleHandshake,
    wrapWithProof,
    wrapWithDelegation,
    withPolicyGate,
  };
}
