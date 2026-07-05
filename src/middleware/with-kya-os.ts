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

import { type CryptoProvider } from "../providers/base.js";
import { RuntimeFetchProvider, NoopFetchProvider } from "../providers/runtime-fetch.js";
import { NoopAuditLogProvider } from "../providers/audit-log.js";
import { GrantStore, MemoryGrantStore } from "../providers/grant-store.js";
import {
  SessionManager,
  validateHandshakeFormat,
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
import { ProofVerifier } from "../proof/verifier.js";
import { SystemClockProvider } from "../providers/system-clock.js";
import { MemoryNonceCacheProvider } from "../providers/memory.js";
import type { DetachedProof } from "../types/protocol.js";
import { logger } from "../logging/index.js";
import { KYA_OS_ERROR_CODES } from "../errors.js";
import { base64urlEncodeFromBytes } from "../utils/base64.js";
import { sanitizeForMessage } from "./with-kya-os.helpers.js";
import {
  KYA_OS_ACTIONS,
  type KyaOsAction,
  type KyaOsConfig,
  type KyaOsToolHandler,
  type KyaOsToolDefinition,
  type KyaOsCallContext,
  type KyaOsMiddleware,
} from "./with-kya-os.types.js";
import type { MiddlewareDeps } from "./with-kya-os.deps.js";
import { createGrantResolution } from "./with-kya-os.grants.js";
import { createPolicyGate } from "./with-kya-os.policy-gate.js";
import { createDelegationGate } from "./with-kya-os.delegation-gate.js";

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

  const { wrapWithDelegation } = createDelegationGate(deps, {
    attachOutcomeProof,
    resolveExistingGrant,
    bindGrantOnSuccess,
  });

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
