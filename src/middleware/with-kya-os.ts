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
import {
  SessionManager,
  type SessionConfig,
  type HandshakeResult,
} from "../session/manager.js";
import {
  ProofGenerator,
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
  createNeedsApprovalError,
  type DelegationCredential,
  type DetachedProof,
  type NeedsAuthorizationError,
} from "../types/protocol.js";
import { logger } from "../logging/index.js";
import { RiskClassifier } from "../policy/classifier.js";
import { DefaultPolicyEngine } from "../policy/default-engine.js";
import { verifyApprovalQuorum, type ApprovalGrant } from "../policy/approval.js";
import type { PolicyEngine } from "../policy/engine.js";
import { buildPolicyRequest } from "../policy/projection.js";
import { KYA_OS_ERROR_CODES } from "../errors.js";
import { canonicalizeJSON, parseVCJWT } from "../delegation/utils.js";
import { base64urlDecodeToBytes, base64urlEncodeFromBytes, bytesToBase64 } from "../utils/base64.js";

export interface KyaOsIdentityConfig {
  did: string;
  kid: string;
  privateKey: string;
  publicKey: string;
  agentName?: string;
}

export const KYA_OS_ACTIONS = ["handshake", "identity", "reputation"] as const;
type KyaOsAction = (typeof KYA_OS_ACTIONS)[number];

export interface KyaOsDelegationConfig {
  /**
   * Optional custom DID resolver. If it returns null, middleware falls back to
   * built-in did:key resolution and fetch-backed did:web resolution.
   */
  didResolver?: DIDResolver;
  /**
   * Optional fetch provider used for did:web resolution.
   * If omitted, middleware falls back to the runtime global fetch when available.
   */
  fetchProvider?: FetchProvider;
  /**
   * Optional DID method resolver registry. Entries are keyed by DID method
   * (for example, "cheqd") and are checked before the built-in did:key and
   * did:web fallback. Factory entries receive the active fetch provider.
   */
  didResolvers?: DIDResolverRegistry;
  /**
   * Resolver for StatusList2021 checks. Credentials with credentialStatus are
   * rejected when no resolver is configured.
   */
  statusListResolver?: StatusListResolver;
  /**
   * Resolve ancestor credentials for a delegated chain. The returned array may
   * contain only ancestors (root -> parent) or the full chain (root -> leaf).
   */
  resolveDelegationChain?: (
    leafCredential: DelegationCredential,
  ) => Promise<DelegationCredential[]>;
  /**
   * Graph-backed ancestor-revocation check. When provided, the chain walk also
   * verifies the leaf is not revoked via a cascade-revoked ANCESTOR — caught
   * independently of how `resolveDelegationChain` hydrated the chain (it walks
   * the delegation graph + StatusList). `CascadingRevocationManager` is the
   * reference adapter. Omit to keep the prior per-credential-status behavior.
   */
  revocationChecker?: RevocationChecker;
  /**
   * Holder-of-key enforcement for inbound calls (spec §11.8). A valid delegation
   * is a *bearer* credential; holder binding additionally requires the caller to
   * present a per-request proof (`_kyaos_proof`) signed by the delegation
   * SUBJECT's key, closing theft-replay for the key-bearing population.
   *
   * - `'off'` (default): no holder-binding check — current behavior, unchanged.
   * - `'warn'`: check and log failures (missing/unbound proof), but still allow.
   * - `'enforce'`: reject calls whose proof is missing or does not bind the
   *   subject. **Breaking for callers that don't yet send `_kyaos_proof`** — opt
   *   in only once your agents mint request proofs.
   *
   * Scope is did:key subjects (the DID encodes the key). did:web and other
   * subjects are deferred to cnf-based binding (phase 2) and logged, never
   * rejected — so enabling `'enforce'` never breaks did:web traffic.
   */
  holderBinding?: "off" | "warn" | "enforce";
}

export interface KyaOsConfig {
  /** Agent identity (DID + key material) */
  identity: KyaOsIdentityConfig;
  /** Session configuration overrides */
  session?: Omit<SessionConfig, "nonceCache">;
  /**
   * Replay-protection store, shared by the session handshake AND inbound holder
   * binding so both draw on one nonce namespace. Defaults to an in-memory store
   * (single-process only); inject a Redis / Durable Object / KV-backed
   * {@link NonceCacheProvider} for multi-instance deployments. Set here, not on
   * `session`, so there is exactly one cache and the two cannot diverge.
   */
  nonceCache?: NonceCacheProvider;
  /** Delegation verification overrides */
  delegation?: KyaOsDelegationConfig;
  /**
   * When true, automatically creates a session on the first tool call
   * if no session exists. Useful for demos and development where
   * MCP clients don't support the `_kyaos` handshake flow.
   * In production, KYA-OS-aware runtimes should execute handshake before tool calls.
   */
  autoSession?: boolean;
  /**
   * Sink for retaining audit records of verified tool calls. Defaults to a
   * no-op; supply an {@link AuditLogProvider} (e.g. a durable, append-only
   * implementation) to capture an audit trail.
   */
  auditLog?: AuditLogProvider;
}

export interface KyaOsToolDefinition {
  name: string;
  description?: string;
  inputSchema: {
    type: "object";
    properties?: Record<string, unknown>;
    required?: string[];
    [key: string]: unknown;
  };
}

/**
 * Per-call context threaded through the middleware wrappers (not part of the
 * tool's public arguments). `wrapWithDelegation` populates `scopeId` so the
 * proof and audit record reflect the scope the call was authorized under.
 */
export interface KyaOsCallContext {
  scopeId?: string;
}

export interface KyaOsToolHandler<
  T extends Record<string, unknown> = Record<string, unknown>,
> {
  (
    args: T,
    sessionId?: string,
    context?: KyaOsCallContext,
  ): Promise<{
    content: Array<{ type: string; text: string; [key: string]: unknown }>;
    isError?: boolean;
    [key: string]: unknown;
  }>;
}

/**
 * Server interface — minimal subset of @modelcontextprotocol/sdk Server.
 * This avoids a hard dependency on the SDK at the type level.
 */
export interface KyaOsServer {
  setRequestHandler(
    schema: unknown,
    handler: (...args: unknown[]) => unknown,
  ): void;
}

export interface KyaOsMiddleware {
  /** The identity config used by this middleware instance */
  identity: KyaOsIdentityConfig;

  /** The SessionManager instance for manual session operations */
  sessionManager: SessionManager;

  /** The ProofGenerator instance for manual proof operations */
  proofGenerator: ProofGenerator;

  /**
   * Unified tool definition for `_kyaos`.
   * Include this in your ListToolsRequest handler's tool list.
   */
  kyaOsTool: KyaOsToolDefinition;

  /**
   * @deprecated Use `kyaOsTool` (`_kyaos` with `action: "handshake"`).
   * Tool definition for `_kyaos_handshake`.
   * Include this in your ListToolsRequest handler's tool list.
   */
  handshakeTool: KyaOsToolDefinition;

  /**
   * Handle a unified `_kyaos` action. Use this in your CallToolRequest handler
   * when `request.params.name === '_kyaos'`.
   */
  handleKyaOs(args: Record<string, unknown>): Promise<{
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  }>;

  /**
   * @deprecated Use `handleKyaOs` with `action: "handshake"`.
   * Handle a handshake call. Use this in your CallToolRequest handler
   * when `request.params.name === '_kyaos_handshake'`.
   */
  handleHandshake(args: Record<string, unknown>): Promise<{
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  }>;

  /**
   * Wrap a tool handler to automatically generate proofs.
   * Returns a new handler that appends proof metadata to the response.
   */
  wrapWithProof<T extends Record<string, unknown> = Record<string, unknown>>(
    toolName: string,
    handler: KyaOsToolHandler<T>,
  ): KyaOsToolHandler;

  /**
   * Wrap a tool handler to require a valid W3C Delegation Credential.
   *
   * Caller must pass the VC as `_kyaos_delegation` in the tool args.
   * - If absent: returns a `needs_authorization` response with the consentUrl.
   * - If present but invalid: returns a structured error with reason.
   * - If valid with correct scope: strips `_kyaos_delegation` and calls the handler.
   */
  wrapWithDelegation(
    toolName: string,
    config: {
      scopeId: string;
      consentUrl: string;
      /**
       * Optional presentation hook for the `needs_authorization` challenge.
       * Given the structured challenge, return the tool-response content to emit
       * (e.g. a markdown "Authorize" link for LLM / chat-style MCP clients that
       * won't parse raw JSON). The signed challenge proof binds a `responseHash`
       * over WHATEVER this returns, so the `authorizationUrl` stays tamper-evident
       * regardless of presentation. Defaults to the structured challenge as JSON.
       */
      formatChallenge?: (
        challenge: NeedsAuthorizationError,
      ) => Array<{ type: "text"; text: string }>;
    },
    handler: KyaOsToolHandler,
  ): KyaOsToolHandler;

  /**
   * Wrap a tool handler with a per-action policy / step-up gate.
   *
   * Compose after `wrapWithDelegation`. Classifies the action's risk and asks a
   * pluggable PolicyEngine: allow → run handler; deny → signed denial proof;
   * step_up → `needs_approval` until N-of-M signed approval grants (bound to the
   * request hash) are supplied.
   */
  // Optional so external structural implementers / mocks of KyaOsMiddleware are
  // not broken by this additive method.
  withPolicyGate?(
    toolName: string,
    handler: KyaOsToolHandler,
    opts?: PolicyGateOptions,
  ): KyaOsToolHandler;
}

/**
 * Strip control characters and cap length on caller-derived values before they
 * are interpolated into client-facing reasons or log lines. A hostile
 * credential could otherwise embed newlines / control chars in an id or scope to
 * forge or corrupt log entries (log injection) or break a terminal. The fixed
 * parts of a reason contain no control chars, so sanitizing the whole assembled
 * string at the emission boundary is equivalent to sanitizing each interpolated
 * value, and is idempotent.
 */
function sanitizeForMessage(value: unknown, maxLen = 256): string {
  const s = typeof value === "string" ? value : String(value);
  // Replace C0/C1 control chars (incl. CR, LF, TAB, ESC, DEL) with U+FFFD so a
  // hostile id/scope cannot forge log lines or break a terminal. Filtered by
  // code point to keep this source ASCII-only (no literal control chars).
  let out = "";
  for (const ch of s) {
    const code = ch.codePointAt(0) ?? 0;
    out += code <= 0x1f || (code >= 0x7f && code <= 0x9f) ? "\uFFFD" : ch;
  }
  return out.length > maxLen ? `${out.slice(0, maxLen)}\u2026` : out;
}

export interface PolicyGateOptions {
  /** Policy decision engine. Defaults to a fail-closed DefaultPolicyEngine. */
  engine?: PolicyEngine;
  /** Risk classifier. Defaults to the built-in RiskClassifier. */
  classifier?: RiskClassifier;
  /** Derive the resource namespace from the tool args (defaults to the tool name). */
  resolveNamespace?: (args: Record<string, unknown>) => string;
  /** Tool-arg key carrying approval grants on resume. Default "_kyaos_approvals". */
  approvalsArgKey?: string;
  /** Verifier for approval-grant signatures (identity-layer). Default: reject all. */
  isValidApprovalSignature?: (grant: ApprovalGrant) => Promise<boolean>;
  /**
   * Whether a prior step already authorized this action's scope/identity.
   *
   * Defaults to FALSE (fail-closed): used standalone, withPolicyGate enforces no
   * scope or identity, so it must NOT be trusted to allow on its own. When you
   * compose it AFTER wrapWithDelegation (the expected usage), pass
   * `scopeMatched: true` to signal that the delegated scope was already verified.
   * Note: principal facts are projected from the (unverified) `_kyaos_delegation`
   * arg on a best-effort basis and must not be treated as authenticated unless
   * wrapWithDelegation ran first.
   */
  scopeMatched?: boolean;
}

/** Best-effort projection of a delegation VC into policy principal facts. */
function extractPolicyPrincipal(del: unknown): {
  agentDid: string;
  responsibleParty?: string;
  delegatedScopes: string[];
} {
  if (!del || typeof del !== "object") {
    return { agentDid: "unknown", delegatedScopes: [] };
  }
  try {
    const vc = del as DelegationCredential;
    const subject = vc.credentialSubject as unknown as {
      id?: string;
      delegation?: { subjectDid?: string; controller?: string };
    };
    const agentDid = subject?.delegation?.subjectDid ?? subject?.id ?? "unknown";
    const responsibleParty = subject?.delegation?.controller;
    let delegatedScopes: string[] = [];
    try {
      delegatedScopes = getDelegationScopes(vc);
    } catch {
      delegatedScopes = [];
    }
    return {
      agentDid,
      ...(responsibleParty ? { responsibleParty } : {}),
      delegatedScopes,
    };
  } catch {
    return { agentDid: "unknown", delegatedScopes: [] };
  }
}

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
 * **Single-process only**: This middleware stores session state in memory using closure
 * variables (`activeSessionId`, `sessionNonces`). It is NOT suitable for multi-instance
 * deployments behind a load balancer. For distributed deployments, implement a custom
 * `SessionStore` backed by Redis, DynamoDB, or similar and pass it via `config.session`.
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

  // Session map: sessionId → last nonce (for proof generation)
  const sessionNonces = new Map<string, string>();

  // Active session tracking — set after handshake (manual or auto)
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

    if (result.success && result.session) {
      sessionNonces.set(result.session.sessionId, result.session.nonce);
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
   */
  async function ensureSession(): Promise<string | undefined> {
    if (activeSessionId) {
      const existing = await sessionManager.getSession(activeSessionId);
      if (existing) return activeSessionId;
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
      sessionNonces.set(result.session.sessionId, result.session.nonce);
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

        // Attach proof as _meta (rendered by MCP Inspector, invisible to LLMs)
        result._meta = { proof };

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
      response._meta = { ...(response._meta ?? {}), proof };
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

      logger.debug(
        `[kya-os] Delegation verified for "${toolName}", scope "${config.scopeId}"`,
      );
      return handler(cleanArgs, sessionId, { scopeId: config.scopeId });
    };
  }

  const defaultRiskClassifier = new RiskClassifier();
  const defaultPolicyEngine: PolicyEngine = new DefaultPolicyEngine();

  /**
   * Per-action policy / step-up gate. Composed AFTER wrapWithDelegation (which
   * enforces identity + scope); this wrapper adds the PROPORTIONALITY layer:
   * classify the action's risk, ask a pluggable PolicyEngine, and either allow,
   * deny (with a signed denial proof), or require N-of-M human approval
   * (needs_approval) before the handler runs. It forces a decision point — it
   * does not itself supply judgment.
   */
  function withPolicyGate(
    toolName: string,
    handler: KyaOsToolHandler,
    opts: PolicyGateOptions = {},
  ): KyaOsToolHandler {
    const engine = opts.engine ?? defaultPolicyEngine;
    const classifier = opts.classifier ?? defaultRiskClassifier;
    const approvalsKey = opts.approvalsArgKey ?? "_kyaos_approvals";
    const isValidApprovalSignature =
      opts.isValidApprovalSignature ?? (async () => false);

    return async (args: Record<string, unknown>, sessionId?: string) => {
      // Drop the reserved _kyaos* namespace plus the (possibly custom) approvals
      // key, so no control arg reaches the handler.
      const cleanArgs: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(args)) {
        if (!isKyaOsControlArg(k) && k !== approvalsKey) cleanArgs[k] = v;
      }

      const namespace = opts.resolveNamespace?.(args) ?? toolName;
      const risk = classifier.classify({ toolName, namespace });
      const principal = extractPolicyPrincipal(args["_kyaos_delegation"]);

      const policyRequest = buildPolicyRequest({
        principal: {
          agentDid: principal.agentDid,
          ...(principal.responsibleParty
            ? { responsibleParty: principal.responsibleParty }
            : {}),
        },
        action: { toolName },
        resource: { namespace },
        delegatedScopes: principal.delegatedScopes,
        scopeMatched: opts.scopeMatched ?? false,
        risk,
      });

      const decision = await engine.evaluate(policyRequest);

      if (decision.decision === "allow") {
        return handler(cleanArgs, sessionId);
      }

      if (decision.decision === "deny") {
        const denied: Awaited<ReturnType<KyaOsToolHandler>> = {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: KYA_OS_ERROR_CODES.policy_denied,
                reason: sanitizeForMessage(decision.reason),
              }),
            },
          ],
          isError: true,
        };
        return attachOutcomeProof(
          denied,
          toolName,
          args,
          sessionId,
          decision.reason,
          "denied",
          cleanArgs,
        );
      }

      // step_up: verify any supplied approval grants, bound to this exact action.
      const requestHash = await proofGenerator.hashRequest({
        method: toolName,
        params: cleanArgs,
      });
      const grants = Array.isArray(args[approvalsKey])
        ? (args[approvalsKey] as ApprovalGrant[])
        : [];
      const quorumResult = await verifyApprovalQuorum(
        grants,
        requestHash,
        decision.quorum,
        isValidApprovalSignature,
      );
      if (quorumResult.satisfied) {
        return handler(cleanArgs, sessionId);
      }

      const needsApproval = createNeedsApprovalError({
        message: `Tool "${toolName}" requires ${decision.quorum.n}-of-N approval before it may proceed (${sanitizeForMessage(decision.reason)}).`,
        resumeToken: `step_up:${requestHash}`,
        expiresAt: Math.floor(Date.now() / 1000) + 300,
        requestHash,
        quorum: decision.quorum,
      });
      const stepUp: Awaited<ReturnType<KyaOsToolHandler>> = {
        content: [{ type: "text", text: JSON.stringify(needsApproval) }],
        isError: true,
      };
      return attachOutcomeProof(
        stepUp,
        toolName,
        args,
        sessionId,
        decision.reason,
        "step_up_required",
        cleanArgs,
      );
    };
  }

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
