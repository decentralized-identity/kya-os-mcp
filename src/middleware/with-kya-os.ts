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
} from "../providers/base.js";
import { RuntimeFetchProvider } from "../providers/runtime-fetch.js";
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
import { scopeSatisfies } from "../delegation/scope-matcher.js";
import { createDidWebResolver } from "../delegation/did-web-resolver.js";
import { verifyDelegationAudience } from "../delegation/audience-validator.js";
import {
  createNeedsAuthorizationError,
  createNeedsApprovalError,
  extractDelegationFromVC,
  type DelegationCredential,
  type DelegationRecord,
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
}

export interface KyaOsConfig {
  /** Agent identity (DID + key material) */
  identity: KyaOsIdentityConfig;
  /** Session configuration overrides */
  session?: Omit<SessionConfig, "nonceCache">;
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

function getDelegationScopes(credential: DelegationCredential): string[] {
  const scopes = new Set<string>();

  for (const scope of credential.credentialSubject.delegation.scopes ?? []) {
    scopes.add(scope);
  }

  for (const scope of credential.credentialSubject.delegation.constraints?.scopes ?? []) {
    scopes.add(scope);
  }

  return Array.from(scopes);
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

function validateScopeAttenuation(
  parentCredential: DelegationCredential,
  childCredential: DelegationCredential,
): { valid: boolean; reason?: string } {
  const parentScopes = getDelegationScopes(parentCredential);
  const childScopes = getDelegationScopes(childCredential);
  const childDelegation = childCredential.credentialSubject.delegation;

  // CRISP matcher attenuation: getDelegationScopes does NOT see constraints.crisp.scopes,
  // so a re-delegation could otherwise widen authority by introducing a broad
  // prefix/regex matcher (e.g. resource:"" matches every scope). Require the child's
  // crisp matchers to be a subset of the parent's (by matcher+resource). Fail closed.
  const crispKey = (s: { resource: string; matcher: string }): string => `${s.matcher}\u0000${s.resource}`;
  const parentCrisp = new Set(
    (parentCredential.credentialSubject.delegation.constraints.crisp?.scopes ?? []).map(crispKey),
  );
  const widenedCrisp = (childDelegation.constraints.crisp?.scopes ?? []).filter(
    (s) => !parentCrisp.has(crispKey(s)),
  );
  if (widenedCrisp.length > 0) {
    return {
      valid: false,
      reason: `Delegation ${childDelegation.id} introduces crisp scope matcher(s) absent from parent ${parentCredential.credentialSubject.delegation.id}: ${widenedCrisp
        .map((s) => `${s.matcher}:${s.resource}`)
        .join(", ")}`,
    };
  }

  if (parentScopes.length === 0) {
    return { valid: true };
  }

  if (childScopes.length === 0) {
    return {
      valid: false,
      reason: `Delegation ${childDelegation.id} omits scopes required to prove attenuation from parent ${parentCredential.credentialSubject.delegation.id}`,
    };
  }

  const parentScopeSet = new Set(parentScopes);
  const widenedScopes = childScopes.filter((scope) => !parentScopeSet.has(scope));
  if (widenedScopes.length > 0) {
    return {
      valid: false,
      reason: `Delegation ${childDelegation.id} widens scopes beyond parent ${parentCredential.credentialSubject.delegation.id}: ${widenedScopes.join(", ")}`,
    };
  }

  return { valid: true };
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

  const sessionManager = new SessionManager(cryptoProvider, {
    ...config.session,
    serverDid: identity.did,
  });

  const proofGenerator = new ProofGenerator(identity, cryptoProvider);
  const delegationConfig = config.delegation;
  const auditLog = config.auditLog ?? new NoopAuditLogProvider();

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
    const didResolver: DIDResolver = {
      async resolve(did: string) {
        const customResolver = delegationConfig?.didResolver;
        if (customResolver) {
          const resolved = await customResolver.resolve(did);
          if (resolved) {
            return resolved;
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

    const validateDelegationChain = async (
      leafCredential: DelegationCredential,
      options?: { skipSignature?: boolean },
    ): Promise<{ valid: boolean; reason?: string }> => {
      // Shape guard (validate* never-throw contract): a structurally malformed
      // leaf returns a { valid, reason } result rather than letting
      // extractDelegationFromVC OR the downstream scopeSatisfies check throw.
      // Requires both credentialSubject.delegation AND .constraints (the
      // verifier's own invariant) — the legacy-unsafe path can reach
      // scopeSatisfies, which runs OUTSIDE the wrapper's try/catch backstop, so a
      // constraints-less leaf must be rejected here. A hostile getter/Proxy
      // accessor still throws → caught by the backstop, by design.
      const leafDelegationObj = (
        leafCredential?.credentialSubject as
          | { delegation?: { constraints?: unknown } }
          | undefined
      )?.delegation;
      if (
        !leafDelegationObj ||
        typeof leafDelegationObj !== "object" ||
        !leafDelegationObj.constraints ||
        typeof leafDelegationObj.constraints !== "object"
      ) {
        return {
          valid: false,
          reason:
            "Malformed delegation credential: missing credentialSubject.delegation or its constraints",
        };
      }
      const leafDelegation = extractDelegationFromVC(leafCredential);
      let chain: DelegationCredential[] = [leafCredential];

      if (leafDelegation.parentId) {
        if (!delegationConfig?.resolveDelegationChain) {
          return {
            valid: false,
            reason: `Delegation ${leafDelegation.id} references parent ${leafDelegation.parentId} but no resolveDelegationChain handler is configured`,
          };
        }

        let resolvedChain: DelegationCredential[];
        try {
          resolvedChain =
            await delegationConfig.resolveDelegationChain(leafCredential);
        } catch (error) {
          return {
            valid: false,
            reason: `Failed to resolve delegation chain: ${error instanceof Error ? error.message : "Unknown error"}`,
          };
        }

        if (resolvedChain.length === 0) {
          return {
            valid: false,
            reason: `Delegation ${leafDelegation.id} references parent ${leafDelegation.parentId} but the resolved chain is empty`,
          };
        }

        const leafIndex = resolvedChain.findIndex(
          (credential) =>
            credential.credentialSubject.delegation.id === leafDelegation.id,
        );
        if (leafIndex !== -1 && leafIndex !== resolvedChain.length - 1) {
          return {
            valid: false,
            reason: `Resolved delegation chain for ${leafDelegation.id} must end with the leaf credential`,
          };
        }

        chain =
          leafIndex === -1 ? [...resolvedChain, leafCredential] : resolvedChain;
      }

      const seenIds = new Set<string>();
      let previousDelegation: DelegationRecord | undefined;
      let previousCredential: DelegationCredential | undefined;

      for (const credential of chain) {
        const delegation = extractDelegationFromVC(credential);

        if (seenIds.has(delegation.id)) {
          return {
            valid: false,
            reason: `Delegation chain contains a circular reference at ${delegation.id}`,
          };
        }
        seenIds.add(delegation.id);

        if (credential.credentialStatus && !delegationConfig?.statusListResolver) {
          return {
            valid: false,
            reason: `Delegation ${delegation.id} has credentialStatus but no statusListResolver is configured`,
          };
        }

        const credentialVerification = await verifier.verifyDelegationCredential(
          credential,
          {
            ...(options?.skipSignature ? { skipSignature: true } : {}),
          },
        );
        if (!credentialVerification.valid) {
          return {
            valid: false,
            reason: `Delegation ${delegation.id} invalid: ${credentialVerification.reason}`,
          };
        }

        if (!verifyDelegationAudience(delegation, identity.did)) {
          return {
            valid: false,
            reason: `Delegation ${delegation.id} audience does not include server DID ${identity.did}`,
          };
        }

        // Every non-root credential in the chain MUST carry an `audience`
        // constraint binding it to the verifying server. This closes the
        // confused-deputy class where a re-delegated credential is forwarded
        // to an unintended server (KYA-OS §11.6). Unconditional as of 1.4.0.
        if (delegation.parentId && !delegation.constraints.audience) {
          return {
            valid: false,
            reason: `Delegation ${delegation.id} is a re-delegation (parentId: ${delegation.parentId}) but has no audience constraint. Re-delegations MUST include an audience constraint (KYA-OS §11.6)`,
          };
        }

        if (!previousDelegation || !previousCredential) {
          if (delegation.parentId) {
            return {
              valid: false,
              reason: `Resolved delegation chain is incomplete: root delegation ${delegation.id} still references parent ${delegation.parentId}`,
            };
          }

          previousDelegation = delegation;
          previousCredential = credential;
          continue;
        }

        if (delegation.parentId !== previousDelegation.id) {
          return {
            valid: false,
            reason: `Delegation ${delegation.id} references parent ${delegation.parentId} but expected ${previousDelegation.id}`,
          };
        }

        if (delegation.issuerDid !== previousDelegation.subjectDid) {
          return {
            valid: false,
            reason: `Delegation ${delegation.id} issued by ${delegation.issuerDid} but parent subject is ${previousDelegation.subjectDid}`,
          };
        }

        const scopeValidation = validateScopeAttenuation(
          previousCredential,
          credential,
        );
        if (!scopeValidation.valid) {
          return scopeValidation;
        }

        previousDelegation = delegation;
        previousCredential = credential;
      }

      const finalDelegation = extractDelegationFromVC(chain[chain.length - 1]!);
      if (finalDelegation.id !== leafDelegation.id) {
        return {
          valid: false,
          reason: `Resolved delegation chain ended at ${finalDelegation.id} instead of leaf ${leafDelegation.id}`,
        };
      }

      return { valid: true };
    };

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

      // Strip _kyaos_delegation from args before passing to handler
      const cleanArgs: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(args)) {
        if (k !== "_kyaos_delegation") cleanArgs[k] = v;
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
      const controlKeys = new Set(["_kyaos_delegation", approvalsKey]);
      const cleanArgs: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(args)) {
        if (!controlKeys.has(k)) cleanArgs[k] = v;
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
