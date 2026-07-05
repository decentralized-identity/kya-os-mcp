/**
 * KYA-OS Middleware — public type surface.
 *
 * The config, tool, and role interfaces for `createKyaOsMiddleware` / `withKyaOs`,
 * separated from the implementation (`./with-kya-os.ts`) so the ~300-line type
 * surface does not inflate the factory module. Re-exported verbatim from
 * `./with-kya-os.ts`, so every existing `import { KyaOsConfig } from './with-kya-os'`
 * is unchanged.
 */

import type { FetchProvider, NonceCacheProvider } from "../providers/base.js";
import type { AuditLogProvider } from "../providers/audit-log.js";
import type { GrantStore } from "../providers/grant-store.js";
import type { SessionManager, SessionConfig } from "../session/manager.js";
import type { ProofGenerator } from "../proof/generator.js";
import type {
  DIDResolver,
  StatusListResolver,
} from "../delegation/vc-verifier.js";
import type { DIDResolverRegistry } from "../delegation/did-resolver-registry.js";
import type { RevocationChecker } from "../delegation/chain-enforcement.js";
import type {
  DelegationCredential,
  NeedsAuthorizationError,
} from "../types/protocol.js";
import type { PolicyEngine } from "../policy/engine.js";
import type { RiskClassifier } from "../policy/classifier.js";
import type { ApprovalGrant } from "../policy/approval.js";

export interface KyaOsIdentityConfig {
  did: string;
  kid: string;
  privateKey: string;
  publicKey: string;
  agentName?: string;
}

export const KYA_OS_ACTIONS = ["handshake", "identity", "reputation"] as const;
export type KyaOsAction = (typeof KYA_OS_ACTIONS)[number];

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
  /**
   * Durable store for approved authorization grants, enabling the no-paste
   * retry: an agent that already obtained a grant can call again — even on a
   * fresh instance with empty memory, or after a restart — without re-pasting
   * the delegation. Defaults to an in-memory {@link MemoryGrantStore}
   * (single-process only); inject a Redis / Durable Object / DB-backed
   * {@link GrantStore} for multi-instance deployments. Mirrors `nonceCache?`.
   *
   * For the no-paste retry to actually RESOLVE a bound grant, the call must be
   * resolvable: either holder binding is `'enforce'` and the agent presents a
   * per-request `_kyaos_proof` (agent-anchored `getByAgent`), or the client
   * threads its `sessionId` (session-bearer `getBySession`). A grant that would
   * be unresolvable — holder binding `'off'` with no threaded `sessionId` — is
   * NOT bound (it would only orphan a store row); such flows achieve durability
   * by re-presenting the delegation instead.
   */
  grantStore?: GrantStore;
  /**
   * Whether to ALSO emit the detached proof under the legacy bare `_meta.proof`
   * key (in addition to the namespaced `org.kya-os/proof`). The value is
   * identical under both keys and `_meta` is excluded from the response hash
   * (§7.6), so the mirror never affects signatures or verification.
   *
   * Default `true` — a transition aid so pre-1.1 clients that still read bare
   * `proof` keep working. Set `false` once your clients read the namespaced key
   * (the examples do this for a clean single-key Inspector view).
   *
   * Stays ON by default for the whole 1.x line (a pre-1.1 reader of bare
   * `_meta.proof` would otherwise silently get no proof); the legacy mirror is
   * dropped at 2.0.
   */
  emitLegacyProofKey?: boolean;
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

// ── Role interfaces (ISP) ────────────────────────────────────────────────────
// The middleware surface is decomposed into four focused ROLES. Depend on the
// single role you need (e.g. a function that only attaches proofs takes a
// `KyaOsProofAttacher`, not the whole middleware). `KyaOsMiddleware` composes
// them, so the existing flat API (`middleware.wrapWithProof(...)`) is unchanged.

/** Route the unified `_kyaos` protocol action (and the deprecated handshake). */
export interface KyaOsProtocolHandler {
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
}

/** Wrap a tool handler to automatically attach holder-of-key proofs. */
export interface KyaOsProofAttacher {
  /**
   * Wrap a tool handler to automatically generate proofs.
   * Returns a new handler that appends proof metadata to the response.
   */
  wrapWithProof<T extends Record<string, unknown> = Record<string, unknown>>(
    toolName: string,
    handler: KyaOsToolHandler<T>,
  ): KyaOsToolHandler;
}

/** Wrap a tool handler to require a valid W3C Delegation Credential. */
export interface KyaOsDelegationGate {
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
}

/** Wrap a tool handler with a per-action policy / step-up gate. */
export interface KyaOsPolicyGate {
  /**
   * Wrap a tool handler with a per-action policy / step-up gate.
   *
   * Compose after `wrapWithDelegation`. Classifies the action's risk and asks a
   * pluggable PolicyEngine: allow → run handler; deny → signed denial proof;
   * step_up → `needs_approval` until N-of-M signed approval grants (bound to the
   * request hash) are supplied.
   */
  withPolicyGate(
    toolName: string,
    handler: KyaOsToolHandler,
    opts?: PolicyGateOptions,
  ): KyaOsToolHandler;
}

/**
 * The full middleware surface = the exposed components PLUS the four wrapping
 * ROLES ({@link KyaOsProtocolHandler}, {@link KyaOsProofAttacher},
 * {@link KyaOsDelegationGate}, {@link KyaOsPolicyGate}). Prefer depending on a
 * single role where a caller only needs one; this composition keeps the flat API
 * for back-compat while satisfying the Interface Segregation Principle.
 */
export interface KyaOsMiddleware
  extends KyaOsProtocolHandler,
    KyaOsProofAttacher,
    KyaOsDelegationGate {
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

  // Optional so external structural implementers / mocks of KyaOsMiddleware are
  // not broken by this additive method (the KyaOsPolicyGate role requires it).
  withPolicyGate?: KyaOsPolicyGate["withPolicyGate"];
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
