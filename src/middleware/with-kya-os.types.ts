/**
 * KYA-OS Middleware — public API-surface types.
 *
 * The tool, call-context, and role interfaces for `createKyaOsMiddleware` /
 * `withKyaOs`, separated from the implementation (`./with-kya-os.ts`). The
 * configuration INPUT types live in `./with-kya-os.config-types.ts` and are
 * re-exported below, so every existing `import { KyaOsConfig } from './with-kya-os'`
 * is unchanged.
 */

import type { SessionManager } from "../session/manager.js";
import type { ProofGenerator } from "../proof/generator.js";
import type { NeedsAuthorizationError } from "../types/protocol.js";
import type { PolicyEngine } from "../policy/engine.js";
import type { RiskClassifier } from "../policy/classifier.js";
import type { ApprovalGrant } from "../policy/approval.js";
import type { KyaOsIdentityConfig } from "./with-kya-os.config-types.js";
import type { AuthorizationEvidence, PartyRef } from "../audit/types.js";

// The configuration input types (KyaOsConfig, KyaOsDelegationConfig, …) live in
// ./with-kya-os.config-types.ts; re-export them so importers are unchanged.
export * from "./with-kya-os.config-types.js";

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
  actor?: PartyRef;
  responsibleParty?: PartyRef;
  authorization?: AuthorizationEvidence;
  correlationId?: string;
  causationId?: string;
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
