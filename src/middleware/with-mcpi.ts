/**
 * MCP-I Middleware — Core Implementation
 *
 * Adds identity, session management, and proof generation to MCP servers.
 *
 * For most use cases, prefer the high-level `withMCPI()` adapter from
 * `./with-mcpi-server.ts` which (by default) auto-registers the handshake
 * tool and auto-attaches proofs to all tool responses:
 *
 *   import { withMCPI } from '@mcp-i/core';
 *   await withMCPI(server, { crypto: new NodeCryptoProvider() });
 *
 * `createMCPIMiddleware()` in this file is the lower-level API used
 * internally by `withMCPI()` and for advanced use cases like the
 * low-level `Server` API or custom request handler patterns.
 */

import {
  type CryptoProvider,
  FetchProvider,
} from "../providers/base.js";
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
import { createDidWebResolver } from "../delegation/did-web-resolver.js";
import { verifyDelegationAudience } from "../delegation/audience-validator.js";
import {
  createNeedsAuthorizationError,
  extractDelegationFromVC,
  type DelegationCredential,
  type DelegationRecord,
} from "../types/protocol.js";
import { logger } from "../logging/index.js";
import { MCPI_ERROR_CODES } from "../errors.js";
import { canonicalizeJSON, parseVCJWT } from "../delegation/utils.js";
import { base64urlDecodeToBytes, base64urlEncodeFromBytes, bytesToBase64 } from "../utils/base64.js";

export interface MCPIIdentityConfig {
  did: string;
  kid: string;
  privateKey: string;
  publicKey: string;
  agentName?: string;
}

export const MCPI_ACTIONS = ["handshake", "identity", "reputation"] as const;
type MCPIAction = (typeof MCPI_ACTIONS)[number];

export interface MCPIDelegationConfig {
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
  /**
   * When true, re-delegations (credentials with a `parentId`) MUST include
   * an `audience` constraint binding them to the verifying server's DID.
   *
   * This prevents confused-deputy attacks where a delegated credential is
   * forwarded to an unintended server. Without audience binding, any server
   * that receives the credential will accept it.
   *
   * Recommended for production. See: Alan Karp's transitive access analysis
   * and MCP-I §11.6 (Confused Deputy Attacks).
   *
   * Default is false for backward compatibility.
   */
  requireAudienceOnRedelegation?: boolean;
  /**
   * Compatibility mode for legacy integrations that cannot yet provide
   * full delegation-chain and status-list resolvers.
   *
   * WARNING: Enabling this weakens verification guarantees:
   * - Parent-linked delegations are accepted without chain resolution
   * - credentialStatus is accepted without StatusList checks
   *
   * Default is false (strict security behavior).
   */
  allowLegacyUnsafeDelegation?: boolean;
}

export interface MCPIConfig {
  /** Agent identity (DID + key material) */
  identity: MCPIIdentityConfig;
  /** Session configuration overrides */
  session?: Omit<SessionConfig, "nonceCache">;
  /** Delegation verification overrides */
  delegation?: MCPIDelegationConfig;
  /**
   * When true, automatically creates a session on the first tool call
   * if no session exists. Useful for demos and development where
   * MCP clients don't support the `_mcpi` handshake flow.
   * In production, MCP-I-aware runtimes should execute handshake before tool calls.
   */
  autoSession?: boolean;
}

export interface MCPIToolDefinition {
  name: string;
  description?: string;
  inputSchema: {
    type: "object";
    properties?: Record<string, unknown>;
    required?: string[];
    [key: string]: unknown;
  };
}

export interface MCPIToolHandler<
  T extends Record<string, unknown> = Record<string, unknown>,
> {
  (
    args: T,
    sessionId?: string,
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
export interface MCPIServer {
  setRequestHandler(
    schema: unknown,
    handler: (...args: unknown[]) => unknown,
  ): void;
}

export interface MCPIMiddleware {
  /** The identity config used by this middleware instance */
  identity: MCPIIdentityConfig;

  /** The SessionManager instance for manual session operations */
  sessionManager: SessionManager;

  /** The ProofGenerator instance for manual proof operations */
  proofGenerator: ProofGenerator;

  /**
   * Unified tool definition for `_mcpi`.
   * Include this in your ListToolsRequest handler's tool list.
   */
  mcpiTool: MCPIToolDefinition;

  /**
   * @deprecated Use `mcpiTool` (`_mcpi` with `action: "handshake"`).
   * Tool definition for `_mcpi_handshake`.
   * Include this in your ListToolsRequest handler's tool list.
   */
  handshakeTool: MCPIToolDefinition;

  /**
   * Handle a unified `_mcpi` action. Use this in your CallToolRequest handler
   * when `request.params.name === '_mcpi'`.
   */
  handleMCPI(args: Record<string, unknown>): Promise<{
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  }>;

  /**
   * @deprecated Use `handleMCPI` with `action: "handshake"`.
   * Handle a handshake call. Use this in your CallToolRequest handler
   * when `request.params.name === '_mcpi_handshake'`.
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
    handler: MCPIToolHandler<T>,
  ): MCPIToolHandler;

  /**
   * Wrap a tool handler to require a valid W3C Delegation Credential.
   *
   * Caller must pass the VC as `_mcpi_delegation` in the tool args.
   * - If absent: returns a `needs_authorization` response with the consentUrl.
   * - If present but invalid: returns a structured error with reason.
   * - If valid with correct scope: strips `_mcpi_delegation` and calls the handler.
   */
  wrapWithDelegation(
    toolName: string,
    config: {
      scopeId: string;
      consentUrl: string;
    },
    handler: MCPIToolHandler,
  ): MCPIToolHandler;
}

class RuntimeFetchProvider extends FetchProvider {
  async resolveDID(): Promise<null> {
    return null;
  }

  async fetchStatusList(): Promise<null> {
    return null;
  }

  async fetchDelegationChain(): Promise<DelegationRecord[]> {
    return [];
  }

  async fetch(url: string, options?: unknown): Promise<Response> {
    if (typeof globalThis.fetch !== "function") {
      throw new Error("Global fetch is not available in this runtime");
    }

    return globalThis.fetch(url, options as RequestInit);
  }
}

function getDelegationScopes(credential: DelegationCredential): string[] {
  const scopes = new Set<string>();

  for (const scope of credential.credentialSubject.delegation.scopes ?? []) {
    scopes.add(scope);
  }

  for (const scope of credential.credentialSubject.delegation.constraints.scopes ?? []) {
    scopes.add(scope);
  }

  return Array.from(scopes);
}

function validateScopeAttenuation(
  parentCredential: DelegationCredential,
  childCredential: DelegationCredential,
): { valid: boolean; reason?: string } {
  const parentScopes = getDelegationScopes(parentCredential);
  const childScopes = getDelegationScopes(childCredential);
  const childDelegation = childCredential.credentialSubject.delegation;

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
 * Create MCP-I middleware for a standard MCP SDK Server.
 *
 * For most use cases, prefer {@link withMCPI} from `./with-mcpi-server.ts`
 * which wraps this function and (by default) auto-registers handshake +
 * auto-attaches proofs.
 *
 * Use `createMCPIMiddleware` directly when:
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
export function createMCPIMiddleware(
  config: MCPIConfig,
  cryptoProvider: CryptoProvider,
): MCPIMiddleware {
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

  // Session map: sessionId → last nonce (for proof generation)
  const sessionNonces = new Map<string, string>();

  // Active session tracking — set after handshake (manual or auto)
  let activeSessionId: string | undefined;

  const handshakeTool: MCPIToolDefinition = {
    name: "_mcpi_handshake",
    description:
      "MCP-I identity handshake — establishes a cryptographic session",
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

  const mcpiTool: MCPIToolDefinition = {
    name: "_mcpi",
    description:
      "MCP-I protocol — identity verification, session handshake, and server metadata",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: [...MCPI_ACTIONS],
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
                code: MCPI_ERROR_CODES.handshake_failed,
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
          }),
        },
      ],
    };
  }

  async function handleMCPI(args: Record<string, unknown>): Promise<{
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  }> {
    const action =
      typeof args.action === "string"
        ? (args.action as MCPIAction)
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
                  code: MCPI_ERROR_CODES.runtime_error,
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
                  code: MCPI_ERROR_CODES.invalid_request,
                  message: `Unknown _mcpi action: "${action ?? "(missing)"}". Valid actions: ${MCPI_ACTIONS.join(", ")}`,
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
   * In production, MCP-I-aware runtimes should execute handshake before tool calls.
   * This convenience mode allows non-MCP-I clients (like MCP Inspector) to
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
    handler: MCPIToolHandler<T>,
  ): MCPIToolHandler {
    return async (args: Record<string, unknown>, sessionId?: string) => {
      const result = await handler(args as T, sessionId);

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
        );

        // Attach proof as _meta (rendered by MCP Inspector, invisible to LLMs)
        result._meta = { proof };
      } catch (error) {
        logger.error("[mcpi] Proof generation failed", {
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

  function wrapWithDelegation(
    toolName: string,
    config: { scopeId: string; consentUrl: string },
    handler: MCPIToolHandler,
  ): MCPIToolHandler {
    const legacyUnsafeDelegationEnabled =
      delegationConfig?.allowLegacyUnsafeDelegation === true;
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
    ): Awaited<ReturnType<MCPIToolHandler>> => ({
      content: [
        {
          type: "text" as const,
          text: JSON.stringify({ error, reason }),
        },
      ],
      isError: true,
    });

    const validateDelegationChain = async (
      leafCredential: DelegationCredential,
      options?: { skipSignature?: boolean },
    ): Promise<{ valid: boolean; reason?: string }> => {
      const leafDelegation = extractDelegationFromVC(leafCredential);
      let chain: DelegationCredential[] = [leafCredential];

      if (leafDelegation.parentId) {
        if (!delegationConfig?.resolveDelegationChain) {
          if (legacyUnsafeDelegationEnabled) {
            logger.warn(
              `[mcpi] Legacy delegation mode enabled: accepting parent-linked credential ${leafDelegation.id} without resolveDelegationChain`,
            );
            return { valid: true };
          }
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
          if (legacyUnsafeDelegationEnabled) {
            logger.warn(
              `[mcpi] Legacy delegation mode enabled: skipping status-list verification for ${delegation.id}`,
            );
          } else {
          return {
            valid: false,
            reason: `Delegation ${delegation.id} has credentialStatus but no statusListResolver is configured`,
          };
          }
        }

        const skipStatusForLegacy =
          legacyUnsafeDelegationEnabled &&
          !!credential.credentialStatus &&
          !delegationConfig?.statusListResolver;
        const credentialVerification = await verifier.verifyDelegationCredential(
          credential,
          {
            ...(skipStatusForLegacy ? { skipStatus: true } : {}),
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

        // When requireAudienceOnRedelegation is enabled, every non-root
        // credential in the chain MUST have an audience constraint.
        // This prevents confused-deputy attacks where re-delegated
        // credentials are forwarded to unintended servers.
        if (
          delegationConfig?.requireAudienceOnRedelegation &&
          delegation.parentId &&
          !delegation.constraints.audience
        ) {
          return {
            valid: false,
            reason: `Delegation ${delegation.id} is a re-delegation (parentId: ${delegation.parentId}) but has no audience constraint. Re-delegations must include an audience when requireAudienceOnRedelegation is enabled`,
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
      const delegationArg = args["_mcpi_delegation"];

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

        return {
          content: [{ type: "text", text: JSON.stringify(authError) }],
        };
      }

      // Accept delegation as either a JSON object (embedded proof) or a
      // VC-JWT string (compact JWT). The Cloudflare consent service issues
      // VC-JWTs; examples use embedded proofs. Support both transparently.
      let vc: DelegationCredential;
      let isVCJWT = false;
      if (typeof delegationArg === "string") {
        const parsed = parseVCJWT(delegationArg);
        if (!parsed || !parsed.payload.vc) {
          return buildDelegationErrorResponse(
            MCPI_ERROR_CODES.delegation_invalid,
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

      // For VC-JWTs, skip the embedded proof/signature check — the JWT
      // envelope signature is the proof. Basic checks (schema, expiry,
      // status, scopes) still apply.
      const verificationResult = await validateDelegationChain(vc, {
        skipSignature: isVCJWT,
      });

      if (!verificationResult.valid) {
        logger.warn(
          `[mcpi] Delegation verification failed for "${toolName}": ${verificationResult.reason}`,
        );
        return buildDelegationErrorResponse(
          MCPI_ERROR_CODES.delegation_invalid,
          verificationResult.reason ?? "Unknown delegation validation error",
        );
      }

      const scopes = getDelegationScopes(vc);
      if (!scopes.includes(config.scopeId)) {
        logger.warn(
          `[mcpi] Delegation missing required scope "${config.scopeId}" for "${toolName}"`,
        );
        return buildDelegationErrorResponse(
          MCPI_ERROR_CODES.insufficient_scope,
          `Required scope "${config.scopeId}" not in delegation scopes`,
        );
      }

      // Strip _mcpi_delegation from args before passing to handler
      const cleanArgs: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(args)) {
        if (k !== "_mcpi_delegation") cleanArgs[k] = v;
      }

      logger.debug(
        `[mcpi] Delegation verified for "${toolName}", scope "${config.scopeId}"`,
      );
      return handler(cleanArgs, sessionId);
    };
  }

  return {
    identity: config.identity,
    sessionManager,
    proofGenerator,
    mcpiTool,
    handshakeTool,
    handleMCPI,
    handleHandshake,
    wrapWithProof,
    wrapWithDelegation,
  };
}
