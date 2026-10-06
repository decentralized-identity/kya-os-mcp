/**
 * McpServer Adapter for KYA-OS
 *
 * Adds KYA-OS identity, session management, and proof generation to a
 * standard McpServer instance with a single function call.
 *
 * Usage:
 *   import { withKyaOs } from '@kya-os/mcp/middleware';
 *   const kyaos = await withKyaOs(server, { crypto: new NodeCryptoProvider() });
 *   // All tools registered on `server` now get proofs automatically.
 *   await server.connect(transport); // transport is transparently wrapped
 */

import type { CryptoProvider, NonceCacheProvider } from "../providers/base.js";
import type { GrantStore } from "../providers/grant-store.js";
import type { AuditLogProvider } from "../providers/audit-log.js";
import type { KyaOsAuditTrail } from "./with-kya-os.config-types.js";
import type { SessionConfig } from "../session/manager.js";
import type { ResponseProofProfile } from "../types/protocol.js";
import { generateDidKeyFromBase64, didKeyFragment } from "../utils/did-helpers.js";
import {
  KYA_OS_ACTIONS,
  createKyaOsMiddleware,
  type KyaOsIdentityConfig,
  type KyaOsDelegationConfig,
  type KyaOsMiddleware,
} from "./with-kya-os.js";
import { createKyaOsTransport, type Transport } from "./kya-os-transport.js";
import { logger } from "../logging/index.js";
import { z } from "zod";

export interface WithKyaOsOptions {
  /** Platform-specific crypto implementation (required) */
  crypto: CryptoProvider;
  /** Identity config — auto-generated if omitted */
  identity?: KyaOsIdentityConfig;
  /**
   * Session configuration. Accepts the full {@link SessionConfig} (minus the
   * `nonceCache`, which is set by the top-level {@link nonceCache} option), so
   * an optional durable `sessionStore` can be injected for cross-instance
   * session continuity.
   */
  session?: Omit<SessionConfig, "nonceCache">;
  /**
   * Replay-protection store shared by the session handshake and holder
   * binding. Defaults to an in-memory store, which protects one process only;
   * a multi-replica deployment MUST inject a shared store with an atomic
   * `consume()`. Passed through to the middleware (see `KyaOsConfig.nonceCache`).
   */
  nonceCache?: NonceCacheProvider;
  /**
   * Refuse a `nonceCache` without an atomic `consume()` instead of warning
   * once. Passed through to the middleware (see `KyaOsConfig.requireAtomicNonce`).
   */
  requireAtomicNonce?: boolean;
  /**
   * Response-proof profile for every proof this server mints (SPEC §7.3).
   * Defaults to the body profile; the envelope profile also binds
   * `structuredContent` and `isError`. Passed through to the middleware (see
   * `KyaOsConfig.responseProofProfile`).
   */
  responseProofProfile?: ResponseProofProfile;
  /** Auto-create sessions for non-KYA-OS clients (default: true) */
  autoSession?: boolean;
  /** Attach proofs to all tool responses (default: true) */
  proofAllTools?: boolean;
  /**
   * Also emit the proof under the legacy bare `_meta.proof` key (default: true),
   * in addition to the namespaced `org.kya-os/proof`. Set `false` for a clean
   * single-key view once clients read the namespaced key. Passed through to the
   * middleware.
   */
  emitLegacyProofKey?: boolean;
  /** Tools to skip proof generation for */
  excludeTools?: string[];
  /** Delegation verification config */
  delegation?: KyaOsDelegationConfig;
  /**
   * Durable store for approved grants, enabling the no-paste retry across
   * instances / restarts. Defaults to in-memory; inject a durable
   * {@link GrantStore} for production. Passed through to the middleware.
   */
  grantStore?: GrantStore;
  /** Verifiable audit trail service, or false to explicitly disable auditing. */
  audit?: KyaOsAuditTrail | false;
  /** @deprecated Use `audit`; this sink provides legacy capture only. */
  auditLog?: AuditLogProvider;
  /**
   * How the KYA-OS protocol tool is exposed on the server.
   * - "tool" (default): auto-register `_kyaos`
   * - "none": do not register KYA-OS tool (use middleware APIs for custom runtime hooks)
   */
  handshakeExposure?: "tool" | "none";
}

/**
 * Generate a fresh Ed25519 identity for KYA-OS.
 *
 * @param crypto - Platform-specific crypto provider
 * @returns Identity config with DID, kid, and key material
 */
export async function generateIdentity(
  crypto: CryptoProvider,
): Promise<KyaOsIdentityConfig> {
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  return {
    did,
    kid: `${did}#${didKeyFragment(did)}`,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
  };
}

/**
 * Minimal McpServer interface — avoids hard dependency on @modelcontextprotocol/sdk.
 * Matches the subset of McpServer's public API that withKyaOs() uses.
 */
interface McpServerLike {
  connect(transport: Transport): Promise<unknown>;
  registerTool(...args: unknown[]): void;
  /** `McpServer.isConnected()`; SDK releases before 1.10 do not have it. */
  isConnected?(): boolean;
  /** The low-level SDK server, whose `transport` is set while it is connected. */
  server?: { transport?: unknown };
}

/**
 * Whether `server` is already connected to a transport. Prefers
 * `isConnected()` and falls back to the low-level server's `transport` on
 * SDKs that predate it.
 */
function isAlreadyConnected(server: McpServerLike): boolean {
  if (typeof server.isConnected === "function") {
    return server.isConnected();
  }
  return server.server?.transport !== undefined;
}

/**
 * Add KYA-OS to a McpServer instance.
 *
 * 1. Auto-generates Ed25519 identity (or uses provided one)
 * 2. Registers `_kyaos` tool by default (`handshakeExposure: "tool"`)
 * 3. Patches `server.connect()` to transparently wrap the transport with
 *    KyaOsTransport, which injects detached proofs into all `tools/call`
 *    responses using only the public Transport interface.
 *
 * The user-facing API is unchanged — register tools before or after this
 * call, then connect as normal:
 *
 * ```ts
 * const kyaos = await withKyaOs(server, { crypto: new NodeCryptoProvider() });
 * await server.connect(transport); // KyaOsTransport wraps silently
 * ```
 *
 * Call it before `server.connect()`. On a server that is already connected it
 * logs a warning, because the live transport is never wrapped and its
 * responses carry no proofs.
 *
 * @param server  - McpServer instance
 * @param options - Configuration
 * @returns The KyaOsMiddleware instance for advanced usage (wrapWithDelegation, etc.)
 */
export async function withKyaOs(
  server: McpServerLike,
  options: WithKyaOsOptions,
): Promise<KyaOsMiddleware> {
  if (isAlreadyConnected(server)) {
    logger.warn(
      "[kya-os] withKyaOs() was called on a server that is already connected. " +
        "Proofs will not be injected on the existing connection, because withKyaOs() " +
        "wraps the transport inside server.connect(). Call withKyaOs() before server.connect().",
    );
  }

  const identity =
    options.identity ?? (await generateIdentity(options.crypto));

  const kyaos = createKyaOsMiddleware(
    {
      identity,
      session: options.session,
      delegation: options.delegation,
      autoSession: options.autoSession ?? true,
      ...(options.audit !== undefined ? { audit: options.audit } : {}),
      ...(options.auditLog !== undefined ? { auditLog: options.auditLog } : {}),
      ...(options.grantStore ? { grantStore: options.grantStore } : {}),
      ...(options.emitLegacyProofKey !== undefined
        ? { emitLegacyProofKey: options.emitLegacyProofKey }
        : {}),
      ...(options.nonceCache !== undefined ? { nonceCache: options.nonceCache } : {}),
      ...(options.requireAtomicNonce !== undefined
        ? { requireAtomicNonce: options.requireAtomicNonce }
        : {}),
      ...(options.responseProofProfile !== undefined
        ? { responseProofProfile: options.responseProofProfile }
        : {}),
    },
    options.crypto,
  );

  if ((options.handshakeExposure ?? "tool") === "tool") {
    // Register the unified _kyaos tool for protocol operations.
    server.registerTool(
      "_kyaos",
      {
        description:
          "KYA-OS protocol — identity verification, session handshake, and server metadata",
        annotations: { title: "KYA-OS Protocol", readOnlyHint: true },
        inputSchema: {
          action: z
            .enum(KYA_OS_ACTIONS)
            .describe("Protocol operation to perform"),
          nonce: z
            .string()
            .optional()
            .describe("Client-generated unique nonce (handshake)"),
          audience: z
            .string()
            .optional()
            .describe("Intended audience (handshake)"),
          timestamp: z
            .number()
            .optional()
            .describe("Unix epoch seconds (handshake)"),
          agentDid: z
            .string()
            .optional()
            .describe("Client agent DID (handshake, optional)"),
        },
      },
      async (args: unknown) => {
        const result = await kyaos.handleKyaOs(
          args as Record<string, unknown>,
        );
        return {
          ...result,
          content: result.content.map((c) => ({ ...c, type: "text" as const })),
        };
      },
    );
  }

  // Auto-proof interception via transport wrapper (public API only).
  //
  // We patch server.connect() so that whatever transport the caller passes
  // is silently wrapped with KyaOsTransport before McpServer sees it.
  // Tool registration order does not matter — proofs are injected at the
  // transport boundary, after McpServer has already dispatched the call.
  if (options.proofAllTools !== false) {
    const exclude = ["_kyaos", "_kyaos_handshake", ...(options.excludeTools ?? [])];
    const originalConnect = server.connect.bind(server);

    server.connect = (transport: Transport) =>
      originalConnect(createKyaOsTransport(transport, kyaos, exclude));
  }

  return kyaos;
}
