/**
 * McpServer Adapter for MCP-I
 *
 * Adds MCP-I identity, session management, and proof generation to a
 * standard McpServer instance with a single function call.
 *
 * Usage:
 *   import { withMCPI } from '@kya-os/mcp/middleware';
 *   const mcpi = await withMCPI(server, { crypto: new NodeCryptoProvider() });
 *   // All tools registered on `server` now get proofs automatically.
 *   await server.connect(transport); // transport is transparently wrapped
 */

import type { CryptoProvider } from "../providers/base.js";
import { generateDidKeyFromBase64, didKeyFragment } from "../utils/did-helpers.js";
import {
  MCPI_ACTIONS,
  createMCPIMiddleware,
  type MCPIIdentityConfig,
  type MCPIDelegationConfig,
  type MCPIMiddleware,
} from "./with-mcpi.js";
import { createMCPITransport, type Transport } from "./mcpi-transport.js";
import { z } from "zod";

export interface WithMCPIOptions {
  /** Platform-specific crypto implementation (required) */
  crypto: CryptoProvider;
  /** Identity config — auto-generated if omitted */
  identity?: MCPIIdentityConfig;
  /** Session configuration */
  session?: { sessionTtlMinutes?: number };
  /** Auto-create sessions for non-MCP-I clients (default: true) */
  autoSession?: boolean;
  /** Attach proofs to all tool responses (default: true) */
  proofAllTools?: boolean;
  /** Tools to skip proof generation for */
  excludeTools?: string[];
  /** Delegation verification config */
  delegation?: MCPIDelegationConfig;
  /**
   * How the MCP-I protocol tool is exposed on the server.
   * - "tool" (default): auto-register `_mcpi`
   * - "none": do not register MCP-I tool (use middleware APIs for custom runtime hooks)
   */
  handshakeExposure?: "tool" | "none";
}

/**
 * Generate a fresh Ed25519 identity for MCP-I.
 *
 * @param crypto - Platform-specific crypto provider
 * @returns Identity config with DID, kid, and key material
 */
export async function generateIdentity(
  crypto: CryptoProvider,
): Promise<MCPIIdentityConfig> {
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
 * Matches the subset of McpServer's public API that withMCPI() uses.
 */
interface McpServerLike {
  connect(transport: Transport): Promise<unknown>;
  registerTool(...args: unknown[]): void;
}

/**
 * Add MCP-I to a McpServer instance.
 *
 * 1. Auto-generates Ed25519 identity (or uses provided one)
 * 2. Registers `_mcpi` tool by default (`handshakeExposure: "tool"`)
 * 3. Patches `server.connect()` to transparently wrap the transport with
 *    MCPITransport, which injects detached proofs into all `tools/call`
 *    responses using only the public Transport interface.
 *
 * The user-facing API is unchanged — register tools before or after this
 * call, then connect as normal:
 *
 * ```ts
 * const mcpi = await withMCPI(server, { crypto: new NodeCryptoProvider() });
 * await server.connect(transport); // MCPITransport wraps silently
 * ```
 *
 * @param server  - McpServer instance
 * @param options - Configuration
 * @returns The MCPIMiddleware instance for advanced usage (wrapWithDelegation, etc.)
 */
export async function withMCPI(
  server: McpServerLike,
  options: WithMCPIOptions,
): Promise<MCPIMiddleware> {
  const identity =
    options.identity ?? (await generateIdentity(options.crypto));

  const mcpi = createMCPIMiddleware(
    {
      identity,
      session: options.session,
      delegation: options.delegation,
      autoSession: options.autoSession ?? true,
    },
    options.crypto,
  );

  if ((options.handshakeExposure ?? "tool") === "tool") {
    // Register the unified _mcpi tool for protocol operations.
    server.registerTool(
      "_mcpi",
      {
        description:
          "MCP-I protocol — identity verification, session handshake, and server metadata",
        annotations: { title: "MCP-I Protocol", readOnlyHint: true },
        inputSchema: {
          action: z
            .enum(MCPI_ACTIONS)
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
        const result = await mcpi.handleMCPI(
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
  // is silently wrapped with MCPITransport before McpServer sees it.
  // Tool registration order does not matter — proofs are injected at the
  // transport boundary, after McpServer has already dispatched the call.
  if (options.proofAllTools !== false) {
    const exclude = ["_mcpi", "_mcpi_handshake", ...(options.excludeTools ?? [])];
    const originalConnect = server.connect.bind(server);

    server.connect = (transport: Transport) =>
      originalConnect(createMCPITransport(transport, mcpi, exclude));
  }

  return mcpi;
}
