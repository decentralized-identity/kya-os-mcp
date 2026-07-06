/**
 * KYA-OS Middleware — the `_kyaos` protocol surface.
 *
 * The unified `_kyaos` action router (handshake / identity / reputation), the
 * `identity` responder, and the two tool definitions. Handshake establishment
 * itself lives in `./with-kya-os.session.ts` (it owns the session state); this
 * module only routes to it.
 */

import { KYA_OS_ERROR_CODES } from "../errors.js";
import {
  KYA_OS_ACTIONS,
  type KyaOsAction,
  type KyaOsToolDefinition,
} from "./with-kya-os.types.js";
import type { MiddlewareDeps } from "./with-kya-os.deps.js";

type ProtocolResponse = {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
};

/** The handshake establishment handler, injected from the session sub-factory. */
export interface ProtocolWiring {
  handleHandshake(args: Record<string, unknown>): Promise<ProtocolResponse>;
}

export interface Protocol {
  handleKyaOs(args: Record<string, unknown>): Promise<ProtocolResponse>;
  handshakeTool: KyaOsToolDefinition;
  kyaOsTool: KyaOsToolDefinition;
}

export function createProtocol(
  deps: MiddlewareDeps,
  wiring: ProtocolWiring,
): Protocol {
  const { identity, config, sessionManager } = deps;
  const { handleHandshake } = wiring;

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

  async function handleIdentity(): Promise<ProtocolResponse> {
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

  async function handleKyaOs(
    args: Record<string, unknown>,
  ): Promise<ProtocolResponse> {
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
                  message: 'action: "reputation" is not yet implemented.',
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

  return { handleKyaOs, handshakeTool, kyaOsTool };
}
