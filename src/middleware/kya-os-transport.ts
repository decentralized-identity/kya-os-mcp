/**
 * KyaOsTransport — Proof-injecting Transport Wrapper
 *
 * Wraps any MCP Transport to intercept `tools/call` responses and attach
 * KYA-OS detached proofs. Uses only the public Transport interface — no
 * private SDK internals accessed.
 *
 * The McpServer never knows this wrapper exists. It sees a normal transport.
 * The connected client sees normal MCP responses with the detached proof added
 * under the namespaced `_meta` key `org.kya-os/response-proof` (see KYA_OS_PROOF_META_KEY).
 *
 * How it works:
 *   1. Incoming `tools/call` requests are captured (by id) to record tool
 *      name and arguments for proof generation.
 *   2. Outgoing responses for those ids get a proof injected into `_meta`.
 *   3. All other message types pass through unmodified.
 *
 * @module kya-os-transport
 */

import type { KyaOsMiddleware, KyaOsToolHandler } from "./with-kya-os.js";
import { logger } from "../logging/index.js";

/** Minimal Transport interface — matches @modelcontextprotocol/sdk Transport */
export interface Transport {
  start(): Promise<void>;
  send(message: JSONRPCMessage): Promise<void>;
  close(): Promise<void>;
  onmessage?: (message: JSONRPCMessage) => void;
  onclose?: () => void;
  onerror?: (error: Error) => void;
}

export type JSONRPCMessage = Record<string, unknown>;

interface PendingCall {
  toolName: string;
  args: Record<string, unknown>;
}

type ToolResult = {
  content: Array<{ type: string; text: string; [key: string]: unknown }>;
  isError?: boolean;
  [key: string]: unknown;
};

/**
 * Creates a transport wrapper that injects KYA-OS proofs into `tools/call`
 * responses.
 *
 * @param inner   - The real transport (Stdio, HTTP, etc.)
 * @param kyaos    - Configured KyaOsMiddleware instance
 * @param exclude - Tool names to skip proof generation for
 */
export function createKyaOsTransport(
  inner: Transport,
  kyaos: KyaOsMiddleware,
  exclude: string[] = ["_kyaos", "_kyaos_handshake"],
): Transport {
  // Request id → { toolName, args } for pending tool calls
  const pending = new Map<unknown, PendingCall>();

  const wrapper: Transport = {
    start: () => inner.start(),
    close: () => inner.close(),

    // McpServer writes into wrapper.onmessage — forward to inner so the
    // real transport can drive it.
    set onmessage(handler: ((msg: JSONRPCMessage) => void) | undefined) {
      inner.onmessage = handler;
    },
    get onmessage() {
      return inner.onmessage;
    },

    set onclose(handler: (() => void) | undefined) {
      inner.onclose = handler;
    },
    get onclose() {
      return inner.onclose;
    },

    set onerror(handler: ((err: Error) => void) | undefined) {
      inner.onerror = handler;
    },
    get onerror() {
      return inner.onerror;
    },

    // McpServer calls send() for every outgoing message.
    // Intercept tools/call responses here to inject proofs.
    async send(message: JSONRPCMessage): Promise<void> {
      const id = message.id;
      const call = id !== undefined ? pending.get(id) : undefined;

      if (call) {
        pending.delete(id);
        try {
          const rawResult = message.result as ToolResult | undefined;
          if (rawResult) {
            // Work on a shallow copy: middleware is allowed to decorate its
            // result, and an error response must remain byte-for-byte free of
            // a success proof even if a custom middleware implementation does
            // not apply the core implementation's early error return.
            const handler: KyaOsToolHandler = async () => ({ ...rawResult });
            const addProof = kyaos.wrapWithProof(call.toolName, handler);
            const proofed = await addProof(call.args);
            // Error results still traverse the middleware so their terminal
            // audit event is emitted, but they retain the established wire
            // contract: no success proof is attached to an error response.
            if (!rawResult.isError && proofed._meta !== undefined) {
              message = {
                ...message,
                result: proofed,
              };
            }
          }
        } catch (error) {
          logger.error("[kya-os-transport] Proof injection failed", {
            tool: call.toolName,
            error: error instanceof Error ? error.message : String(error),
          });
          const rawResult = message.result as ToolResult | undefined;
          if (rawResult) {
            rawResult._meta = {
              proofError: "Proof generation failed — response is unproven",
            };
            message = { ...message, result: rawResult };
          }
        }
      }

      return inner.send(message);
    },
  };

  // Intercept incoming messages from the real transport to capture
  // tools/call requests before McpServer processes them.
  // We defer setting inner.onmessage until McpServer has set wrapper.onmessage
  // via server.connect() — so we proxy through the getter/setter above and
  // add our interception in a one-time initializer on start().
  const originalStart = inner.start.bind(inner);
  wrapper.start = async () => {
    await originalStart();
    // At this point McpServer has called server.connect(wrapper) which set
    // wrapper.onmessage = <McpServer handler>. That assignment forwarded to
    // inner.onmessage via the setter above. Now we inject our interceptor.
    const downstream = inner.onmessage;
    inner.onmessage = (message: JSONRPCMessage) => {
      if (
        message.method === "tools/call" &&
        message.id !== undefined
      ) {
        const params = message.params as
          | { name?: string; arguments?: Record<string, unknown> }
          | undefined;
        const toolName = params?.name;
        if (toolName && !exclude.includes(toolName)) {
          pending.set(message.id, {
            toolName,
            args: params?.arguments ?? {},
          });
        }
      }
      downstream?.(message);
    };
  };

  return wrapper;
}
