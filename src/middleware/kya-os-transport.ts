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
 *   2. Outgoing responses for those ids get a proof injected into `_meta`,
 *      unless the middleware's own wrappers already proved or audited the
 *      result, which they mark with a private per-middleware stamp.
 *   3. Under the envelope response-proof profile the wrappers leave their
 *      proofs here, and every proof is made in `send()`, over the result as
 *      the MCP SDK finished it: the SDK sets members after the handler
 *      returns (`resultType` on the 2026-07-28 revision), and the envelope
 *      profile covers them.
 *   4. All other message types pass through unmodified, except that the
 *      middleware's private members are removed from every result before it
 *      is sent.
 *
 * @module kya-os-transport
 */

import type { KyaOsMiddleware, KyaOsToolHandler } from "./with-kya-os.js";
import {
  attachOuterProofLayer,
  withoutOutcomeMeta,
  withoutPrivateMeta,
} from "./with-kya-os.session.js";
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
 * responses. Under the envelope response-proof profile it also makes the
 * proofs the middleware's wrappers and `proveOutcome` leave to it, over each
 * result as it is sent.
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
  // From here on the middleware's wrappers stamp what they return, and the
  // layer tells a stamped result from one that only looks proven, and makes
  // the proofs they leave to it. Undefined for a custom middleware, whose
  // results are all proved here.
  const layer = attachOuterProofLayer(kyaos.wrapWithProof);
  // While started and not closed, this transport counts as open for the
  // middleware; under the envelope profile its wrappers run only then.
  let release: (() => void) | undefined;
  const releaseOpen = (): void => {
    release?.();
    release = undefined;
  };
  // The close handler the server installed through the wrapper. It runs the
  // handler the caller set on the inner transport before connecting, which
  // the server read through the getter below and chained.
  let closeHandler: (() => void) | undefined;
  const closed = (): void => {
    releaseOpen();
    closeHandler?.();
  };

  const wrapper: Transport = {
    start: () => inner.start(),
    close: async () => {
      releaseOpen();
      await inner.close();
    },

    // McpServer writes into wrapper.onmessage — forward to inner so the
    // real transport can drive it.
    set onmessage(handler: ((msg: JSONRPCMessage) => void) | undefined) {
      inner.onmessage = handler;
    },
    get onmessage() {
      return inner.onmessage;
    },

    // The inner transport may close on its own (the client went away), so
    // its close also ends this transport's count. Before a handler is set
    // here, the getter reports the inner transport's own: the SDK reads it
    // when it connects and chains it (a session map's cleanup, say), so it
    // keeps running.
    set onclose(handler: (() => void) | undefined) {
      closeHandler = handler;
      inner.onclose = closed;
    },
    get onclose() {
      return closeHandler ?? (inner.onclose === closed ? undefined : inner.onclose);
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
      // Only a response (result or error, no method) can answer a pending call:
      // a server-initiated request such as elicitation/create numbers its ids
      // in the server's own space, so its id can equal a pending client id.
      const isResponse =
        message.method === undefined && ("result" in message || "error" in message);
      const id = message.id;
      const call = isResponse && id !== undefined ? pending.get(id) : undefined;

      if (call) {
        pending.delete(id);
        const rawResult = message.result as ToolResult | undefined;
        // A result the middleware's wrappers already proved or audited (a
        // delegated call's scope-bearing proof, a signed needs_authorization
        // outcome, an outcome application code proved with proveOutcome, an
        // audited error) passes through: proving it again would replace its
        // proof and record its lifecycle twice. Only the stamp shows that;
        // proof, proofError and audit members can come from any handler,
        // including one relaying an upstream server's result.
        if (rawResult && layer?.owns(rawResult) !== true) {
          // Those members are untrusted here, so they are removed and the
          // result is proved and audited as any other. Other members stay.
          const received = withoutOutcomeMeta(rawResult);
          try {
            // Work on a shallow copy: middleware is allowed to decorate its
            // result, and an error response must remain byte-for-byte free of
            // a success proof even if a custom middleware implementation does
            // not apply the core implementation's early error return.
            const handler: KyaOsToolHandler = async () => ({ ...received });
            const addProof = kyaos.wrapWithProof(call.toolName, handler);
            const proofed = await addProof(call.args);
            // Error results still traverse the middleware so their terminal
            // audit event is emitted, but they retain the established wire
            // contract: no success proof is attached to an error response.
            message = {
              ...message,
              result: !received.isError && proofed._meta !== undefined ? proofed : received,
            };
          } catch (error) {
            logger.error("[kya-os-transport] Proof injection failed", {
              tool: call.toolName,
              error: error instanceof Error ? error.message : String(error),
            });
            message = {
              ...message,
              result: {
                ...received,
                _meta: {
                  ...((received._meta as Record<string, unknown> | undefined) ?? {}),
                  proofError: "Proof generation failed — response is unproven",
                },
              },
            };
          }
        }
      }

      // Whichever path the message took: a proof a wrapper left for the wire
      // is made now, over the result as it is sent, and the private members
      // never leave the process.
      if (typeof message.result === "object" && message.result !== null) {
        const result = message.result as ToolResult;
        const sent = layer ? await layer.send(result) : withoutPrivateMeta(result);
        if (sent !== message.result) message = { ...message, result: sent };
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
  let interceptor: ((message: JSONRPCMessage) => void) | undefined;
  wrapper.start = async () => {
    await originalStart();
    // Counted once however often start() is called, until the transport closes.
    release ??= layer?.open();
    // A close handler set on the inner transport and never read through the
    // wrapper is adopted, so it still runs, after the one installed here.
    const foreign = inner.onclose;
    if (foreign !== undefined && foreign !== closed) {
      const installed = closeHandler;
      closeHandler = installed === undefined ? foreign : () => {
        foreign();
        installed();
      };
    }
    inner.onclose = closed;
    // At this point McpServer has called server.connect(wrapper) which set
    // wrapper.onmessage = <McpServer handler>. That assignment forwarded to
    // inner.onmessage via the setter above. Now we inject our interceptor,
    // once.
    if (interceptor !== undefined && inner.onmessage === interceptor) return;
    const downstream = inner.onmessage;
    interceptor = (message: JSONRPCMessage) => {
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
      } else if (message.method === "notifications/cancelled") {
        // A cancelled request gets no response, so its entry would never be
        // consumed by send().
        const params = message.params as { requestId?: unknown } | undefined;
        pending.delete(params?.requestId);
      }
      downstream?.(message);
    };
    inner.onmessage = interceptor;
  };

  return wrapper;
}
