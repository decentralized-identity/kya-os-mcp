/**
 * Call KYA-OS-wrapped tool handlers in process, outside an MCP server, and
 * get the results a client would receive.
 *
 * The middleware makes its response proofs where the KYA-OS transport sends a
 * result, because the MCP SDK changes a result after the handler returns it.
 * A script, a walkthrough or a test that calls a wrapped handler directly
 * therefore needs a KYA-OS transport to send what the handler returns, as a
 * server connected through `withKyaOs()` or `createKyaOsTransport()` has. This
 * module is that transport, with nothing on the far end but the caller.
 *
 * ```ts
 * const local = serveInProcess(kyaos);
 * const checkout = local.tool('checkout', kyaos.wrapWithDelegation('checkout', consent, handler));
 * const result = await checkout({ item: 'laptop' }); // proved, as a client receives it
 * await local.close();
 * ```
 *
 * @module serve-in-process
 */

import { createKyaOsTransport, type JSONRPCMessage } from "./kya-os-transport.js";
import type { KyaOsMiddleware, KyaOsToolHandler, KyaOsToolResult } from "./with-kya-os.types.js";

/** A KYA-OS transport for in-process calls, open until {@link InProcessServer.close}. */
export interface InProcessServer {
  /**
   * `handler`, answering as an MCP server would: its result goes through the
   * KYA-OS transport, and the caller gets what a client receives, proof
   * included. `toolName` names the call, as a client's `tools/call` would.
   */
  tool<R = KyaOsToolResult>(
    toolName: string,
    handler: KyaOsToolHandler,
  ): (args: Record<string, unknown>, sessionId?: string) => Promise<R>;
  /**
   * Close the transport. It no longer counts as open for the middleware, and
   * its tools refuse further calls.
   */
  close(): Promise<void>;
}

/**
 * Open a KYA-OS transport for `kyaos` whose far end is the caller. While it
 * is open it counts as an open KYA-OS transport for the middleware, so close
 * it when done.
 */
export function serveInProcess(kyaos: KyaOsMiddleware): InProcessServer {
  // Each call's answer, by its request id, as it crossed the wire.
  const answers = new Map<number, JSONRPCMessage>();
  let closed = false;
  const inner: {
    start(): Promise<void>;
    close(): Promise<void>;
    send(message: JSONRPCMessage): Promise<void>;
    onmessage?(message: JSONRPCMessage): void;
    onclose?(): void;
  } = {
    start: async () => {},
    close: async () => {},
    send: async (message) => {
      // What crosses the wire is JSON.
      if (typeof message.id === "number") answers.set(message.id, JSON.parse(JSON.stringify(message)) as JSONRPCMessage);
    },
  };
  const transport = createKyaOsTransport(inner, kyaos);
  const ready = transport.start();
  let nextId = 0;

  return {
    tool<R = KyaOsToolResult>(toolName: string, handler: KyaOsToolHandler) {
      return async (args: Record<string, unknown>, sessionId?: string): Promise<R> => {
        if (closed) throw new Error("[kya-os] serveInProcess: the transport is closed");
        await ready;
        const id = ++nextId;
        inner.onmessage?.({
          jsonrpc: "2.0",
          id,
          method: "tools/call",
          params: { name: toolName, arguments: args },
        });
        const result = await handler(args, sessionId);
        await transport.send({ jsonrpc: "2.0", id, result });
        const answer = answers.get(id) as { result: R };
        answers.delete(id);
        return answer.result;
      };
    },
    async close() {
      if (closed) return;
      closed = true;
      await ready;
      await transport.close();
    },
  };
}
