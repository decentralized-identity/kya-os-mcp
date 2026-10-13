/**
 * Call a KYA-OS-wrapped tool handler outside an MCP server and get the result
 * a client would receive.
 *
 * The middleware makes its response proofs where the KYA-OS transport sends a
 * result, because the MCP SDK changes a result after the handler returns it.
 * A walkthrough, a script or a test that calls a handler directly therefore
 * sends what the handler returns through a KYA-OS transport, as a server
 * connected through withKyaOs() or createKyaOsTransport() does. Only the
 * public API is used.
 */

import {
  createKyaOsTransport,
  type KyaOsMiddleware,
  type KyaOsToolHandler,
  type KyaOsToolResult,
} from '@kya-os/mcp';

type Message = Record<string, unknown>;

interface Wire {
  inner: { onmessage?: (message: Message) => void };
  transport: ReturnType<typeof createKyaOsTransport>;
  ready: Promise<void>;
  sent: Message[];
  nextId: number;
}

/** One KYA-OS transport per middleware, as a server has. */
const wires = new WeakMap<KyaOsMiddleware, Wire>();

function wireFor(kyaos: KyaOsMiddleware): Wire {
  const existing = wires.get(kyaos);
  if (existing) return existing;
  const sent: Message[] = [];
  const inner: Wire['inner'] & {
    start(): Promise<void>;
    close(): Promise<void>;
    send(message: Message): Promise<void>;
  } = {
    start: async () => {},
    close: async () => {},
    send: async (message) => {
      // What crosses the wire is JSON.
      sent.push(JSON.parse(JSON.stringify(message)) as Message);
    },
  };
  const transport = createKyaOsTransport(inner, kyaos);
  const wire: Wire = { inner, transport, ready: transport.start(), sent, nextId: 0 };
  wires.set(kyaos, wire);
  return wire;
}

/**
 * `handler`, answering as an MCP server would: its result goes through the
 * middleware's KYA-OS transport, and the caller gets what the client receives.
 */
export function serveTool<R = KyaOsToolResult>(
  kyaos: KyaOsMiddleware,
  toolName: string,
  handler: KyaOsToolHandler,
): (args: Record<string, unknown>, sessionId?: string) => Promise<R> {
  const wire = wireFor(kyaos);
  return async (args, sessionId) => {
    await wire.ready;
    const id = ++wire.nextId;
    wire.inner.onmessage?.({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: toolName, arguments: args } });
    await wire.transport.send({ jsonrpc: '2.0', id, result: await handler(args, sessionId) });
    return (wire.sent.at(-1) as { result: R }).result;
  };
}
