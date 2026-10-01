import { timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

/** Constant-time bearer comparison, so a wrong token leaks no length or prefix. */
function bearerMatches(req: IncomingMessage, expected: string): boolean {
  const header = req.headers.authorization ?? '';
  const presented = header.startsWith('Bearer ') ? header.slice(7) : '';
  const a = Buffer.from(presented);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Each HTTP request owns its MCP server and transport; there is no session map. */
export async function handleStatelessMcp(
  req: IncomingMessage,
  res: ServerResponse,
  createServer: () => Server,
  options: { loopbackOnly?: boolean; allowedHosts?: readonly string[]; token?: string } = {},
): Promise<void> {
  res.setHeader('Cache-Control', 'no-store');
  if (options.token && !bearerMatches(req, options.token)) {
    res.writeHead(401, { 'WWW-Authenticate': 'Bearer', 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32001, message: 'Unauthorized. This gateway signs as the demo agent and requires a bearer token.' } }));
    return;
  }
  if (req.method !== 'POST') {
    res.writeHead(405, { Allow: 'POST', 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32000, message: 'Use POST for stateless Streamable HTTP. Connection instructions: /connect' } }));
    return;
  }

  let server: Server | undefined;
  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    await server?.close();
  };
  res.once('close', () => { void close().catch(() => {}); });
  try {
    server = createServer();
    const loopback = ['localhost', '127.0.0.1', '[::1]'].map((host) => `${host}:${req.socket.localPort}`);
    // A deployment answers on its own hostname, so the rebinding guard has to
    // know it. Origins stay loopback-only: no browser page calls this endpoint,
    // so any request that carries an Origin at all is refused.
    const hosts = [...loopback, ...(options.allowedHosts ?? [])];
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
      // The gateway can sign as the configured demo agent. A browser on an
      // unrelated origin or a rebinding hostname must not invoke that authority.
      ...(options.loopbackOnly ? {
        enableDnsRebindingProtection: true,
        allowedHosts: hosts,
        allowedOrigins: loopback.map((host) => `http://${host}`),
      } : {}),
    });
    await server.connect(transport);
    await transport.handleRequest(req, res);
  } catch {
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32603, message: 'MCP request failed' } }));
    } else if (!res.writableEnded) res.end();
    await close().catch(() => {});
  }
}
