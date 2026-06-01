/**
 * Streamable HTTP entrypoint for the authz Inspector demo (modern MCP `/mcp`
 * transport).
 *
 * Launch:
 *   npx tsx examples/authz-inspector/src/http.ts
 *   # then point MCP Inspector at  http://localhost:3030/mcp
 *
 * Serves the same server as the stdio entrypoint over the Streamable HTTP
 * transport, so the demo works with both the classic stdio launcher and a
 * modern `/mcp` deployment. A fresh server + transport is created per request
 * (stateless), matching the SDK's stateless Streamable HTTP pattern.
 */
import http from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createAuthzInspectorMcpServer } from './server.js';

const PORT = parseInt(process.env['PORT'] ?? '3030', 10);

const httpServer = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://localhost:${PORT}`);

  // Modern Streamable HTTP transport: POST /mcp
  if (url.pathname === '/mcp' && req.method === 'POST') {
    const { server } = createAuthzInspectorMcpServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    res.on('close', () => {
      void transport.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res);
    return;
  }

  if (url.pathname === '/' && req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ name: 'kya-os-authz-inspector', mcp: `http://localhost:${PORT}/mcp` }));
    return;
  }

  res.writeHead(404, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ error: 'not_found' }));
});

httpServer.listen(PORT, () => {
  // Diagnostics on stderr so they never interfere with a piped stdout.
  process.stderr.write(`[kya-os] authz Inspector demo (Streamable HTTP) on http://localhost:${PORT}/mcp\n`);
});
