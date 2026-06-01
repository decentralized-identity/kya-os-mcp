/**
 * Streamable HTTP entrypoint for the authz Inspector demo — with a real,
 * visitable authorization server.
 *
 * Launch:
 *   npx tsx examples/authz-inspector/src/http.ts
 *   # MCP endpoint:   http://localhost:3030/mcp
 *   # authorize page: opened from the challenge the protected tool returns
 *
 * Unlike the stdio entrypoint (which uses the in-memory provider), this server
 * co-hosts a genuine OAuth 2.1 + PKCE authorization server, so the authorize
 * URL the protected tool hands back is a real page you open in the browser and
 * click "Approve". The MCP adapter's token exchange is pointed at this server's
 * own /token endpoint, so the whole authorization-code + PKCE round trip runs
 * locally end to end (no external IdP, deterministic).
 *
 * A single shared adapter is used across requests so a resume token issued on
 * one /mcp call is still valid on the follow-up call.
 */
import http from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { GenericOidcAdapter } from '@kya-os/mcp/authz';
import { createAuthzInspectorMcpServer } from './server.js';
import { createDemoAuthServer, type AuthorizeParams } from './auth-server.js';

const PORT = parseInt(process.env['PORT'] ?? '3030', 10);
const BASE = `http://localhost:${PORT}`;

// The demo's own authorization server (consent page + code + token endpoint).
const authServer = createDemoAuthServer();

// One shared adapter for the whole process. Its token exchange is pointed at
// this server's /token endpoint, so verifyAuthorization completes a real PKCE
// code exchange against the local authorization server.
const adapter = new GenericOidcAdapter({
  type: 'oauth',
  issuer: BASE,
  authorizationEndpoint: `${BASE}/authorize`,
  tokenEndpoint: `${BASE}/token`,
  clientId: 'authz-inspector-demo',
  scopes: ['vault:read'],
  resource: `${BASE}/vault`,
  fetchImpl: (url, init) => fetch(url, init),
});

function authorizeParamsFrom(source: URLSearchParams): AuthorizeParams {
  return {
    clientId: source.get('client_id') ?? '',
    redirectUri: source.get('redirect_uri') ?? '',
    scope: source.get('scope') ?? '',
    state: source.get('state') ?? '',
    codeChallenge: source.get('code_challenge') ?? '',
    codeChallengeMethod: source.get('code_challenge_method') ?? '',
  };
}

async function readBody(req: http.IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

const httpServer = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', BASE);

  // ── MCP transport: POST /mcp (modern Streamable HTTP) ──────────────
  if (url.pathname === '/mcp' && req.method === 'POST') {
    const { server } = createAuthzInspectorMcpServer({ adapter, redirectUri: `${BASE}/callback`, visitable: true });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => void transport.close());
    await server.connect(transport);
    await transport.handleRequest(req, res);
    return;
  }

  // ── Authorization server: GET /authorize → consent page ────────────
  if (url.pathname === '/authorize' && req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(authServer.renderConsent(authorizeParamsFrom(url.searchParams)));
    return;
  }

  // ── Authorization server: POST /approve → mint code, redirect ──────
  if (url.pathname === '/approve' && req.method === 'POST') {
    const params = authorizeParamsFrom(new URLSearchParams(await readBody(req)));
    const { code } = authServer.approve(params);
    const back = new URL(params.redirectUri);
    back.searchParams.set('code', code);
    back.searchParams.set('state', params.state);
    res.writeHead(302, { location: back.toString() });
    res.end();
    return;
  }

  // ── Redirect target: GET /callback → show the code to paste back ───
  if (url.pathname === '/callback' && req.method === 'GET') {
    const code = url.searchParams.get('code') ?? '';
    const state = url.searchParams.get('state') ?? '';
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(
      `<!doctype html><meta charset="utf-8"><body style="font:15px system-ui;max-width:32rem;margin:4rem auto">
       <h1 style="font-size:1.1rem">Authorized ✓</h1>
       <p>Copy this authorization code back into the <code>read_vault</code> tool in MCP Inspector:</p>
       <p><code style="font-size:1.1rem;background:#f3f3f7;padding:.4rem .6rem;border-radius:6px">${escapeHtml(code)}</code></p>
       <p style="color:#666;font-size:.85rem">state: <code>${escapeHtml(state)}</code></p>
       </body>`,
    );
    return;
  }

  // ── Authorization server: POST /token → PKCE-verified token ────────
  if (url.pathname === '/token' && req.method === 'POST') {
    const form = new URLSearchParams(await readBody(req));
    try {
      const token = await authServer.exchangeToken({
        grant_type: 'authorization_code',
        code: form.get('code') ?? '',
        redirect_uri: form.get('redirect_uri') ?? '',
        client_id: form.get('client_id') ?? '',
        code_verifier: form.get('code_verifier') ?? '',
      });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(token));
    } catch (error) {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'invalid_grant', error_description: (error as Error).message }));
    }
    return;
  }

  if (url.pathname === '/' && req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ name: 'kya-os-authz-inspector', mcp: `${BASE}/mcp`, authorize: `${BASE}/authorize` }));
    return;
  }

  res.writeHead(404, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ error: 'not_found' }));
});

function escapeHtml(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

httpServer.listen(PORT, () => {
  process.stderr.write(`[kya-os] authz Inspector demo (Streamable HTTP) on ${BASE}/mcp\n`);
  process.stderr.write(`[kya-os] authorization server (consent page) on ${BASE}/authorize\n`);
});
