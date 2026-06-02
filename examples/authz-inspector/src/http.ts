/**
 * Streamable HTTP entrypoint for the authz Inspector demo — with a real,
 * visitable authorization server and the one-token consent flow.
 *
 * Launch:
 *   npx tsx examples/authz-inspector/src/http.ts
 *   # MCP endpoint:   http://localhost:3030/mcp
 *
 * Flow (the caller only ever handles a resume_token):
 *   1. call read_vault (no args) → challenge: a real /authorize URL + resume_token
 *   2. open /authorize → Approve → the SERVER runs the OAuth + PKCE exchange and
 *      caches the grant (the human copies nothing back)
 *   3. re-call read_vault { resume_token } → grant auto-applied → vault reads
 *
 * One shared session holds the pending flows and the grant store; one shared
 * authorization server hosts the consent page + token endpoint. Everything runs
 * in-process, so the round trip is a genuine authorization-code + PKCE exchange
 * with no external IdP.
 */
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createAuthzInspectorMcpServer } from './server.js';
import { createAuthzSession } from './session.js';
import { createDemoAuthServer, type AuthorizeParams } from './auth-server.js';

const PORT = parseInt(process.env['PORT'] ?? '3030', 10);
const BASE = `http://localhost:${PORT}`;
const CALLBACK = `${BASE}/callback`;

// The demo's own authorization server (consent page + code + token endpoint).
const authServer = createDemoAuthServer();

// One shared session: its adapter's token exchange is pointed at this server's
// own /token endpoint, so completing the flow is a real local PKCE exchange.
const session = createAuthzSession({
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

  // Stateful transports, keyed by mcp-session-id. A stable session id is what
  // lets a retried read_vault auto-apply the approval bound to this connection,
  // with no token to paste — and keeps one connection's grant off another's.
  const transports = new Map<string, StreamableHTTPServerTransport>();

const httpServer = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', BASE);

  // ── MCP transport: /mcp (stateful Streamable HTTP) ─────────────────
  if (url.pathname === '/mcp') {
    const sid = req.headers['mcp-session-id'];
    const existing = typeof sid === 'string' ? transports.get(sid) : undefined;

    if (existing) {
      // Subsequent request on an established session (POST, GET stream, DELETE).
      await existing.handleRequest(req, res);
      return;
    }

    if (req.method === 'POST') {
      // A new session: the transport assigns the id on initialize, and the
      // server reads it as extra.sessionId on every later tool call.
      const { server } = createAuthzInspectorMcpServer({ session, callbackUri: CALLBACK, visitable: true });
      const transport: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id: string) => {
          transports.set(id, transport);
        },
        enableJsonResponse: true,
      });
      transport.onclose = () => {
        if (transport.sessionId) transports.delete(transport.sessionId);
      };
      await server.connect(transport);
      await transport.handleRequest(req, res);
      return;
    }

    res.writeHead(400, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'invalid_request', error_description: 'No valid mcp-session-id; POST to initialize first.' }));
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

  // ── Redirect target: GET /callback → SERVER completes the exchange ─
  if (url.pathname === '/callback' && req.method === 'GET') {
    const code = url.searchParams.get('code') ?? '';
    const state = url.searchParams.get('state') ?? '';
    const outcome = await session.completeFromCallback(state, code);
    res.writeHead(outcome.ok ? 200 : 400, { 'content-type': 'text/html; charset=utf-8' });
    res.end(
      outcome.ok
        ? `<!doctype html><meta charset="utf-8"><body style="font:15px system-ui;max-width:32rem;margin:4rem auto">
           <h1 style="font-size:1.1rem">Authorized ✓</h1>
           <p>You can close this tab and return to MCP Inspector. Just re-run
           <code>read_vault</code> — no arguments needed; the approval is applied
           automatically.</p></body>`
        : `<!doctype html><meta charset="utf-8"><body style="font:15px system-ui;max-width:32rem;margin:4rem auto">
           <h1 style="font-size:1.1rem">Authorization failed</h1>
           <p>${escapeHtml(outcome.reason ?? 'unknown error')}</p></body>`,
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
