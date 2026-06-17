/**
 * Consent server — renders the consent page and, on POST /approve, mints the
 * delegation VC and binds a durable grant into the SHARED grant store (see
 * approve.ts). It is the durable-storage write half of the flow; the MCP server
 * instances read that store on a retry.
 *
 * UI note: this example deliberately uses the basic shared consent page
 * (examples/_shared/consent-page.ts), NOT @kya-os/consent (which consent-full /
 * node-server use). @kya-os/consent's approval response schema REQUIRES a
 * `delegation_id` + `delegation_token` on success, but this flow is
 * holder-of-key: approval binds an agent-anchored grant and returns no token
 * (the agent re-proves possession per request). The basic page handles that
 * `{ approved: true }` response cleanly; @kya-os/consent would reject it. This
 * is the honest holder-of-key exception, not an oversight.
 */

import http from 'node:http';
import { approve } from './approve.js';
import { FileGrantStore } from './file-grant-store.js';
import { SCOPE, TOOL, type AgentIdentity } from './instance.js';
import { renderConsentPage } from '../../_shared/consent-page.js';

export interface ConsentServer {
  url: string;
  close: () => Promise<void>;
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => (data += chunk));
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function parseBody(req: http.IncomingMessage, raw: string): Record<string, string> {
  const contentType = req.headers['content-type'] ?? '';
  if (contentType.includes('application/json')) {
    try {
      return JSON.parse(raw) as Record<string, string>;
    } catch {
      return {};
    }
  }
  const out: Record<string, string> = {};
  for (const [k, v] of new URLSearchParams(raw)) out[k] = v;
  return out;
}

export async function startConsentServer(opts: {
  port: number;
  identity: AgentIdentity;
  grantStore: FileGrantStore;
}): Promise<ConsentServer> {
  const server = http.createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url ?? '/', 'http://localhost');

    if (url.pathname === '/consent' && req.method === 'GET') {
      const tool = url.searchParams.get('tool') ?? TOOL;
      const agentDid = url.searchParams.get('agent_did') ?? opts.identity.did;
      const scopes = url.searchParams.get('scopes') ?? SCOPE;
      // Canonical shared consent page (escapes all reflected values). On approve
      // its script POSTs JSON and, since this backend returns `{ approved: true }`
      // (no token), shows the holder-of-key "retry, no re-paste" message.
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(renderConsentPage({ tool, scopes, agentDid, approvePath: '/approve' }));
      return;
    }

    if (url.pathname === '/approve' && req.method === 'POST') {
      const params = parseBody(req, await readBody(req));
      const agentDid = params['agentDid'] ?? params['agent_did'] ?? opts.identity.did;
      const scopes = (params['scopes'] ?? SCOPE).split(',').filter(Boolean);
      const result = await approve({
        identity: opts.identity,
        grantStore: opts.grantStore,
        agentDid,
        scopes,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ approved: true, grantId: result.grantId, agentDid }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found' }));
  });

  await new Promise<void>((resolve) => server.listen(opts.port, resolve));
  const addr = server.address();
  const actualPort = typeof addr === 'object' && addr ? addr.port : opts.port;

  return {
    url: `http://localhost:${actualPort}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
