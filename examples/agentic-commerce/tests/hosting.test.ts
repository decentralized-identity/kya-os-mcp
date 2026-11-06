/** The changes that make the demo deployable: bind host, public hosts, gateway
 *  bearer auth and the presenter's admin token. */
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hosting-'));
const PUBLIC_HOST = 'commerce.kya-os.ai';
const TOKEN = 'presenter-token-value';
let handleStatelessMcp: typeof import('../src/lib/stateless-mcp.js').handleStatelessMcp;
let server: http.Server;
let port: number;

const rpc = { jsonrpc: '2.0', id: 1, method: 'initialize', params: {
  protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'probe', version: '1.0' },
} };

// fetch() refuses to send a caller-supplied Host header, which is exactly the
// header the rebinding guard reads, so these go out over a raw HTTP request.
function post(headers: Record<string, string>): Promise<{ status: number; body: Record<string, unknown> }> {
  const payload = JSON.stringify(rpc);
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port, path: '/agent/mcp', method: 'POST',
      headers: {
        'Content-Type': 'application/json', Accept: 'application/json, text/event-stream',
        'Content-Length': Buffer.byteLength(payload), ...headers,
      },
    }, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: JSON.parse(raw) as Record<string, unknown> }));
    });
    req.once('error', reject);
    req.end(payload);
  });
}

beforeAll(async () => {
  process.env['DEMO_VAR_DIR'] = path.join(tmp, 'var');
  process.env['DEMO_DATA_DIR'] = path.join(tmp, 'data');
  ({ handleStatelessMcp } = await import('../src/lib/stateless-mcp.js'));
  server = http.createServer((req, res) => {
    void handleStatelessMcp(req, res, () => new Server({ name: 'probe', version: '1.0' }, { capabilities: {} }), {
      loopbackOnly: true,
      allowedHosts: [PUBLIC_HOST, `${PUBLIC_HOST}:443`],
      token: TOKEN,
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as { port: number }).port;
});
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

describe('agent gateway bearer authentication', () => {
  it('refuses a request with no Authorization header', async () => {
    const { status, body } = await post({});
    expect(status).toBe(401);
    expect((body['error'] as { code: number }).code).toBe(-32001);
  });

  it('refuses a wrong token of the same length and of a different length', async () => {
    const sameLength = TOKEN.slice(0, -1) + 'X';
    expect(sameLength).toHaveLength(TOKEN.length);
    expect((await post({ Authorization: `Bearer ${sameLength}` })).status).toBe(401);
    expect((await post({ Authorization: 'Bearer short' })).status).toBe(401);
    expect((await post({ Authorization: TOKEN })).status).toBe(401);
  });

  it('accepts the configured token and completes the MCP handshake', async () => {
    const { status, body } = await post({ Authorization: `Bearer ${TOKEN}` });
    expect(status).toBe(200);
    expect((body['result'] as { serverInfo: { name: string } }).serverInfo.name).toBe('probe');
  });
});

describe('rebinding guard on a public deployment', () => {
  const auth = { Authorization: `Bearer ${TOKEN}` };

  it('accepts the configured public hostname', async () => {
    expect((await post({ ...auth, Host: PUBLIC_HOST })).status).toBe(200);
  });

  it('still refuses an unknown hostname', async () => {
    const { status, body } = await post({ ...auth, Host: 'attacker.example' });
    expect(status).toBe(403);
    expect((body['error'] as { message: string }).message).toContain('Invalid Host');
  });

  it('refuses a browser Origin even on the public hostname, since no page calls this', async () => {
    const { status, body } = await post({ ...auth, Host: PUBLIC_HOST, Origin: `https://${PUBLIC_HOST}` });
    expect(status).toBe(403);
    expect((body['error'] as { message: string }).message).toContain('Invalid Origin');
  });
});

describe('wiring host and token helpers', () => {
  afterEach(() => { vi.unstubAllEnvs(); vi.resetModules(); });

  it('derives the hosts a deployment answers on from its origin', async () => {
    const { publicHosts } = await import('../src/lib/wiring.js');
    expect(publicHosts('https://commerce.kya-os.ai')).toEqual([
      'commerce.kya-os.ai', 'commerce.kya-os.ai:443', 'commerce.kya-os.ai:80',
    ]);
    expect(publicHosts('http://localhost:4949')).toEqual(['localhost:4949']);
  });

  it('leaves the admin guard open when no token is configured', async () => {
    vi.stubEnv('ADMIN_TOKEN', '');
    vi.resetModules();
    const { adminTokenOk } = await import('../src/lib/wiring.js');
    expect(adminTokenOk(undefined)).toBe(true);
    expect(adminTokenOk('anything')).toBe(true);
  });

  it('requires an exact match once a token is configured', async () => {
    vi.stubEnv('ADMIN_TOKEN', TOKEN);
    vi.resetModules();
    const { adminTokenOk } = await import('../src/lib/wiring.js');
    expect(adminTokenOk(TOKEN)).toBe(true);
    expect(adminTokenOk(undefined)).toBe(false);
    expect(adminTokenOk('')).toBe(false);
    expect(adminTokenOk(TOKEN.slice(0, -1) + 'X')).toBe(false);
    expect(adminTokenOk(TOKEN + 'extra')).toBe(false);
  });
});
