import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { serve, type ServerType } from '@hono/node-server';
import { NodeCryptoProvider } from '@kya-os/mcp';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'consent-status-cors-'));
const merchantOrigin = 'http://localhost:4949';
let server: ServerType;
let origin: string;
let statusPath: string;

beforeAll(async () => {
  process.env['DEMO_VAR_DIR'] = path.join(tmp, 'var');
  process.env['DEMO_DATA_DIR'] = path.join(tmp, 'data');
  const [{ createRpApp }, { ConsentFlowStore }] = await Promise.all([
    import('../src/rp/server.js'), import('../src/rp/consent-store.js'),
  ]);
  const pair = await new NodeCryptoProvider().generateKeyPair();
  const app = createRpApp({
    identity: {
      did: 'did:web:localhost%3A4950', kid: 'did:web:localhost%3A4950#key-1',
      privateKeyBase64: pair.privateKey, publicKeyBase64: pair.publicKey,
    },
    statusListUrl: 'http://localhost:4950/status-list',
    agentDid: () => 'did:key:agent', merchantDid: () => 'did:key:merchant',
    corsOrigins: [merchantOrigin], keySetup: false, keyWebauthn: false,
    consentWebauthn: false, bypassWebauthn: false,
    rpID: 'localhost', origin: 'http://localhost:4950',
  });
  const challenge = new ConsentFlowStore().create({
    agentDid: 'did:key:agent', audience: 'did:key:merchant',
    product: 'risotto', quantity: 2,
    productClass: 'https://id.gs1.org/01/09506000134352',
    cap: '50.00', currency: 'CHF', validHours: 48,
    authorizationOrigin: 'http://localhost:4950',
  });
  statusPath = `/consent/status?resume_token=${encodeURIComponent(challenge.resumeToken)}`;
  server = serve({ fetch: app.fetch, port: 0, hostname: '127.0.0.1' });
  if (!server.listening) await new Promise<void>(resolve => server.once('listening', resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  if (server) await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('cross-origin consent status for the merchant monitor', () => {
  it('allows the monitor preflight and pending-status read over HTTP', async () => {
    const preflight = await fetch(origin + statusPath, {
      method: 'OPTIONS', headers: {
        Origin: merchantOrigin, 'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'content-type',
      },
    });
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get('access-control-allow-origin')).toBe(merchantOrigin);
    expect(preflight.headers.get('access-control-allow-methods')?.split(',')).toContain('GET');
    expect(preflight.headers.get('access-control-allow-headers')?.toLowerCase()).toContain('content-type');

    const response = await fetch(origin + statusPath, {
      headers: { Origin: merchantOrigin, 'Content-Type': 'application/json' },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get('access-control-allow-origin')).toBe(merchantOrigin);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await response.json()).toMatchObject({ state: 'pending' });
  });

  it('does not expose the status read to an unconfigured origin', async () => {
    const response = await fetch(origin + statusPath, {
      headers: { Origin: 'https://untrusted.example' },
    });
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
  });

  it.each(['/consent/approve', '/consent/deny', '/consent/webauthn/challenge', '/consent/pickup', '/consent/requests'])(
    'does not extend browser cross-origin access to %s', async route => {
      const response = await fetch(origin + route, {
        method: 'OPTIONS', headers: {
          Origin: merchantOrigin, 'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'content-type',
        },
      });
      expect(response.headers.get('access-control-allow-origin')).toBeNull();
    },
  );
});
