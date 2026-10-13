import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPairSync, sign } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { request as httpRequest } from 'node:http';
import type { AddressInfo } from 'node:net';
import { serve, type ServerType } from '@hono/node-server';
import { Hono } from 'hono';
import { OAuth2Client } from 'google-auth-library';
import { GoogleIdentity } from '../src/rp/google-identity.js';

const origin = 'https://auth.workshop.example';
const hostname = new URL(origin).host;
const clientId = 'workshop.apps.googleusercontent.com';
const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
let dir: string;
let server: ServerType;
let listener: string;

function credential(nonce: string) {
  const now = Math.floor(Date.now() / 1000);
  const input = [
    { alg: 'RS256', kid: 'proxy-test-key', typ: 'JWT' },
    { iss: 'https://accounts.google.com', sub: 'proxy-human', aud: clientId,
      iat: now - 10, exp: now + 3600, nonce, name: 'Workshop Human' },
  ].map(value => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
  return `${input}.${sign('RSA-SHA256', Buffer.from(input), keys.privateKey).toString('base64url')}`;
}

function cookie(response: Response, name: string) {
  return response.headers.getSetCookie().find(value => value.startsWith(`${name}=`))?.split(';')[0] ?? '';
}

function request(route: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (!headers.has('Host')) headers.set('Host', hostname);
  // The public HTTPS proxy forwards HTTP to Hono while retaining the public Host.
  // node:http preserves Host, whereas browser-compatible fetch may override it.
  return new Promise((resolve, reject) => {
    const req = httpRequest(listener + route, { method: init.method ?? 'GET', headers: Object.fromEntries(headers) }, res => {
      const chunks: Buffer[] = [];
      res.on('data', chunk => chunks.push(Buffer.from(chunk)));
      res.on('error', reject);
      res.on('end', () => {
        const responseHeaders = new Headers();
        for (let i = 0; i < res.rawHeaders.length; i += 2) {
          responseHeaders.append(res.rawHeaders[i]!, res.rawHeaders[i + 1]!);
        }
        resolve(new Response(Buffer.concat(chunks), { status: res.statusCode, headers: responseHeaders }));
      });
    });
    req.on('error', reject);
    req.end(init.body);
  });
}

async function beginLogin() {
  const start = await request('/auth/login?return_to=%2Fconsent%3Fresume_token%3Dpending');
  expect(start.status).toBe(200);
  expect(start.headers.getSetCookie().join(';')).toMatch(/; Secure/i);
  const loginCookie = cookie(start, 'kya_google_login');
  expect(loginCookie).not.toBe('');
  const options = await request('/auth/google/options', { headers: { Cookie: loginCookie } });
  expect(options.status).toBe(200);
  const body = await options.json();
  expect(body.clientId).toBe(clientId);
  return { loginCookie, nonce: body.nonce as string };
}

beforeEach(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'google-proxy-'));
  const verifier = new OAuth2Client(clientId);
  // Only the certificate transport is replaced. GoogleAuth verifies the signed JWT.
  vi.spyOn(verifier, 'getFederatedSignonCertsAsync').mockResolvedValue({
    certs: { 'proxy-test-key': keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() },
    format: 'PEM' as Awaited<ReturnType<OAuth2Client['getFederatedSignonCertsAsync']>>['format'],
  });
  const identity = new GoogleIdentity({ clientId, origin, dataDir: dir, verifier });
  const app = new Hono().route('/', identity.routes);
  // Consent and passkey registration consume account() outside the /auth middleware.
  app.get('/consent-account', c => c.json({ account: identity.account(c), requestUrl: c.req.url }));
  server = serve({ fetch: app.fetch, port: 0, hostname: '127.0.0.1' });
  if (!server.listening) await new Promise<void>(resolve => server.once('listening', resolve));
  listener = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  if (server) await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  vi.restoreAllMocks();
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('Google sign-in behind an HTTPS-terminating proxy', () => {
  it('signs in over HTTP forwarding and preserves the account for consent with secure cookies', async () => {
    const { loginCookie, nonce } = await beginLogin();
    const verified = await request('/auth/google/verify', {
      method: 'POST', headers: { Cookie: loginCookie, Origin: origin, 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential: credential(nonce) }),
    });
    expect(verified.status).toBe(200);
    expect(await verified.json()).toMatchObject({ success: true, returnTo: '/consent?resume_token=pending',
      account: { displayName: 'Workshop Human' } });
    const cookies = verified.headers.getSetCookie();
    expect(cookies.find(value => value.startsWith('kya_human_session='))).toMatch(/; Secure/i);
    expect(cookies.find(value => value.startsWith('kya_human_session='))).toMatch(/; HttpOnly/i);
    const session = cookie(verified, 'kya_human_session');
    const account = await request('/auth/account', { headers: { Cookie: session } });
    expect(account.status).toBe(200);
    expect(await account.json()).toMatchObject({ signedIn: true, account: { displayName: 'Workshop Human' } });
    const consent = await request('/consent-account', { headers: { Cookie: session } });
    expect(await consent.json()).toMatchObject({ account: { subject: 'proxy-human' },
      requestUrl: `http://${hostname}/consent-account` });
    const spoofed = await request('/consent-account', {
      headers: { Cookie: session, Host: 'attacker.example', 'X-Forwarded-Host': hostname, 'X-Forwarded-Proto': 'https' },
    });
    expect((await spoofed.json()).account).toBeNull();
  });

  it.each([undefined, 'http://auth.workshop.example', 'https://attacker.example'])(
    'rejects an absent or mismatched browser Origin (%s) without consuming the login', async browserOrigin => {
      const { loginCookie, nonce } = await beginLogin();
      const headers = new Headers({ Cookie: loginCookie, 'Content-Type': 'application/json' });
      if (browserOrigin) headers.set('Origin', browserOrigin);
      const rejected = await request('/auth/google/verify', {
        method: 'POST', headers, body: JSON.stringify({ credential: credential(nonce) }),
      });
      expect(rejected.status).toBe(403);
      expect(await rejected.json()).toEqual({ error: 'wrong_origin' });
      expect(cookie(rejected, 'kya_human_session')).toBe('');
      expect((await request('/auth/google/options', { headers: { Cookie: loginCookie } })).status).toBe(200);
    },
  );

  it.each(['attacker.example', `${hostname}:8080`])('rejects a different Host %s despite spoofed forwarding headers', async host => {
    const response = await request('/auth/login', {
      headers: { Host: host, 'X-Forwarded-Host': hostname, 'X-Forwarded-Proto': 'https', Origin: origin },
    });
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: 'wrong_origin' });
    expect(cookie(response, 'kya_google_login')).toBe('');
  });
});
