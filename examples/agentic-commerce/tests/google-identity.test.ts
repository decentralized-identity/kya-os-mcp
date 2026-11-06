import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPairSync, sign } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Hono } from 'hono';
import { OAuth2Client } from 'google-auth-library';
import { GoogleIdentity } from '../src/rp/google-identity.js';

const origin = 'http://localhost:4950';
const clientId = 'workshop.apps.googleusercontent.com';
const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const attackerKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const epoch = Date.now();
let now: number;
let dir: string;
let identity: GoogleIdentity;
let app: Hono;
let verifier: OAuth2Client;
function jwt(nonce: string, overrides: Record<string, unknown> = {}, forged = false) {
  const parts = [
    { alg: 'RS256', kid: 'test-key', typ: 'JWT' },
    { iss: 'https://accounts.google.com', sub: 'google-user-1', aud: clientId,
      iat: Math.floor(epoch / 1000) - 10, exp: Math.floor(epoch / 1000) + 3600,
      nonce, name: 'Workshop Human', email: 'human@example.test', email_verified: true, ...overrides },
  ].map(value => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
  return `${parts}.${sign('RSA-SHA256', Buffer.from(parts), forged ? attackerKeys.privateKey : keys.privateKey).toString('base64url')}`;
}
function cookie(response: Response, name: string): string {
  return response.headers.getSetCookie().find(value => value.startsWith(`${name}=`))?.split(';')[0] ?? '';
}
function request(url: string, init?: RequestInit) { return app.request(`${origin}${url}`, init); }
async function login(returnTo = '/setup-key.html') {
  const response = await request(`/auth/login?return_to=${encodeURIComponent(returnTo)}`);
  const loginCookie = cookie(response, 'kya_google_login');
  const options = await request('/auth/google/options', { headers: { Cookie: loginCookie } });
  expect(options.status).toBe(200);
  const body = await options.json() as { nonce: string; clientId: string };
  expect(body.clientId).toBe(clientId);
  return { loginCookie, nonce: body.nonce, response };
}
function verify(loginCookie: string, credential: string, requestOrigin = origin, extras = {}) {
  return request('/auth/google/verify', { method: 'POST', headers: {
    Origin: requestOrigin, Cookie: loginCookie, 'Content-Type': 'application/json',
  }, body: JSON.stringify({ credential, ...extras }) });
}
beforeEach(() => {
  now = epoch;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'google-identity-'));
  verifier = new OAuth2Client(clientId);
  // Only replace Google's certificate transport. The real library validates each JWT signature and claims.
  vi.spyOn(verifier, 'getFederatedSignonCertsAsync').mockResolvedValue({
    certs: { 'test-key': keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() },
    format: 'PEM' as Awaited<ReturnType<OAuth2Client['getFederatedSignonCertsAsync']>>['format'],
  });
  identity = new GoogleIdentity({ clientId, origin, dataDir: dir, now: () => now, verifier });
  app = new Hono().route('/', identity.routes);
  app.get('/private-account', c => c.json(identity.account(c)));
});
afterEach(() => { vi.restoreAllMocks(); fs.rmSync(dir, { recursive: true, force: true }); });

describe('Google account sign-in with real ID-token signature verification', () => {
  it('honestly disables sign-in without a configured client ID', async () => {
    const disabled = new GoogleIdentity({ origin, dataDir: dir });
    expect(disabled.enabled).toBe(false);
    expect(await (await disabled.routes.request(`${origin}/auth/account`)).json()).toEqual({ enabled: false, signedIn: false, account: null });
    expect((await disabled.routes.request(`${origin}/auth/google/options`)).status).toBe(503);
    expect(await (await disabled.routes.request(`${origin}/auth/login`)).text()).toContain('Google sign-in is not configured');
    expect(fs.readdirSync(dir)).toEqual([]);
  });

  it.each(['https://attacker.test/consent', '//attacker.test/consent', '/\\attacker.test/consent', '/consent/../auth/logout', '/setup-key.html?redirect=https://attacker.test', '/consent#fragment', '/other', '/consent\n'])('rejects unsafe return target %j', async target => {
    expect((await request(`/auth/login?return_to=${encodeURIComponent(target)}`)).status).toBe(400);
  });

  it('binds a Google nonce to a private cookie and a server-validated local return target', async () => {
    const start = await login('/consent?resume_token=abc&agent_did=did%3Akey%3Aagent');
    expect(start.response.headers.get('set-cookie')).toMatch(/HttpOnly/i);
    expect(start.response.headers.get('set-cookie')).toMatch(/SameSite=Lax/i);
    expect(start.response.headers.get('Referrer-Policy')).toBe('no-referrer-when-downgrade');
    expect(start.loginCookie).not.toContain(start.nonce);
    expect(start.nonce.length).toBeGreaterThanOrEqual(32);
    const html = await start.response.text();
    expect(html).toContain('https://accounts.google.com/gsi/client');
    expect(html).toContain('google.accounts.id.renderButton');
    expect(html).toContain('nonce: options.nonce');
    expect(html).toContain("window.history.replaceState(null, '', '/auth/login')");
    expect(html.indexOf('window.history.replaceState')).toBeLessThan(html.indexOf("script.src = 'https://accounts.google.com/gsi/client'"));
    const response = await verify(start.loginCookie, jwt(start.nonce), origin, {
      returnTo: 'https://attacker.test', account: { id: 'attacker', name: 'Forged Browser Name' },
    });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({ success: true, returnTo: '/consent?resume_token=abc&agent_did=did%3Akey%3Aagent', account: {
      provider: 'google', issuer: 'https://accounts.google.com', displayName: 'Workshop Human', identitySource: 'identity-provider',
    } });
    expect(body.account.accountRef).toMatch(/^[a-f0-9-]{36}$/);
    expect(JSON.stringify(body)).not.toMatch(/google-user-1|human@example.test|Forged Browser Name/);
    const session = cookie(response, 'kya_human_session');
    expect(session).not.toContain(body.account.accountRef);
    expect(await (await request('/auth/account', { headers: { Cookie: session } })).json()).toEqual({ enabled: true, signedIn: true, account: body.account });
    expect(await (await request('/private-account', { headers: { Cookie: session } })).json()).toMatchObject({
      id: body.account.accountRef, subject: 'google-user-1', email: 'human@example.test', emailVerified: true,
      authenticatedAt: new Date(epoch).toISOString(),
    });
    const file = path.join(dir, 'human-accounts.json');
    expect(fs.readFileSync(file, 'utf8')).not.toContain(jwt(start.nonce));
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  });

  it.each([
    ['wrong audience', { aud: 'attacker.apps.googleusercontent.com' }],
    ['wrong issuer', { iss: 'https://attacker.test' }],
    ['expired token even within library clock skew', { exp: Math.floor(epoch / 1000) - 1 }],
    ['wrong nonce', { nonce: 'unbound-nonce' }],
    ['missing nonce', { nonce: undefined }],
    ['wrong authorized party', { azp: 'attacker.apps.googleusercontent.com' }],
    ['empty subject', { sub: '' }],
  ])('fails closed for %s', async (_label, claims) => {
    const start = await login();
    const response = await verify(start.loginCookie, jwt(start.nonce, claims));
    expect(response.status).toBe(401);
    expect(await response.text()).not.toMatch(/google-user-1|human@example.test|eyJ/);
    expect(cookie(response, 'kya_human_session')).toBe('');
    expect(fs.readdirSync(dir)).toEqual([]);
  });

  it('rejects a forged signature and burns the attempted nonce', async () => {
    const start = await login();
    expect((await verify(start.loginCookie, jwt(start.nonce, {}, true))).status).toBe(401);
    expect((await verify(start.loginCookie, jwt(start.nonce))).status).toBe(401);
  });

  it('keeps the server-bound return target when a failed login is safely reloaded without its query', async () => {
    const start = await login('/consent?resume_token=still-pending');
    expect((await verify(start.loginCookie, jwt(start.nonce, {}, true))).status).toBe(401);
    const reloaded = await request('/auth/login', { headers: { Cookie: start.loginCookie } });
    const nextCookie = cookie(reloaded, 'kya_google_login');
    const next = await (await request('/auth/google/options', { headers: { Cookie: nextCookie } })).json();
    expect(next.nonce).not.toBe(start.nonce);
    const response = await verify(nextCookie, jwt(next.nonce));
    expect(response.status).toBe(200);
    expect((await response.json()).returnTo).toBe('/consent?resume_token=still-pending');
  });

  it('rejects cross-origin, missing-cookie, and cross-browser login attempts', async () => {
    const first = await login(); const second = await login();
    expect((await verify(first.loginCookie, jwt(first.nonce), 'https://attacker.test')).status).toBe(403);
    expect((await verify(first.loginCookie, jwt(first.nonce), 'http://127.0.0.1:4950')).status).toBe(403);
    expect((await verify('', jwt(first.nonce))).status).toBe(401);
    expect((await verify(second.loginCookie, jwt(first.nonce))).status).toBe(401);
    expect((await verify(first.loginCookie, jwt(first.nonce))).status).toBe(200);
  });

  it('consumes each nonce once, including concurrent submissions', async () => {
    const start = await login();
    const token = jwt(start.nonce);
    const attempts = await Promise.all([verify(start.loginCookie, token), verify(start.loginCookie, token)]);
    expect(attempts.map(response => response.status).sort()).toEqual([200, 401]);
    expect((await verify(start.loginCookie, token)).status).toBe(401);
  });

  it('expires abandoned login attempts', async () => {
    const start = await login();
    now += 10 * 60_000;
    expect((await verify(start.loginCookie, jwt(start.nonce))).status).toBe(401);
  });

  it('rejects a nonce that expires while Google certificate verification is in flight', async () => {
    const start = await login();
    const original = verifier.verifyIdToken.bind(verifier);
    vi.spyOn(verifier, 'verifyIdToken').mockImplementation(async options => {
      const ticket = await original(options);
      now += 10 * 60_000;
      return ticket;
    });
    expect((await verify(start.loginCookie, jwt(start.nonce))).status).toBe(401);
  });

  it('does not create a session if logout cancels an in-flight sign-in', async () => {
    const start = await login();
    const original = verifier.verifyIdToken.bind(verifier);
    vi.spyOn(verifier, 'verifyIdToken').mockImplementation(async options => {
      const ticket = await original(options);
      expect((await request('/auth/logout', { method: 'POST', headers: { Origin: origin, Cookie: start.loginCookie } })).status).toBe(200);
      return ticket;
    });
    expect((await verify(start.loginCookie, jwt(start.nonce))).status).toBe(401);
  });

  it('persists issuer-subject identity across restart, without trusting matching names or emails', async () => {
    const first = await login();
    const original = await (await verify(first.loginCookie, jwt(first.nonce))).json();
    identity = new GoogleIdentity({ clientId, origin, dataDir: dir, now: () => now, verifier });
    app = new Hono().route('/', identity.routes);
    const second = await login();
    const renamed = await (await verify(second.loginCookie, jwt(second.nonce, { iss: 'accounts.google.com', name: 'Updated Name', email: 'new@example.test' }))).json();
    expect(renamed.account.accountRef).toBe(original.account.accountRef);
    expect(renamed.account.displayName).toBe('Updated Name');
    const third = await login();
    const other = await (await verify(third.loginCookie, jwt(third.nonce, { sub: 'different-user', name: 'Updated Name', email: 'new@example.test' }))).json();
    expect(other.account.accountRef).not.toBe(original.account.accountRef);
  });

  it('rotates, expires and explicitly destroys sessions without accepting cross-origin logout', async () => {
    const first = await login();
    const session1 = cookie(await verify(first.loginCookie, jwt(first.nonce)), 'kya_human_session');
    const second = await login();
    const session2 = cookie(await verify(`${second.loginCookie}; ${session1}`, jwt(second.nonce)), 'kya_human_session');
    expect(session2).not.toBe(session1);
    expect((await (await request('/auth/account', { headers: { Cookie: session1 } })).json()).signedIn).toBe(false);
    const logout = (requestOrigin: string) => request('/auth/logout', { method: 'POST', headers: { Cookie: session2, Origin: requestOrigin } });
    expect((await logout('https://attacker.test')).status).toBe(403);
    expect((await (await request('/auth/account', { headers: { Cookie: session2 } })).json()).signedIn).toBe(true);
    expect((await logout(origin)).status).toBe(200);
    expect((await (await request('/auth/account', { headers: { Cookie: session2 } })).json()).signedIn).toBe(false);
    const third = await login();
    const session3 = cookie(await verify(third.loginCookie, jwt(third.nonce)), 'kya_human_session');
    now += 2 * 60 * 60_000;
    expect((await (await request('/auth/account', { headers: { Cookie: session3 } })).json()).signedIn).toBe(false);
  });

  it('does not replace malformed persistent identity records with a new identity', () => {
    fs.writeFileSync(path.join(dir, 'human-accounts.json'), '{bad');
    expect(() => new GoogleIdentity({ clientId, origin, dataDir: dir })).toThrow(/account store/i);
  });
});
