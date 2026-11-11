import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { NodeCryptoProvider } from '@kya-os/mcp';
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hosted-consent-'));
const origin = 'https://authorization.example', rpID = 'authorization.example', internal = 'http://rp.internal:4950';
const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const id = Buffer.from('hosted-authenticator').toString('base64url');
const bindings = { agentDid: 'did:key:agent', audience: 'did:key:merchant', product: 'risotto', quantity: 2,
  productClass: 'https://id.gs1.org/01/09506000134352', cap: '50.00', currency: 'CHF', validHours: 48, authorizationOrigin: origin };
let routes: typeof import('../src/rp/consent.js');
let stores: typeof import('../src/rp/consent-store.js');
let credentials: typeof import('../src/rp/key/credential-store.js');
let issuance: typeof import('../src/rp/issue.js');
let identity: import('../src/lib/wiring.js').KeyedIdentity;
let count = 0;
const fields = (token: string) => ({ tool: 'place_order', agent_did: bindings.agentDid, scopes: JSON.stringify([bindings.productClass]), selected_scopes: JSON.stringify([bindings.productClass]), session_id: token });
function assertion(challenge: string, assertedOrigin = origin, assertedRpID = rpID) {
  const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: assertedOrigin, crossOrigin: false }));
  const auth = Buffer.concat([createHash('sha256').update(assertedRpID).digest(), Buffer.from([1, 0, 0, 0, 1])]);
  return { id, rawId: id, type: 'public-key', clientExtensionResults: {}, response: {
    clientDataJSON: client.toString('base64url'), authenticatorData: auth.toString('base64url'),
    signature: sign('sha256', Buffer.concat([auth, createHash('sha256').update(client).digest()]), keys.privateKey).toString('base64url'),
  } };
}
function fixture(publicOrigin = origin, configuredRpID = rpID) {
  // Persisted public challenge exercises proxy routes independently of creation.
  const store = new stores.ConsentFlowStore({ dir: path.join(tmp, `flows-${count++}`), authorizationOrigin: publicOrigin });
  const challenge = { error: 'needs_authorization', message: 'Human approval required', resumeToken: 'a'.repeat(43),
    authorizationUrl: `${publicOrigin}/consent?${new URLSearchParams({ resume_token: 'a'.repeat(43), agent_did: bindings.agentDid, scopes: bindings.productClass, tool: 'place_order' })}`,
    expiresAt: Math.floor(Date.now() / 1000) + 600, scopes: [bindings.productClass] };
  fs.mkdirSync(store.dir, { recursive: true });
  fs.writeFileSync(path.join(store.dir, 'flows.json'), JSON.stringify({ flows: { [challenge.resumeToken]: { challenge, bindings: { ...bindings, authorizationOrigin: publicOrigin }, state: 'pending', createdAt: new Date().toISOString() } }, events: [] }));
  const app = routes.createConsentRoutes({ identity, statusListUrl: `${publicOrigin}/status-list`, authorizationOrigin: publicOrigin,
    rpID: configuredRpID, agentDid: () => bindings.agentDid, merchantDid: () => bindings.audience, store, broadcast: () => {}, consentWebauthn: true });
  const post = (endpoint: string, body: object, requestOrigin = publicOrigin, extra: Record<string, string> = {}) => app.request(`${internal}${endpoint}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: requestOrigin, ...extra }, body: JSON.stringify(body) });
  return { app, store, challenge, post };
}
beforeAll(async () => {
  vi.stubEnv('DEMO_ENV_FILE', '/dev/null'); vi.stubEnv('DEMO_VAR_DIR', path.join(tmp, 'var')); vi.stubEnv('DEMO_DATA_DIR', path.join(tmp, 'keys')); vi.stubEnv('WEBAUTHN_RP_ID', rpID);
  const pair = await new NodeCryptoProvider().generateKeyPair();
  identity = { did: `did:web:${rpID}`, kid: `did:web:${rpID}#key-1`, privateKeyBase64: pair.privateKey, publicKeyBase64: pair.publicKey };
  stores = await import('../src/rp/consent-store.js'); routes = await import('../src/rp/consent.js');
  credentials = await import('../src/rp/key/credential-store.js'); issuance = await import('../src/rp/issue.js');
});
beforeEach(() => {
  issuance.clearActiveCredential();
  const jwk = keys.publicKey.export({ format: 'jwk' });
  const cose = Buffer.concat([Buffer.from('a5010203262001215820', 'hex'), Buffer.from(jwk.x!, 'base64url'), Buffer.from('225820', 'hex'), Buffer.from(jwk.y!, 'base64url')]);
  credentials.saveAuthenticator({ id, publicKey: cose.toString('base64url'), counter: 0, label: 'Hosted key', registeredAt: new Date().toISOString() });
});
afterAll(() => { vi.unstubAllEnvs(); fs.rmSync(tmp, { recursive: true, force: true }); });
describe('public HTTPS authorization behind an HTTP reverse proxy', () => {
  it('creates a challenge only at its configured public origin', () => {
    const store = new stores.ConsentFlowStore({ dir: path.join(tmp, `create-${count++}`), authorizationOrigin: origin });
    expect(new URL(store.create(bindings).authorizationUrl).origin).toBe(origin);
    expect(new URL(store.create({ ...bindings, authorizationOrigin: undefined }).authorizationUrl).origin).toBe(origin);
    for (const bad of ['https://attacker.example', 'http://authorization.example', 'http://localhost:4950', `${origin}/unexpected`, `${origin}?redirect=1`, 'https://user:password@authorization.example']) {
      expect(() => store.create({ ...bindings, authorizationOrigin: bad })).toThrow();
    }
  });
  it('renders public links even when the request URL is internal HTTP', async () => {
    const f = fixture(), url = new URL(f.challenge.authorizationUrl);
    const response = await f.app.request(internal + url.pathname + url.search);
    expect(response.status).toBe(200);
    const html = await response.text();
    expect(html).toContain(`action="${origin}/consent/approve"`); expect(html).not.toContain(internal);
  });
  it('verifies a real public-origin passkey assertion through the proxy', async () => {
    const f = fixture(), form = fields(f.challenge.resumeToken);
    const challenge = await f.post('/consent/webauthn/challenge', form);
    expect(challenge.status).toBe(200);
    const ceremony = await challenge.json();
    const approved = await f.post('/consent/approve', { ...form, webauthn_nonce: ceremony.nonce, webauthn_response: JSON.stringify(assertion(ceremony.options.challenge)) });
    expect(approved.status).toBe(200); expect(f.store.get(f.challenge.resumeToken)?.state).toBe('approved');
    expect(issuance.activeCredentialOrNull()?.issuer).toBe(identity.did); expect(credentials.findAuthenticator(id)?.counter).toBe(1);
  });
  it.each(['https://commerce.example', 'https://auth.commerce.example'])('verifies a real assertion with the shared parent RP ID on %s', async publicOrigin => {
    const sharedRpID = 'commerce.example';
    const f = fixture(publicOrigin, sharedRpID), form = fields(f.challenge.resumeToken);
    const response = await f.post('/consent/webauthn/challenge', form);
    expect(response.status).toBe(200);
    const ceremony = await response.json();
    expect(ceremony.options.rpId).toBe(sharedRpID);
    const approved = await f.post('/consent/approve', { ...form, webauthn_nonce: ceremony.nonce,
      webauthn_response: JSON.stringify(assertion(ceremony.options.challenge, publicOrigin, sharedRpID)) });
    expect(approved.status).toBe(200);
    expect(f.store.get(f.challenge.resumeToken)?.state).toBe('approved');
    expect(credentials.findAuthenticator(id)?.counter).toBe(1);
  });
  it.each(['https://notcommerce.example', 'https://commerce.example.attacker.test'])('rejects an RP ID without a complete hostname boundary on %s', async publicOrigin => {
    const f = fixture(publicOrigin, 'commerce.example');
    const response = await f.post('/consent/webauthn/challenge', fields(f.challenge.resumeToken));
    expect(await response.json()).toMatchObject({ error: 'consent_origin_mismatch' });
    expect(issuance.activeCredentialOrNull()).toBeNull();
  });
  it.each([
    { assertedOrigin: 'https://commerce.example', assertedRpID: 'commerce.example' },
    { assertedOrigin: 'https://auth.commerce.example', assertedRpID: 'auth.commerce.example' },
  ])('still binds the assertion to the exact public origin and configured RP ID: $assertedOrigin / $assertedRpID', async ({ assertedOrigin, assertedRpID }) => {
    const f = fixture('https://auth.commerce.example', 'commerce.example'), form = fields(f.challenge.resumeToken);
    const response = await f.post('/consent/webauthn/challenge', form);
    expect(response.status).toBe(200);
    const ceremony = await response.json();
    const approved = await f.post('/consent/approve', { ...form, webauthn_nonce: ceremony.nonce,
      webauthn_response: JSON.stringify(assertion(ceremony.options.challenge, assertedOrigin, assertedRpID)) });
    expect(await approved.json()).toMatchObject({ error: 'consent_assertion_rejected' });
    expect(issuance.activeCredentialOrNull()).toBeNull();
    expect(credentials.findAuthenticator(id)?.counter).toBe(0);
  });
  it.each([internal, 'https://attacker.example', 'null'])('rejects forged browser origin %s despite proxy headers', async (requestOrigin) => {
    const f = fixture();
    const response = await f.post('/consent/deny', fields(f.challenge.resumeToken), requestOrigin, { 'X-Forwarded-Host': rpID, 'X-Forwarded-Proto': 'https' });
    expect(response.status).toBe(403); expect(f.store.get(f.challenge.resumeToken)?.state).toBe('pending'); expect(issuance.activeCredentialOrNull()).toBeNull();
  });
  it('rejects an internal-origin assertion even with the correct HTTP Origin header', async () => {
    const f = fixture(), form = fields(f.challenge.resumeToken);
    const request = await f.post('/consent/webauthn/challenge', form);
    expect(request.status).toBe(200);
    const ceremony = await request.json();
    const response = await f.post('/consent/approve', { ...form, webauthn_nonce: ceremony.nonce, webauthn_response: JSON.stringify(assertion(ceremony.options.challenge, internal)) });
    expect(await response.json()).toMatchObject({ error: 'consent_assertion_rejected' });
    expect(issuance.activeCredentialOrNull()).toBeNull(); expect(credentials.findAuthenticator(id)?.counter).toBe(0);
  });
});
