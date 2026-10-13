import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import type { Server } from 'node:http';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'commerce-deployment-'));
const servers: Server[] = [];
let rp: typeof import('../src/rp/server.js');
let merchant: typeof import('../src/merchant/server.js');
beforeAll(async () => {
  const keys = await new NodeCryptoProvider().generateKeyPair();
  const did = generateDidKeyFromBase64(keys.publicKey);
  for (const [name, value] of Object.entries({
    DEMO_VAR_DIR: path.join(directory, 'var'), DEMO_DATA_DIR: path.join(directory, 'data'), DEMO_ENV_FILE: path.join(directory, 'missing.env'),
    RP_DID: 'did:web:auth.workshop.example', RP_KID: 'did:web:auth.workshop.example#key-1', RP_PRIVATE_KEY_BASE64: keys.privateKey, RP_PUBLIC_KEY_BASE64: keys.publicKey,
    MERCHANT_DID: did, MERCHANT_PRIVATE_KEY_BASE64: keys.privateKey, MERCHANT_PUBLIC_KEY_BASE64: keys.publicKey,
    RP_ORIGIN: 'https://auth.workshop.example', MERCHANT_ORIGIN: 'https://merchant.workshop.example', STATUS_LIST_URL: 'https://status.workshop.example/status-list',
    COMMERCE_PAYMENTS: '0', KEY_SETUP: '0', KEY_WEBAUTHN: '0', CONSENT_WEBAUTHN: '0', AUDIT_WITNESS: '0', GOOGLE_CLIENT_ID: '',
    WEBAUTHN_ORIGIN: 'https://merchant.workshop.example', WEBAUTHN_RP_ID: 'workshop.example',
  })) vi.stubEnv(name, value);
  rp = await import('../src/rp/server.js');
  merchant = await import('../src/merchant/server.js');
});
beforeEach(() => {
  vi.stubEnv('BIND_HOST', undefined);
  vi.stubEnv('RP_ORIGIN', 'https://auth.workshop.example');
});
afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()))));
});
afterAll(() => { vi.unstubAllEnvs(); fs.rmSync(directory, { recursive: true, force: true }); });

describe('public deployment configuration', () => {
  it('uses the configured RP origin for Google sign-in and CORS while retaining merchant revocation origin', () => {
    const config = rp.rpConfigFromEnv();
    expect(config.googleOrigin).toBe('https://auth.workshop.example');
    expect(config.authorizationOrigin).toBe('https://auth.workshop.example');
    expect(config.corsOrigins).toContain('https://auth.workshop.example');
    expect(config.corsOrigins).toContain('https://merchant.workshop.example');
    expect(config.origin).toBe('https://merchant.workshop.example');
    expect(config.rpID).toBe('workshop.example');
  });

  it('creates and renders consent on the RP host even when status is hosted elsewhere and passkeys are disabled', async () => {
    const { signMessage } = await import('../src/lib/consent-protocol.js');
    const { loadMerchantIdentity } = await import('../src/lib/wiring.js');
    const identity = loadMerchantIdentity();
    const config = rp.rpConfigFromEnv({ agentDid: () => identity.did });
    expect(config.statusListUrl).toBe('https://status.workshop.example/status-list');
    expect(config.consentWebauthn).toBe(false);
    const app = rp.createRpApp(config);
    const order = { product: 'risotto', quantity: 2 };
    const proof = (await signMessage('place_order', order, identity, identity.did)).proof;
    const message = await signMessage('consent.create', {
      bindings: { agentDid: identity.did, audience: identity.did, ...order,
        productClass: 'https://id.gs1.org/01/09506000134352', cap: '50.00', currency: 'CHF', validHours: 48 },
      agentRequest: { ...order, _kyaos_proof: proof },
    }, identity, config.identity.did);
    const response = await app.request('http://rp.internal:4950/consent/requests', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(message),
    });
    expect(response.status).toBe(200);
    const result = await response.json();
    const consentUrl = new URL(result.body.challenge.authorizationUrl);
    expect(consentUrl.origin).toBe('https://auth.workshop.example');
    const page = await app.request('http://rp.internal:4950' + consentUrl.pathname + consentUrl.search);
    expect(page.status).toBe(200);
    expect(await page.text()).toContain('action="https://auth.workshop.example/consent/approve"');
  });

  it.each(['https://auth.workshop.example/unexpected', 'https://name:password@auth.workshop.example'])('rejects unsafe RP origin configuration %s', origin => {
    vi.stubEnv('RP_ORIGIN', origin);
    expect(() => rp.rpConfigFromEnv()).toThrow('Use an HTTPS origin');
  });

  it.each([undefined, '0.0.0.0'])('binds both real listeners to %s with loopback as the default', async hostname => {
    vi.stubEnv('BIND_HOST', hostname);
    const responsibleParty = rp.startRpServer(0);
    servers.push(responsibleParty.server as Server);
    if (!responsibleParty.server.listening) await once(responsibleParty.server, 'listening');
    const edge = await merchant.startMerchantServer({ port: 0 });
    servers.push(edge.httpServer);
    const expected = hostname ?? '127.0.0.1';
    expect(responsibleParty.server.address()).toMatchObject({ address: expected });
    expect(edge.httpServer.address()).toMatchObject({ address: expected });
  });
});
