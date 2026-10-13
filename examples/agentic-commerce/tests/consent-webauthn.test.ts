import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'consent-webauthn-'));
const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const id = Buffer.from('workshop-authenticator').toString('base64url');
let ceremonies: import('../src/rp/consent-webauthn.js').ConsentWebauthn;
let flow: import('../src/rp/consent-store.js').ConsentFlow;
let credentialStore: typeof import('../src/rp/key/credential-store.js');
const origin = 'http://localhost:4950';
function assertion(challenge: string, assertedOrigin = origin) {
  const client = Buffer.from(
    JSON.stringify({
      type: 'webauthn.get',
      challenge,
      origin: assertedOrigin,
      crossOrigin: false,
    }),
  );
  const auth = Buffer.concat([
    createHash('sha256').update('localhost').digest(),
    Buffer.from([1]),
    Buffer.from([0, 0, 0, 1]),
  ]);
  const signature = sign(
    'sha256',
    Buffer.concat([auth, createHash('sha256').update(client).digest()]),
    keys.privateKey,
  );
  return {
    id,
    rawId: id,
    type: 'public-key',
    clientExtensionResults: {},
    response: {
      clientDataJSON: client.toString('base64url'),
      authenticatorData: auth.toString('base64url'),
      signature: signature.toString('base64url'),
    },
  };
}
beforeAll(async () => {
  process.env['DEMO_DATA_DIR'] = tmp;
  credentialStore = await import('../src/rp/key/credential-store.js');
  const jwk = keys.publicKey.export({ format: 'jwk' });
  const cose = Buffer.concat([
    Buffer.from('a5010203262001215820', 'hex'),
    Buffer.from(jwk.x!, 'base64url'),
    Buffer.from('225820', 'hex'),
    Buffer.from(jwk.y!, 'base64url'),
  ]);
  credentialStore.saveAuthenticator({
    id,
    publicKey: cose.toString('base64url'),
    counter: 0,
    aaguid: 'test-aaguid',
    label: 'Workshop key',
    registeredAt: new Date().toISOString(),
  });
  const { ConsentWebauthn } = await import('../src/rp/consent-webauthn.js');
  ceremonies = new ConsentWebauthn({ rpID: 'localhost' });
  const { ConsentFlowStore } = await import('../src/rp/consent-store.js');
  const store = new ConsentFlowStore({ dir: path.join(tmp, 'flows') });
  const challenge = store.create({
    agentDid: 'did:key:agent',
    audience: 'did:key:merchant',
    product: 'risotto',
    quantity: 2,
    productClass: 'https://id.gs1.org/01/09506000134352',
    cap: '50.00',
    currency: 'CHF',
    validHours: 48,
  });
  flow = store.get(challenge.resumeToken)!;
});
afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));
describe('issuance intent authenticated by the existing WebAuthn stack', () => {
  it('binds agent, scopes, cap, token and nonce into the authenticator challenge', async () => {
    const request = await ceremonies.challenge(flow, origin);
    expect(request.intent).toMatchObject({
      action: 'issue',
      agentDid: flow.bindings.agentDid,
      scopes: flow.challenge.scopes,
      cap: '50.00',
      currency: 'CHF',
      resumeToken: flow.challenge.resumeToken,
      nonce: request.nonce,
    });
    const { canonicalizeJSON } = await import('@kya-os/mcp');
    expect(request.options.challenge).toBe(
      createHash('sha256')
        .update(canonicalizeJSON(request.intent))
        .digest('base64url'),
    );
  });
  it('rejects an assertion for another origin without issuing or advancing the counter', async () => {
    const request = await ceremonies.challenge(flow, origin);
    await expect(
      ceremonies.verify(
        flow,
        {
          webauthn_nonce: request.nonce,
          webauthn_response: JSON.stringify(
            assertion(request.options.challenge, 'https://attacker.example'),
          ),
        },
        origin,
      ),
    ).rejects.toMatchObject({ code: 'consent_assertion_rejected' });
    expect(credentialStore.findAuthenticator(id)?.counter).toBe(0);
  });
  it('never treats a corrupted registered-key store as an absent authenticator', () => {
    const file = path.join(tmp, 'authenticators.json');
    const original = fs.readFileSync(file, 'utf8');
    for (const bad of ['[', '{}', '[{}]']) {
      fs.writeFileSync(file, bad);
      expect(() => credentialStore.hasAuthenticator()).toThrow();
    }
    fs.writeFileSync(file, original);
    expect(credentialStore.hasAuthenticator()).toBe(true);
  });
  it('rejects a valid assertion if the selected grant scope changes after its challenge', async () => {
    const reviewed = { ...flow, approvedScopes: [flow.bindings.productClass] };
    const request = await ceremonies.challenge(reviewed, origin);
    await expect(ceremonies.verify({ ...reviewed, approvedScopes: ['https://id.gs1.org/01/07612345678901'] }, {
      webauthn_nonce: request.nonce,
      webauthn_response: JSON.stringify(assertion(request.options.challenge)),
    }, origin)).rejects.toMatchObject({ code: 'consent_assertion_mismatch' });
    expect(credentialStore.findAuthenticator(id)?.counter).toBe(0);
  });
  it('verifies a real signed assertion once and retains authenticator identity for audit', async () => {
    const request = await ceremonies.challenge(flow, origin);
    const fields = {
      webauthn_nonce: request.nonce,
      webauthn_response: JSON.stringify(assertion(request.options.challenge)),
    };
    expect(await ceremonies.verify(flow, fields, origin)).toMatchObject({
      method: 'webauthn',
      credentialId: id,
      aaguid: 'test-aaguid',
    });
    expect(credentialStore.findAuthenticator(id)?.counter).toBe(1);
    await expect(ceremonies.verify(flow, fields, origin)).rejects.toMatchObject(
      { code: 'consent_assertion_expired' },
    );
  });
  it('rejects cross-origin or ambiguous key removal before it can downgrade issuance', async () => {
    const { createKeyRoutes } = await import('../src/rp/key/webauthn-routes.js');
    const app = createKeyRoutes({ rpID: 'localhost', origin: 'http://localhost:4949', rpName: 'Test RP', setupEnabled: true, statusListUrl: () => 'http://localhost:4950/status-list', currentIndex: () => 94, performRevoke: async () => { throw new Error('Revoke must not run'); } });
    const malicious = await app.request('/api/rp/key/remove', { method: 'POST', headers: { Origin: 'https://attacker.example', 'Content-Type': 'text/plain' }, body: JSON.stringify({ idTail: id.slice(-6) }) });
    expect(malicious.status).toBe(403); expect(credentialStore.hasAuthenticator()).toBe(true);
    const empty = await app.request('/api/rp/key/remove', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    expect(empty.status).toBe(400); expect(credentialStore.hasAuthenticator()).toBe(true);
    const original = credentialStore.findAuthenticator(id)!;
    credentialStore.saveAuthenticator({ ...original, id: 'second' + id.slice(-6) });
    const ambiguous = await app.request('/api/rp/key/remove', { method: 'POST', headers: { Origin: 'http://localhost:4949', 'Content-Type': 'application/json' }, body: JSON.stringify({ idTail: id.slice(-6) }) });
    expect(ambiguous.status).toBe(409); expect(credentialStore.listAuthenticators()).toHaveLength(2);
    credentialStore.removeAuthenticator('second' + id.slice(-6));
  });

});
