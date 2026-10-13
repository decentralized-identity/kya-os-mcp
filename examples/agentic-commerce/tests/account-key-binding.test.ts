import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { HumanAccount } from '../src/rp/human-identity.js';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'account-key-binding-'));
const origin = 'http://localhost:4949';
const consentOrigin = 'http://localhost:4950';
const alice: HumanAccount = {
  id: '00000000-0000-4000-8000-000000000001',
  provider: 'google',
  issuer: 'https://accounts.google.com',
  subject: 'google-alice',
  displayName: 'Alice From Google',
  email: 'alice@example.test',
  emailVerified: true,
  authenticatedAt: new Date().toISOString(),
};
const bob: HumanAccount = {
  ...alice,
  id: '00000000-0000-4000-8000-000000000002',
  subject: 'google-bob',
  displayName: 'Bob From Google',
  email: 'bob@example.test',
};
let current: HumanAccount | null = alice;
let keys: typeof import('../src/rp/key/credential-store.js');
let createKeyRoutes: typeof import('../src/rp/key/webauthn-routes.js').createKeyRoutes;
let ConsentWebauthn: typeof import('../src/rp/consent-webauthn.js').ConsentWebauthn;
let flow: import('../src/rp/consent-store.js').ConsentFlow;
const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const jwk = pair.publicKey.export({ format: 'jwk' });
const cose = Buffer.concat([
  Buffer.from('a5010203262001215820', 'hex'),
  Buffer.from(jwk.x!, 'base64url'),
  Buffer.from('225820', 'hex'),
  Buffer.from(jwk.y!, 'base64url'),
]);
const credId = Buffer.from('account-bound-key').toString('base64url');
function registration(
  challenge: string,
  id = credId,
  registrationOrigin = origin,
) {
  const idBytes = Buffer.from(id, 'base64url');
  const length = Buffer.alloc(2);
  length.writeUInt16BE(idBytes.length);
  const auth = Buffer.concat([
    createHash('sha256').update('localhost').digest(),
    Buffer.from([0x41, 0, 0, 0, 0]),
    Buffer.alloc(16),
    length,
    idBytes,
    cose,
  ]);
  const attestationObject = Buffer.concat([
    Buffer.from(
      'a363666d74646e6f6e656761747453746d74a068617574684461746158',
      'hex',
    ),
    Buffer.from([auth.length]),
    auth,
  ]);
  return {
    id,
    rawId: id,
    type: 'public-key',
    clientExtensionResults: {},
    response: {
      clientDataJSON: Buffer.from(
        JSON.stringify({
          type: 'webauthn.create',
          challenge,
          origin: registrationOrigin,
        }),
      ).toString('base64url'),
      attestationObject: attestationObject.toString('base64url'),
      transports: ['internal'],
    },
  };
}
function assertion(challenge: string, id = credId) {
  const client = Buffer.from(
    JSON.stringify({ type: 'webauthn.get', challenge, origin: consentOrigin }),
  );
  const auth = Buffer.concat([
    createHash('sha256').update('localhost').digest(),
    Buffer.from([1, 0, 0, 0, 1]),
  ]);
  const signature = sign(
    'sha256',
    Buffer.concat([auth, createHash('sha256').update(client).digest()]),
    pair.privateKey,
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
function app(enabled = true, registrationOrigin?: string) {
  return createKeyRoutes({
    rpID: 'localhost',
    origin,
    registrationOrigin,
    rpName: 'Test RP',
    setupEnabled: true,
    statusListUrl: () => 'http://localhost:4950/status-list',
    currentIndex: () => 94,
    performRevoke: async () => {
      throw new Error('No revocation in registration tests');
    },
    identityAuth: { enabled, account: () => current },
  });
}
function request(body: unknown = {}, requestOrigin = origin) {
  return {
    method: 'POST',
    headers: { Origin: requestOrigin, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  };
}
function save(id = credId, accountId?: string) {
  keys.saveAuthenticator({
    id,
    publicKey: cose.toString('base64url'),
    counter: 0,
    label: 'A label is not a human identity',
    registeredAt: new Date().toISOString(),
    ...(accountId ? { accountId } : {}),
  });
}
beforeAll(async () => {
  process.env['DEMO_DATA_DIR'] = path.join(tmp, 'data');
  process.env['DEMO_VAR_DIR'] = path.join(tmp, 'var');
  keys = await import('../src/rp/key/credential-store.js');
  ({ createKeyRoutes } = await import('../src/rp/key/webauthn-routes.js'));
  ({ ConsentWebauthn } = await import('../src/rp/consent-webauthn.js'));
  const { ConsentFlowStore } = await import('../src/rp/consent-store.js');
  const store = new ConsentFlowStore();
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
beforeEach(() => {
  current = alice;
  fs.rmSync(path.join(tmp, 'data'), { recursive: true, force: true });
  vi.restoreAllMocks();
});
afterAll(() => {
  vi.restoreAllMocks();
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('Google account bound registration', () => {
  it('requires a server authenticated account for setup and key visibility', async () => {
    current = null;
    const server = app();
    expect(
      (await server.request('/api/rp/key/register/options', request())).status,
    ).toBe(401);
    expect((await server.request('/api/rp/key/list')).status).toBe(401);
    expect(
      (
        await server.request(
          '/api/rp/key/remove',
          request({ idTail: 'anything' }),
        )
      ).status,
    ).toBe(401);
  });
  it('uses only verified account claims for WebAuthn user identity and persists account ownership', async () => {
    const server = app();
    const response = await server.request(
      '/api/rp/key/register/options',
      request({
        label: 'Forged Bob',
        accountId: bob.id,
        displayName: 'Mallory',
      }),
    );
    const options = await response.json();
    expect(Buffer.from(options.user.id, 'base64url').toString()).toBe(alice.id);
    expect(options.user.name).toBe(alice.displayName);
    expect(options.user.displayName).toBe(alice.displayName);
    expect(keys.listAuthenticators()).toEqual([]);
    expect(
      (
        await server.request(
          '/api/rp/key/register/verify',
          request(registration(options.challenge)),
        )
      ).status,
    ).toBe(200);
    expect(keys.findAuthenticator(credId)).toMatchObject({
      accountId: alice.id,
      label: 'Forged Bob',
    });
  });
  it('keeps the verified account handle stable across enrollment requests and distinct across accounts', async () => {
    const server = app();
    const options = async () =>
      (await server.request('/api/rp/key/register/options', request())).json();
    const first = await options();
    const second = await options();
    expect(first.user.id).toBe(second.user.id);
    expect(Buffer.from(first.user.id, 'base64url').toString()).toBe(alice.id);
    current = bob;
    const other = await options();
    expect(other.user.id).not.toBe(first.user.id);
    expect(Buffer.from(other.user.id, 'base64url').toString()).toBe(bob.id);
  });
  it('rejects account switching and consumes the original pending registration', async () => {
    const server = app();
    const options = await (
      await server.request('/api/rp/key/register/options', request())
    ).json();
    current = bob;
    expect(
      (
        await server.request(
          '/api/rp/key/register/verify',
          request(registration(options.challenge)),
        )
      ).status,
    ).toBe(403);
    current = alice;
    expect(
      (
        await server.request(
          '/api/rp/key/register/verify',
          request(registration(options.challenge)),
        )
      ).status,
    ).toBe(400);
    expect(keys.listAuthenticators()).toEqual([]);
  });
  it('expires pending registration and accepts a valid attestation only once under concurrency', async () => {
    const server = app();
    const now = Date.now();
    const options = await (
      await server.request('/api/rp/key/register/options', request())
    ).json();
    vi.spyOn(Date, 'now').mockReturnValue(now + 121_000);
    expect(
      (
        await server.request(
          '/api/rp/key/register/verify',
          request(registration(options.challenge)),
        )
      ).status,
    ).toBe(400);
    vi.restoreAllMocks();
    const fresh = await (
      await server.request('/api/rp/key/register/options', request())
    ).json();
    const responses = await Promise.all([
      server.request(
        '/api/rp/key/register/verify',
        request(registration(fresh.challenge)),
      ),
      server.request(
        '/api/rp/key/register/verify',
        request(registration(fresh.challenge)),
      ),
    ]);
    expect(responses.map((r) => r.status).sort()).toEqual([200, 400]);
    expect(keys.listAuthenticators()).toHaveLength(1);
  });
  it('allows fresh account enrollment on hardware with legacy or other-account credentials without claiming those keys', async () => {
    save();
    save(Buffer.from('another-account').toString('base64url'), bob.id);
    const server = app();
    const options = await (
      await server.request('/api/rp/key/register/options', request())
    ).json();
    expect(options.excludeCredentials).toEqual([]);
    const freshId = Buffer.from('fresh-alice-credential').toString('base64url');
    expect(
      (
        await server.request(
          '/api/rp/key/register/verify',
          request(registration(options.challenge, freshId)),
        )
      ).status,
    ).toBe(200);
    expect(keys.findAuthenticator(freshId)?.accountId).toBe(alice.id);
    expect(keys.findAuthenticator(credId)?.accountId).toBeUndefined();
  });
  it('never reassigns an existing key ID to another account', async () => {
    save(credId, alice.id);
    current = bob;
    const server = app();
    const options = await (
      await server.request('/api/rp/key/register/options', request())
    ).json();
    expect(
      (
        await server.request(
          '/api/rp/key/register/verify',
          request(registration(options.challenge)),
        )
      ).status,
    ).toBe(409);
    expect(keys.findAuthenticator(credId)?.accountId).toBe(alice.id);
  });
  it('filters key list and removal to the current account and excludes legacy keys', async () => {
    save(credId, alice.id);
    const other = Buffer.from('bob-key').toString('base64url');
    save(other, bob.id);
    save(Buffer.from('legacy').toString('base64url'));
    const server = app();
    const list = await (await server.request('/api/rp/key/list')).json();
    expect(list.authenticators).toHaveLength(1);
    expect(list.authenticators[0].idTail).toBe(credId.slice(-6));
    expect(
      (
        await server.request(
          '/api/rp/key/remove',
          request({ idTail: other.slice(-6) }),
        )
      ).status,
    ).toBe(404);
    expect(keys.findAuthenticator(other)).toBeDefined();
  });
  it('supports an RP registration origin independently from the merchant revocation origin', async () => {
    const server = app(true, consentOrigin);
    expect(
      (await server.request('/api/rp/key/register/options', request())).status,
    ).toBe(403);
    const options = await (
      await server.request(
        '/api/rp/key/register/options',
        request({}, consentOrigin),
      )
    ).json();
    expect(
      (
        await server.request(
          '/api/rp/key/register/verify',
          request(
            registration(options.challenge, credId, consentOrigin),
            consentOrigin,
          ),
        )
      ).status,
    ).toBe(200);
    expect(keys.findAuthenticator(credId)?.accountId).toBe(alice.id);
  });
  it('preserves nameless legacy registration when identity integration is disabled', async () => {
    current = null;
    const server = app(false);
    const options = await (
      await server.request('/api/rp/key/register/options', request())
    ).json();
    expect(options.user.name).toBe('responsible-party');
    expect(
      (
        await server.request(
          '/api/rp/key/register/verify',
          request(registration(options.challenge)),
        )
      ).status,
    ).toBe(200);
    expect(keys.findAuthenticator(credId)?.accountId).toBeUndefined();
  });
  it('uses a fresh opaque user handle for each anonymous enrollment across route instances', async () => {
    current = null;
    const server = app(false);
    const options = [];
    for (const routes of [server, server, app(false)]) {
      options.push(
        await (
          await routes.request('/api/rp/key/register/options', request())
        ).json(),
      );
    }
    expect(new Set(options.map((value) => value.user.id)).size).toBe(3);
    for (const value of options) {
      expect(Buffer.from(value.user.id, 'base64url')).toHaveLength(32);
      expect(value.user.name).toBe('responsible-party');
      expect(value.authenticatorSelection.residentKey).toBe('discouraged');
    }
  });
  it('keeps legacy and newly enrolled anonymous keys usable by credential ID without a user handle', async () => {
    current = null;
    save();
    const server = app(false);
    const registeredIds = [credId];
    const userHandles: string[] = [];
    for (const name of ['anonymous-one', 'anonymous-two']) {
      const id = Buffer.from(name).toString('base64url');
      const options = await (
        await server.request('/api/rp/key/register/options', request())
      ).json();
      expect(
        options.excludeCredentials.map((key: { id: string }) => key.id),
      ).toEqual(registeredIds);
      userHandles.push(options.user.id);
      const response = await server.request(
        '/api/rp/key/register/verify',
        request(registration(options.challenge, id)),
      );
      expect(response.status).toBe(200);
      expect(keys.findAuthenticator(id)?.accountId).toBeUndefined();
      registeredIds.push(id);
    }
    expect(new Set(userHandles).size).toBe(2);
    expect(keys.listAuthenticators().map((key) => key.id)).toEqual(
      registeredIds,
    );
    const ceremony = new ConsentWebauthn({ rpID: 'localhost' });
    for (const id of registeredIds) {
      const challenge = await ceremony.challenge(flow, consentOrigin);
      expect(
        challenge.options.allowCredentials?.map((key) => key.id),
      ).toEqual(registeredIds);
      const authentication = await ceremony.verify(
        flow,
        {
          webauthn_nonce: challenge.nonce,
          webauthn_response: JSON.stringify(
            assertion(challenge.options.challenge, id),
          ),
        },
        consentOrigin,
      );
      expect(authentication.credentialId).toBe(id);
      expect(keys.findAuthenticator(id)?.counter).toBe(1);
    }
  });
});

describe('human account bound issuance assertion', () => {
  it("fails registration-needed if an account has only someone else's or legacy keys", async () => {
    save();
    save(Buffer.from('bob-only').toString('base64url'), bob.id);
    await expect(
      new ConsentWebauthn({ rpID: 'localhost' }).challenge(
        flow,
        consentOrigin,
        alice,
      ),
    ).rejects.toMatchObject({ code: 'consent_register_needed' });
  });
  it('binds the public provider identity into the intent and verifies its own actual signed assertion', async () => {
    save(credId, alice.id);
    save(Buffer.from('bob').toString('base64url'), bob.id);
    const ceremony = new ConsentWebauthn({ rpID: 'localhost' });
    const challenge = await ceremony.challenge(flow, consentOrigin, alice);
    expect(challenge.options.allowCredentials?.map((c) => c.id)).toEqual([
      credId,
    ]);
    expect(challenge.intent.human).toMatchObject({
      accountRef: alice.id,
      displayName: alice.displayName,
      identitySource: 'identity-provider',
    });
    expect(JSON.stringify(challenge.intent)).not.toContain(alice.subject);
    expect(JSON.stringify(challenge.intent)).not.toContain(alice.email);
    const authentication = await ceremony.verify(
      flow,
      {
        webauthn_nonce: challenge.nonce,
        webauthn_response: JSON.stringify(
          assertion(challenge.options.challenge),
        ),
      },
      consentOrigin,
      alice,
    );
    expect(authentication.human).toEqual(challenge.intent.human);
    expect(authentication.human).not.toHaveProperty('label');
  });
  it('rejects a cryptographically valid assertion from another account key', async () => {
    save(credId, alice.id);
    const other = Buffer.from('bob-signer').toString('base64url');
    save(other, bob.id);
    const ceremony = new ConsentWebauthn({ rpID: 'localhost' });
    const challenge = await ceremony.challenge(flow, consentOrigin, alice);
    await expect(
      ceremony.verify(
        flow,
        {
          webauthn_nonce: challenge.nonce,
          webauthn_response: JSON.stringify(
            assertion(challenge.options.challenge, other),
          ),
        },
        consentOrigin,
        alice,
      ),
    ).rejects.toMatchObject({ code: 'consent_assertion_rejected' });
    expect(keys.findAuthenticator(other)?.counter).toBe(0);
  });
  it('requires the same account throughout the ceremony and never upgrades an anonymous intent', async () => {
    save(credId, alice.id);
    const ceremony = new ConsentWebauthn({ rpID: 'localhost' });
    const challenge = await ceremony.challenge(flow, consentOrigin, alice);
    await expect(
      ceremony.verify(
        flow,
        {
          webauthn_nonce: challenge.nonce,
          webauthn_response: JSON.stringify(
            assertion(challenge.options.challenge),
          ),
        },
        consentOrigin,
        bob,
      ),
    ).rejects.toMatchObject({ code: 'consent_assertion_expired' });
    const anonymous = await ceremony.challenge(flow, consentOrigin);
    await expect(
      ceremony.verify(
        flow,
        {
          webauthn_nonce: anonymous.nonce,
          webauthn_response: JSON.stringify(
            assertion(anonymous.options.challenge),
          ),
        },
        consentOrigin,
        alice,
      ),
    ).rejects.toMatchObject({ code: 'consent_assertion_expired' });
  });
});
