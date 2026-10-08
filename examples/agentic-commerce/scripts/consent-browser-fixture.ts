/** Isolated browser-test fixture. Keys and grants live only under DEMO_VAR_DIR. */
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';
import { generateKeyPairSync, sign } from 'node:crypto';
import { OAuth2Client } from 'google-auth-library';

if (!process.env['DEMO_VAR_DIR'] || !process.env['DEMO_DATA_DIR'])
  throw new Error('Browser fixture requires isolated data directories.');
const googleMode = process.env['DEMO_GOOGLE_IDENTITY_TEST'] === '1';
const fixtureClientId = 'isolated-browser-fixture.apps.googleusercontent.com';
const crypto = new NodeCryptoProvider();
const [rp, merchant, agent] = await Promise.all([
  crypto.generateKeyPair(),
  crypto.generateKeyPair(),
  crypto.generateKeyPair(),
]);
const rpDid = `did:web:localhost%3A${process.env['RP_PORT']}`;
Object.assign(process.env, {
  RP_DID: rpDid,
  RP_KID: `${rpDid}#key-1`,
  RP_PRIVATE_KEY_BASE64: rp.privateKey,
  RP_PUBLIC_KEY_BASE64: rp.publicKey,
  MERCHANT_DID: generateDidKeyFromBase64(merchant.publicKey),
  MERCHANT_PRIVATE_KEY_BASE64: merchant.privateKey,
  MERCHANT_PUBLIC_KEY_BASE64: merchant.publicKey,
  AGENT_DID: generateDidKeyFromBase64(agent.publicKey),
  AGENT_ED25519_PRIVATE_KEY_BASE64: agent.privateKey,
  AGENT_ED25519_PUBLIC_KEY_BASE64: agent.publicKey,
  RP_ORIGIN: `http://localhost:${process.env['RP_PORT']}`,
  MERCHANT_ORIGIN: `http://localhost:${process.env['MERCHANT_PORT']}`,
  STATUS_LIST_URL: `http://localhost:${process.env['RP_PORT']}/status-list`,
  RP_DID_MIRROR_URL: `http://localhost:${process.env['RP_PORT']}/.well-known/did.json`,
  WEBAUTHN_ORIGIN: `http://localhost:${process.env['MERCHANT_PORT']}`,
  WEBAUTHN_RP_ID: 'localhost',
  CONSENT_WEBAUTHN: '1',
  KEY_SETUP: '1',
  KEY_WEBAUTHN: process.env['DEMO_PASSKEY_REVOCATION_TEST'] === '1' ? '1' : '0',
  DEMO_BYPASS_WEBAUTHN: '0',
  OFFLINE: '0',
  GOOGLE_CLIENT_ID: googleMode ? fixtureClientId : '',
});
const { startRpServer } = await import('../src/rp/server.js');
const { startMerchantServer } = await import('../src/merchant/server.js');
let identityAuth: import('../src/rp/google-identity.js').GoogleIdentity | undefined;
if (googleMode) {
  const { GoogleIdentity } = await import('../src/rp/google-identity.js');
  const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const verifier = new OAuth2Client(fixtureClientId);
  // This isolated test replaces Google's public-key transport only. Production
  // GoogleIdentity still verifies signature, issuer, audience, lifetime and nonce.
  verifier.getFederatedSignonCertsAsync = async () => ({
    certs: { 'browser-fixture': keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() },
    format: 'PEM' as Awaited<ReturnType<OAuth2Client['getFederatedSignonCertsAsync']>>['format'],
  });
  identityAuth = new GoogleIdentity({ clientId: fixtureClientId, origin: process.env['RP_ORIGIN']!, verifier });
  // Never mounted by src/rp/server.ts. Only this explicit isolated browser-test
  // entrypoint can issue a test token, and the private signing key stays in RAM.
  identityAuth.routes.post('/test/google-token', async c => {
    if (c.req.header('Origin') !== process.env['RP_ORIGIN']) return c.json({ error: 'wrong_origin' }, 403);
    const input = await c.req.json() as { nonce?: unknown };
    if (typeof input.nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(input.nonce)) return c.json({ error: 'invalid_nonce' }, 400);
    const seconds = Math.floor(Date.now() / 1000);
    const parts = [
      { alg: 'RS256', kid: 'browser-fixture', typ: 'JWT' },
      { iss: 'https://accounts.google.com', sub: 'fixture-human-not-a-real-google-account', aud: fixtureClientId,
        iat: seconds, exp: seconds + 3600, nonce: input.nonce, name: 'Workshop Test Human',
        email: 'fictional-human@example.test', email_verified: true },
    ].map(value => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
    return c.json({ credential: `${parts}.${sign('RSA-SHA256', Buffer.from(parts), keys.privateKey).toString('base64url')}` });
  });
}
startRpServer(Number(process.env['RP_PORT']), identityAuth ? { identityAuth } : {});
await startMerchantServer({ port: Number(process.env['MERCHANT_PORT']) });
console.log('BROWSER_FIXTURE_READY');
