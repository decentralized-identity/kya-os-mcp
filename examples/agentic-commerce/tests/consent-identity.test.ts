import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { canonicalizeJSON, NodeCryptoProvider } from '@kya-os/mcp';
import type { HumanAccount } from '../src/rp/human-identity.js';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'consent-account-'));
const account: HumanAccount = { id: 'account-a', provider: 'google', issuer: 'https://accounts.google.com', subject: 'private-google-subject', displayName: 'Alex Example', email: 'alex@example.test', emailVerified: true, authenticatedAt: new Date().toISOString() };
let signedIn: HumanAccount | null = null;
let app: import('hono').Hono;
let store: import('../src/rp/consent-store.js').ConsentFlowStore;
let issue: typeof import('../src/rp/issue.js');
let ceremony: typeof import('../src/rp/consent-webauthn.js').ConsentWebauthn;
let identity: import('../src/lib/wiring.js').KeyedIdentity;
const bindings = { agentDid: 'did:key:agent', audience: 'did:key:merchant', product: 'risotto', quantity: 2, productClass: 'https://id.gs1.org/01/09506000134352', cap: '50.00', currency: 'CHF', validHours: 48, authorizationOrigin: 'http://localhost:4950' };
const fields = (token: string) => ({ tool: 'place_order', agent_did: bindings.agentDid, scopes: JSON.stringify([bindings.productClass]), selected_scopes: JSON.stringify([bindings.productClass]), session_id: token });
const post = (token: string, extra = {}) => app.request('http://localhost:4950/consent/approve', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'http://localhost:4950' }, body: JSON.stringify({ ...fields(token), ...extra }) });

beforeAll(async () => {
  process.env['DEMO_VAR_DIR'] = path.join(tmp, 'var');
  process.env['DEMO_DATA_DIR'] = path.join(tmp, 'data');
  const keys = await new NodeCryptoProvider().generateKeyPair();
  identity = { did: 'did:web:localhost%3A4950', kid: 'did:web:localhost%3A4950#key-1', privateKeyBase64: keys.privateKey, publicKeyBase64: keys.publicKey };
  const { ConsentFlowStore } = await import('../src/rp/consent-store.js');
  const { createConsentRoutes } = await import('../src/rp/consent.js');
  ceremony = (await import('../src/rp/consent-webauthn.js')).ConsentWebauthn;
  issue = await import('../src/rp/issue.js');
  store = new ConsentFlowStore({ dir: path.join(tmp, 'flows') });
  app = createConsentRoutes({ identity, statusListUrl: 'http://localhost:4950/status-list', agentDid: () => bindings.agentDid, merchantDid: () => bindings.audience, store, broadcast: () => {}, consentWebauthn: false, identityAuth: { enabled: true, account: () => signedIn } });
});
afterAll(() => { vi.restoreAllMocks(); fs.rmSync(tmp, { recursive: true, force: true }); });

describe('a named delegation is bound to the signed-in account and its approval', () => {
  it('keeps the profile snapshot authenticated by the passkey when account display data changes', async () => {
    const { buildDemoConsent } = await import('../src/rp/demo-consent.js');
    const { publicHumanAccount } = await import('../src/rp/human-identity.js');
    const link = buildDemoConsent({ ...account, displayName: 'Changed after challenge' }, { method: 'webauthn', credentialId: 'key', intentHash: 'signed-intent', human: publicHumanAccount(account) }, 'token');
    expect(link.human.displayName).toBe('Alex Example');
  });
  it('sends an anonymous human to sign-in and refuses browser-supplied identity', async () => {
    signedIn = null;
    const challenge = store.create(bindings);
    const page = await app.request(challenge.authorizationUrl);
    expect(page.status).toBe(302);
    expect(page.headers.get('location')).toContain('/auth/login?return_to=');
    const response = await post(challenge.resumeToken, { account, oauth_identity: { sub: account.subject, name: account.displayName } });
    expect(response.status).toBe(401);
    expect(issue.activeCredentialOrNull()).toBeNull();
    expect(store.get(challenge.resumeToken)?.state).toBe('pending');
  });

  it('requires a passkey assertion even if the legacy click-wrap flag is off', async () => {
    signedIn = account;
    const challenge = store.create(bindings);
    const response = await post(challenge.resumeToken);
    expect(response.status).not.toBe(200);
    expect(issue.activeCredentialOrNull()).toBeNull();
  });

  it('signs the server-derived human, consent and agent relationship without leaking provider secrets', async () => {
    signedIn = account;
    const { publicHumanAccount } = await import('../src/rp/human-identity.js');
    const authentication = { method: 'webauthn', credentialId: 'registered-key-a', intentHash: 'signed-grant-intent', userVerified: true, human: publicHumanAccount(account) };
    const verify = vi.spyOn(ceremony.prototype, 'verify').mockResolvedValueOnce(authentication);
    const challenge = store.create(bindings);
    const response = await post(challenge.resumeToken, { human: { displayName: 'Impersonated Name' }, webauthn_nonce: 'fixture' });
    expect(response.status).toBe(200);
    expect(verify.mock.calls[0]?.[3]).toEqual(account);
    const vc = issue.activeCredentialOrNull()!;
    const link = vc.credentialSubject.delegation.metadata?.['demoConsent'] as Record<string, unknown>;
    expect(link).toMatchObject({ human: publicHumanAccount(account), authentication: { method: 'webauthn', userVerified: true }, consentRef: expect.stringMatching(/^sha256:/), approvedAt: expect.any(String) });
    expect(vc.credentialSubject.id).toBe(bindings.agentDid);
    const encoded = JSON.stringify(link);
    for (const secret of [account.subject, account.email!, 'registered-key-a', challenge.resumeToken, 'Impersonated Name']) expect(encoded).not.toContain(secret);
    const flow = store.findByCredential(vc.id!)!;
    expect(flow.auditPayload?.['demoConsent']).toEqual(link);
    expect(flow.authentication?.['human']).toEqual(publicHumanAccount(account));
    const { proof, ...unsigned } = vc;
    const crypto = new NodeCryptoProvider();
    expect(await crypto.verify(new TextEncoder().encode(canonicalizeJSON(unsigned)), Buffer.from(proof!.proofValue!, 'base64url'), identity.publicKeyBase64)).toBe(true);
    ((unsigned.credentialSubject.delegation.metadata!['demoConsent'] as { human: { displayName: string } }).human).displayName = 'Another Person';
    expect(await crypto.verify(new TextEncoder().encode(canonicalizeJSON(unsigned)), Buffer.from(proof!.proofValue!, 'base64url'), identity.publicKeyBase64)).toBe(false);
    verify.mockRestore();
  });
});
