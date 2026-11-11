import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { NodeCryptoProvider } from '@kya-os/mcp';
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'consent-routes-'));
let app: import('hono').Hono;
let store: import('../src/rp/consent-store.js').ConsentFlowStore;
let binding: import('../src/rp/consent-store.js').ConsentBindings;
let issueModule: typeof import('../src/rp/issue.js');
let identity: import('../src/lib/wiring.js').KeyedIdentity;
function fields(token: string) {
  return {
    tool: 'place_order',
    agent_did: binding.agentDid,
    scopes: JSON.stringify([binding.productClass]),
    selected_scopes: JSON.stringify([binding.productClass]),
    session_id: token,
  };
}
beforeAll(async () => {
  process.env['DEMO_VAR_DIR'] = path.join(tmp, 'var');
  process.env['DEMO_DATA_DIR'] = path.join(tmp, 'data');
  const pair = await new NodeCryptoProvider().generateKeyPair();
  identity = {
    did: 'did:web:localhost%3A4950',
    kid: 'did:web:localhost%3A4950#key-1',
    privateKeyBase64: pair.privateKey,
    publicKeyBase64: pair.publicKey,
  };
  const { ConsentFlowStore } = await import('../src/rp/consent-store.js');
  const { createConsentRoutes } = await import('../src/rp/consent.js');
  issueModule = await import('../src/rp/issue.js');
  store = new ConsentFlowStore({ dir: path.join(tmp, 'consent') });
  binding = {
    agentDid: 'did:key:agent',
    audience: 'did:key:merchant',
    product: 'risotto',
    quantity: 2,
    productClass: 'https://id.gs1.org/01/09506000134352',
    cap: '50.00',
    currency: 'CHF',
    validHours: 48,
    authorizationOrigin: 'http://127.0.0.1:4950',
  };
  app = createConsentRoutes({
    identity,
    statusListUrl: 'http://localhost:4950/status-list',
    agentDid: () => binding.agentDid,
    merchantDid: () => binding.audience,
    store,
    broadcast: () => {},
  });
});
afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));
describe('the RP human issuance ceremony', () => {
  it('serves the real package component with readable first-paint grant details and no-JS approval/denial', async () => {
    const challenge = store.create(binding);
    const response = await app.request(challenge.authorizationUrl);
    const html = await response.text();
    expect(response.status).toBe(200);
    expect(html).toContain('<consent-capabilities-screen');
    expect(html).toContain('customElements');
    expect(html).toContain('09506000134352');
    expect(html).toContain('MaxAmount');
    expect(html).toContain('CHF');
    expect(html).toContain(binding.audience);
    expect(html).toContain(identity.did);
    for (const [, script] of html.matchAll(
      /<script type="module">([\s\S]*?)<\/script>/g,
    )) {
      const parsed = spawnSync(
        process.execPath,
        ['--check', '--input-type=module'],
        { input: script, encoding: 'utf8' },
      );
      expect(parsed.stderr).toBe('');
      expect(parsed.status).toBe(0);
    }
    expect(html).toContain('Approve grant');
    expect(html).toContain('<noscript>');
    expect(html).toContain('/consent/deny');
    expect(html).toContain('type="checkbox" name="selected_scopes"');
    expect(html).toContain('checked required');
    expect(html).toContain('formnovalidate');
    expect(html).not.toContain('loading-skeleton');
  });
  it('rejects tampering of URL bindings and cross-origin approvals', async () => {
    const c = store.create(binding);
    const url = new URL(c.authorizationUrl);
    url.searchParams.set('agent_did', 'did:key:attacker');
    expect((await app.request(url.toString())).status).toBe(400);
    expect(
      (
        await app.request('/consent/approve', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Origin: 'https://attacker.example',
          },
          body: JSON.stringify(fields(c.resumeToken)),
        })
      ).status,
    ).toBe(403);
    expect(issueModule.activeCredentialOrNull()).toBeNull();
  });
  it('denies through FormData without minting and reports terminal status', async () => {
    const c = store.create(binding);
    const form = new FormData();
    for (const [k, v] of Object.entries(fields(c.resumeToken))) form.set(k, v);
    const response = await app.request('/consent/deny', {
      method: 'POST',
      body: form,
    });
    expect(response.status).toBe(200);
    expect(issueModule.activeCredentialOrNull()).toBeNull();
    expect(
      await (
        await app.request(`/consent/status?resume_token=${c.resumeToken}`)
      ).json(),
    ).toMatchObject({ state: 'denied' });
    expect(
      (
        await app.request('/consent/approve', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(fields(c.resumeToken)),
        })
      ).status,
    ).toBe(409);
  });
  it.each([
    undefined, '[]', '["payment.execute"]',
    '["https://id.gs1.org/01/09506000134352","payment.execute"]',
    '["https://id.gs1.org/01/09506000134352","https://id.gs1.org/01/09506000134352"]',
    '[null]', '{',
  ])('does not mint without an explicit valid checked scope selection (%s)', async (selection) => {
    issueModule.clearActiveCredential();
    const challenge = store.create(binding);
    const response = await app.request('/consent/approve', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...fields(challenge.resumeToken), selected_scopes: selection }),
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: 'consent_selection_invalid' });
    expect(issueModule.activeCredentialOrNull()).toBeNull();
    expect(store.get(challenge.resumeToken)?.state).toBe('pending');
    expect(store.get(challenge.resumeToken)?.credentialId).toBeUndefined();
  });
  it.each(['/22/variant', '/'])('rejects a selection that would be broadened by issuer normalization (%s)', async (suffix) => {
    issueModule.clearActiveCredential();
    const selected = binding.productClass + suffix;
    const challenge = store.create({ ...binding, productClass: selected });
    const response = await app.request('/consent/approve', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...fields(challenge.resumeToken), scopes: JSON.stringify([selected]), selected_scopes: JSON.stringify([selected]) }),
    });
    expect(response.status).toBe(400);
    expect(issueModule.activeCredentialOrNull()).toBeNull();
  });
  it('issues the existing RP VC with exact GS1, cap, holder, audience, status and time fields', async () => {
    const c = store.create(binding);
    const form = new URLSearchParams(fields(c.resumeToken));
    const response = await app.request('/consent/approve', {
      method: 'POST',
      body: form,
    });
    expect(response.status).toBe(200);
    const vc = issueModule.activeCredentialOrNull()!;
    expect(vc.type).toContain('DelegationCredential');
    expect(vc.issuer).toBe(identity.did);
    expect(vc.credentialSubject.id).toBe(binding.agentDid);
    const constraints = vc.credentialSubject.delegation.constraints;
    expect(constraints.audience).toBe(binding.audience);
    expect(constraints.crisp?.scopes?.[0]).toMatchObject({
      resource: binding.productClass,
      matcher: 'prefix',
      constraints: { maxAmount: '50.00', currency: 'CHF', per: 'order' },
    });
    expect(Number(constraints.notAfter) - Number(constraints.notBefore)).toBe(
      48 * 3600 + 60,
    );
    expect(vc.credentialStatus).toMatchObject({
      type: 'StatusList2021Entry',
      statusListIndex: '94',
      statusListCredential: 'http://localhost:4950/status-list',
    });
    const approved = store.findByCredential(vc.id!)!;
    expect(approved.state).toBe('approved');
    expect(approved.approvedScopes).toEqual([binding.productClass]);
    expect(approved.auditPayload).toMatchObject({ approvedScopes: [binding.productClass], scope: binding.productClass });
    expect(constraints.crisp?.scopes?.map(scope => scope.resource)).toEqual(approved.approvedScopes);
    expect(store.pendingEvents().find(event => event.type === 'consent.approved' && event.payload['credentialId'] === vc.id)?.payload).toMatchObject({ approvedScopes: approved.approvedScopes });
    expect(
      (
        await app.request('/consent/approve', {
          method: 'POST',
          body: new URLSearchParams(fields(c.resumeToken)),
        })
      ).status,
    ).toBe(409);
  });
  it('preserves committed decisions after the resume window expires while expiring a pending request', async () => {
    const approved = store.create(binding);
    const denied = store.create(binding);
    const pending = store.create(binding);
    for (const [decision, challenge] of [
      ['approve', approved],
      ['deny', denied],
    ] as const) {
      const response = await app.request(`/consent/${decision}`, {
        method: 'POST',
        body: new URLSearchParams(fields(challenge.resumeToken)),
      });
      expect(response.status).toBe(200);
    }
    const now = vi
      .spyOn(Date, 'now')
      .mockReturnValue(
        (Math.max(approved.expiresAt, denied.expiresAt, pending.expiresAt) +
          1) *
          1000,
      );
    try {
      for (const [state, challenge] of [
        ['approved', approved],
        ['denied', denied],
        ['expired', pending],
      ] as const) {
        const response = await app.request(
          `/consent/status?resume_token=${challenge.resumeToken}`,
        );
        expect(response.status).toBe(200);
        const status = await response.json();
        expect(status.state).toBe(state);
        if (state === 'approved') expect(status.credentialId).toBeTruthy();
      }
    } finally {
      now.mockRestore();
    }
  });
  it('fails closed if a configured authenticator store becomes corrupt instead of downgrading to click-wrap', async () => {
    issueModule.clearActiveCredential();
    const { createConsentRoutes } = await import('../src/rp/consent.js');
    const protectedApp = createConsentRoutes({
      identity,
      statusListUrl: 'http://localhost:4950/status-list',
      agentDid: () => binding.agentDid,
      merchantDid: () => binding.audience,
      store,
      broadcast: () => {},
      consentWebauthn: true,
    });
    const file = path.join(tmp, 'data', 'authenticators.json');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, '[');
    const challenge = store.create(binding);
    const response = await protectedApp.request('/consent/approve', {
      method: 'POST',
      body: new URLSearchParams(fields(challenge.resumeToken)),
    });
    expect(response.status).toBe(500);
    expect(issueModule.activeCredentialOrNull()).toBeNull();
    expect(store.get(challenge.resumeToken)?.state).toBe('failed');
    const { createRpApp } = await import('../src/rp/server.js');
    const diagnosticApp = createRpApp({
      identity,
      statusListUrl: 'http://localhost:4950/status-list',
      agentDid: () => binding.agentDid,
      merchantDid: () => binding.audience,
      corsOrigins: [],
      keySetup: false,
      keyWebauthn: false,
      consentWebauthn: false,
      bypassWebauthn: false,
      rpID: 'localhost',
      origin: 'http://localhost:4949',
    });
    const state = await diagnosticApp.request('/api/rp/state');
    expect(state.status).toBe(200);
    expect(await state.json()).toMatchObject({
      keyRequired: false,
      authenticatorStoreError: 'Registered authenticator store is malformed.',
    });
    const defaultChallenge = store.create(binding);
    const clickwrap = await app.request('/consent/approve', {
      method: 'POST',
      body: new URLSearchParams(fields(defaultChallenge.resumeToken)),
    });
    expect(clickwrap.status).toBe(200);
  });
});
