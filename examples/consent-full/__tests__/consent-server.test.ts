/**
 * Integration Tests: consent-server.ts (powered by @kya-os/consent)
 *
 * Validates the HTTP consent server serves rendered consent pages from
 * @kya-os/consent and issues spec-compliant W3C Delegation Credentials
 * on approval via the /consent/approve endpoint.
 *
 * Spec coverage: §3.1 (VC structure), §4.1 (DelegationRecord),
 *                §4.2 (DelegationConstraints)
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { startConsentServer, type ConsentServer } from '../src/consent-server.js';
import type { DelegationCredential } from '@kya-os/mcp';

let server: ConsentServer;

function request(path: string, options?: RequestInit): Promise<Response> {
  return fetch(`${server.url}${path}`, options);
}

describe('Consent HTTP Server (@kya-os/consent)', () => {
  beforeAll(async () => {
    server = await startConsentServer({ port: 0 });
  });

  afterAll(async () => {
    await server.close();
  });

  // GET /consent — page serving via @kya-os/consent
  it('should serve a consent page with <mcp-consent> component', async () => {
    const res = await request(
      '/consent?tool=checkout&scopes=cart:write&agent_did=did:key:z6MkTest',
    );

    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');

    const body = await res.text();
    // @kya-os/consent generates HTML with <mcp-consent> web component
    expect(body).toContain('<mcp-consent');
    expect(body).toContain('checkout');
    expect(body).toContain('cart:write');
    expect(body).toContain('did:key:z6MkTest');
  });

  it('should include loading skeleton for perceived performance', async () => {
    const res = await request('/consent?tool=checkout&scopes=cart:write&agent_did=did:key:z6MkTest');
    const body = await res.text();
    expect(body).toContain('loading-skeleton');
  });

  it('should include no-JS fallback form', async () => {
    const res = await request('/consent?tool=checkout&scopes=cart:write&agent_did=did:key:z6MkTest');
    const body = await res.text();
    expect(body).toContain('<noscript>');
    expect(body).toContain('consent/approve');
  });

  // GET /consent.js — bundle serving
  it('should serve the consent component bundle', async () => {
    const res = await request('/consent.js');

    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('application/javascript');
    expect(res.headers.get('cache-control')).toContain('public');

    const body = await res.text();
    expect(body.length).toBeGreaterThan(1000); // Bundle should be substantial
  });

  // POST /consent/approve — §3.1 compliant VC (JSON body)
  it('should issue a valid delegation VC on approval', async () => {
    const res = await request('/consent/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'checkout',
        scopes: '["cart:write"]',
        agent_did: 'did:key:z6MkTestAgent',
      }),
    });

    expect(res.status).toBe(200);

    const data = (await res.json()) as {
      success: boolean;
      delegation_id: string;
      delegationToken: DelegationCredential;
    };
    expect(data.success).toBe(true);
    expect(data.delegation_id).toBeDefined();
    expect(data.delegationToken).toBeDefined();

    const vc = data.delegationToken;
    expect(vc.type).toContain('DelegationCredential');
    expect(vc.credentialSubject.delegation.constraints.scopes).toContain('cart:write');
    expect(vc.proof).toBeDefined();
    expect(vc.proof!.type).toBe('Ed25519Signature2020');
  });

  // §4.1 — subjectDid set to requesting agent
  it('should set subjectDid to the requesting agent DID', async () => {
    const agentDid = 'did:key:z6MkSpecificAgent';
    const res = await request('/consent/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'checkout',
        scopes: '["cart:write"]',
        agent_did: agentDid,
      }),
    });

    const data = (await res.json()) as { delegationToken: DelegationCredential };
    const vc = data.delegationToken;
    expect(vc.credentialSubject.delegation.subjectDid).toBe(agentDid);
  });

  // §4.2 — 1 hour expiry
  it('should set notAfter to approximately 1 hour from now', async () => {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const res = await request('/consent/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'checkout',
        scopes: '["cart:write"]',
        agent_did: 'did:key:z6MkExpiryTest',
      }),
    });

    const data = (await res.json()) as { delegationToken: DelegationCredential };
    const vc = data.delegationToken;
    const notAfter = vc.credentialSubject.delegation.constraints.notAfter!;

    expect(notAfter).toBeGreaterThanOrEqual(nowSeconds + 3595);
    expect(notAfter).toBeLessThanOrEqual(nowSeconds + 3605);
  });

  // Comma-separated scopes (backward compat)
  it('should handle comma-separated scopes', async () => {
    const res = await request('/consent/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'checkout',
        scopes: 'cart:write,cart:read',
        agent_did: 'did:key:z6MkMultiScope',
      }),
    });

    const data = (await res.json()) as { delegationToken: DelegationCredential };
    const vc = data.delegationToken;
    expect(vc.credentialSubject.delegation.constraints.scopes).toEqual(['cart:write', 'cart:read']);
  });

  // CORS
  it('should include Access-Control-Allow-Origin header', async () => {
    const res = await request('/consent/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'checkout',
        scopes: '["cart:write"]',
        agent_did: 'did:key:z6MkCorsTest',
      }),
    });

    expect(res.headers.get('access-control-allow-origin')).toBe('*');
  });

  // 404
  it('should return 404 for unknown routes', async () => {
    const res = await request('/unknown');
    expect(res.status).toBe(404);
  });

  // Error: missing required fields
  it('should return 400 when required fields are missing', async () => {
    const res = await request('/consent/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool: 'checkout' }),
    });

    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe('missing_fields');
  });

  // Error: malformed JSON — server-side parse failure
  it('should return 500 for malformed JSON body', async () => {
    const res = await request('/consent/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not-json',
    });

    expect(res.status).toBe(500);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe('internal_error');
  });
});

describe('Consent HTTP Server — credentials mode', () => {
  let credServer: ConsentServer;

  beforeAll(async () => {
    credServer = await startConsentServer({ port: 0, authMode: 'credentials' });
  });

  afterAll(async () => {
    await credServer.close();
  });

  it('should serve consent page with auth-mode="credentials"', async () => {
    const res = await fetch(
      `${credServer.url}/consent?tool=checkout&scopes=cart:write&agent_did=did:key:z6MkTest`,
    );

    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('auth-mode="credentials"');
  });

  it('should reject invalid credentials', async () => {
    const res = await fetch(`${credServer.url}/consent/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'checkout',
        scopes: '["cart:write"]',
        agent_did: 'did:key:z6MkTest',
        auth_mode: 'credentials',
        username: 'wrong',
        password: 'wrong',
      }),
    });

    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe('invalid_credentials');
  });

  it('should issue delegation with valid credentials', async () => {
    const res = await fetch(`${credServer.url}/consent/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'checkout',
        scopes: '["cart:write"]',
        agent_did: 'did:key:z6MkTest',
        auth_mode: 'credentials',
        username: 'demo',
        password: 'demo123',
      }),
    });

    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      success: boolean;
      delegationToken: DelegationCredential;
    };
    expect(data.success).toBe(true);
    expect(data.delegationToken.type).toContain('DelegationCredential');
  });
});
