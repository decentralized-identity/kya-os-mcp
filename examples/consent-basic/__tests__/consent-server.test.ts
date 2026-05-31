/**
 * Integration Tests: consent-server.ts
 *
 * Validates the HTTP consent server serves the consent page and issues
 * spec-compliant W3C Delegation Credentials on approval.
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

describe('Consent HTTP Server', () => {
  beforeAll(async () => {
    server = await startConsentServer({ port: 0 });
  });

  afterAll(async () => {
    await server.close();
  });

  // GET /consent — page serving
  it('should serve consent.html with query params injected', async () => {
    const res = await request(
      '/consent?tool=checkout&scopes=cart:write&agent_did=did:key:z6MkTest',
    );

    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');

    const body = await res.text();
    expect(body).toContain('checkout');
    expect(body).toContain('cart:write');
    expect(body).toContain('did:key:z6MkTest');
  });

  it('should handle missing query params gracefully', async () => {
    const res = await request('/consent');

    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('unknown');
  });

  // POST /approve — §3.1 compliant VC
  it('should issue a valid delegation VC on approval', async () => {
    const res = await request('/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'checkout',
        scopes: 'cart:write',
        agentDid: 'did:key:z6MkTestAgent',
      }),
    });

    expect(res.status).toBe(200);

    const data = (await res.json()) as { delegationToken: DelegationCredential };
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
    const res = await request('/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'checkout',
        scopes: 'cart:write',
        agentDid,
      }),
    });

    const data = (await res.json()) as { delegationToken: DelegationCredential };
    const vc = data.delegationToken;
    expect(vc.credentialSubject.delegation.subjectDid).toBe(agentDid);
  });

  // §4.2 — 1 hour expiry
  it('should set notAfter to approximately 1 hour from now', async () => {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const res = await request('/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'checkout',
        scopes: 'cart:write',
        agentDid: 'did:key:z6MkExpiryTest',
      }),
    });

    const data = (await res.json()) as { delegationToken: DelegationCredential };
    const vc = data.delegationToken;
    const notAfter = vc.credentialSubject.delegation.constraints.notAfter!;

    // Within 5s tolerance
    expect(notAfter).toBeGreaterThanOrEqual(nowSeconds + 3595);
    expect(notAfter).toBeLessThanOrEqual(nowSeconds + 3605);
  });

  // CORS
  it('should include Access-Control-Allow-Origin header', async () => {
    const res = await request('/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'checkout',
        scopes: 'cart:write',
        agentDid: 'did:key:z6MkCorsTest',
      }),
    });

    expect(res.headers.get('access-control-allow-origin')).toBe('*');
  });

  // 404
  it('should return 404 for unknown routes', async () => {
    const res = await request('/unknown');
    expect(res.status).toBe(404);
  });

  // Multiple scopes
  it('should handle comma-separated scopes', async () => {
    const res = await request('/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'checkout',
        scopes: 'cart:write,cart:read',
        agentDid: 'did:key:z6MkMultiScope',
      }),
    });

    const data = (await res.json()) as { delegationToken: DelegationCredential };
    const vc = data.delegationToken;
    expect(vc.credentialSubject.delegation.constraints.scopes).toEqual(['cart:write', 'cart:read']);
  });

  // Error: malformed JSON
  it('should return 400 for malformed JSON body', async () => {
    const res = await request('/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not-json',
    });

    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe('invalid_request');
  });

  // Error: missing required fields
  it('should return 400 when required fields are missing', async () => {
    const res = await request('/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool: 'checkout' }),
    });

    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe('missing_fields');
  });
});
