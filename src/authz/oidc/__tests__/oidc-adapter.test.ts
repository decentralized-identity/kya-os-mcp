import { describe, it, expect, vi } from 'vitest';
import { GenericOidcAdapter } from '../oidc-adapter.js';
import { isNeedsAuthorizationError } from '../../../types/protocol.js';
import type { ToolProtection } from '../../requirement.js';

/**
 * The generic-OIDC reference adapter is the in-package implementation of the
 * AuthorizationServerAdapter port (DR-4: no named vendor IdP here). Its pure
 * parts run inline; every IdP HTTP call goes through an injected fetch seam so
 * the adapter is deterministic and testable with no network.
 */

const config = {
  type: 'oauth' as const,
  issuer: 'https://idp.example',
  authorizationEndpoint: 'https://idp.example/authorize',
  tokenEndpoint: 'https://idp.example/token',
  clientId: 'agent-client',
  scopes: ['openid', 'vault:read'],
  resource: 'https://api.example/mcp',
};

const protection: ToolProtection = {
  toolName: 'vault.read',
  requirement: { type: 'oauth', provider: 'generic-oidc', requiredScopes: ['vault:read'] },
};

const flowParams = {
  protection,
  agentDid: 'did:key:zAgent',
  redirectUri: 'https://app.example/callback',
  state: 'state-xyz',
};

describe('GenericOidcAdapter.isRequired', () => {
  it('runs for an oauth-protected tool', () => {
    expect(new GenericOidcAdapter(config).isRequired(protection)).toBe(true);
  });

  it('does not run for an unprotected tool', () => {
    expect(
      new GenericOidcAdapter(config).isRequired({ toolName: 'ping', requirement: { type: 'none' } }),
    ).toBe(false);
  });
});

describe('GenericOidcAdapter.initiateFlow', () => {
  it('produces a needs_authorization challenge with an S256 authorize URL', async () => {
    const adapter = new GenericOidcAdapter(config);
    const challenge = await adapter.initiateFlow(flowParams);

    expect(isNeedsAuthorizationError(challenge)).toBe(true);
    const url = new URL(challenge.authorizationUrl);
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('code_challenge')).toBeTruthy();
    expect(url.searchParams.get('resource')).toBe('https://api.example/mcp');
    expect(url.searchParams.get('state')).toBe('state-xyz');
    expect(challenge.scopes).toContain('vault:read');
    expect(challenge.resumeToken).toBeTruthy();
    expect(challenge.expiresAt).toBeGreaterThan(0);
  });

  it('binds the code_verifier to the resumeToken so the token exchange can complete', async () => {
    const adapter = new GenericOidcAdapter(config);
    const challenge = await adapter.initiateFlow(flowParams);
    // The verifier is retrievable by resumeToken (kept off the wire / not in the URL).
    expect(new URL(challenge.authorizationUrl).searchParams.has('code_verifier')).toBe(false);
    expect(adapter.pendingVerifierFor(challenge.resumeToken)).toBeTruthy();
  });
});

describe('GenericOidcAdapter.verifyAuthorization', () => {
  it('exchanges the code via the injected fetch seam and maps to a delegation result', async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({ access_token: 'at-1', token_type: 'Bearer', scope: 'vault:read' }),
    );
    const adapter = new GenericOidcAdapter({ ...config, fetchImpl });
    const challenge = await adapter.initiateFlow(flowParams);

    const result = await adapter.verifyAuthorization(challenge.resumeToken, {
      code: 'auth-code-1',
      state: 'state-xyz',
    });

    expect(result.valid).toBe(true);
    expect(result.credential?.agent_did).toBe('did:key:zAgent');
    expect(result.credential?.scopes).toContain('vault:read');
    expect(result.credential?.authorization.type).toBe('oauth');
    expect(result.credential?.authorization.provider).toBe('generic-oidc');
    // Token exchange went through the injected seam, never a real network call.
    expect(fetchImpl).toHaveBeenCalledOnce();
    const [calledUrl, init] = fetchImpl.mock.calls[0];
    expect(calledUrl).toBe('https://idp.example/token');
    expect(String(init?.body)).toContain('grant_type=authorization_code');
    expect(String(init?.body)).toContain('code_verifier=');
  });

  it('fails closed when the state does not match the initiated flow', async () => {
    const adapter = new GenericOidcAdapter(config);
    const challenge = await adapter.initiateFlow(flowParams);
    const result = await adapter.verifyAuthorization(challenge.resumeToken, {
      code: 'auth-code-1',
      state: 'WRONG-state',
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/state/i);
  });

  it('fails closed for an unknown resumeToken', async () => {
    const adapter = new GenericOidcAdapter(config);
    const result = await adapter.verifyAuthorization('never-issued', { code: 'x', state: 'y' });
    expect(result.valid).toBe(false);
  });
});

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}
