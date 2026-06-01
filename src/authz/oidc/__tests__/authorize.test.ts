import { describe, it, expect } from 'vitest';
import { buildAuthorizeUrl } from '../authorize.js';
import { buildAuthorizationServerMetadata, buildProtectedResourceMetadata } from '../metadata.js';
import { verifyS256Challenge, isS256ChallengeMethod } from '../pkce.js';

/**
 * The authorize-URL builder, AS/PR metadata assembly, and PKCE validators are
 * pure: they construct strings and check equality, with no network. They are
 * the deterministic core the reference adapter composes.
 */
describe('buildAuthorizeUrl', () => {
  const base = {
    authorizationEndpoint: 'https://idp.example/authorize',
    clientId: 'agent-client',
    redirectUri: 'https://app.example/callback',
    scopes: ['vault:read', 'openid'],
    state: 'state-123',
    codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  };

  it('builds an authorization-code URL with mandatory S256 PKCE parameters', () => {
    const url = new URL(buildAuthorizeUrl(base));
    expect(url.origin + url.pathname).toBe('https://idp.example/authorize');
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('client_id')).toBe('agent-client');
    expect(url.searchParams.get('redirect_uri')).toBe('https://app.example/callback');
    expect(url.searchParams.get('scope')).toBe('vault:read openid');
    expect(url.searchParams.get('state')).toBe('state-123');
    expect(url.searchParams.get('code_challenge')).toBe(base.codeChallenge);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  });

  it('includes the RFC 8707 resource indicator when given', () => {
    const url = new URL(buildAuthorizeUrl({ ...base, resource: 'https://api.example/mcp' }));
    expect(url.searchParams.get('resource')).toBe('https://api.example/mcp');
  });

  it('omits the resource parameter when not given', () => {
    const url = new URL(buildAuthorizeUrl(base));
    expect(url.searchParams.has('resource')).toBe(false);
  });

  it('rejects a non-S256 challenge method (S256 is mandatory)', () => {
    // @ts-expect-error — plain is intentionally not an accepted method
    expect(() => buildAuthorizeUrl({ ...base, codeChallengeMethod: 'plain' })).toThrow();
  });
});

describe('PKCE S256', () => {
  // Canonical RFC 7636 Appendix B vector.
  const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

  it('isS256ChallengeMethod only accepts S256', () => {
    expect(isS256ChallengeMethod('S256')).toBe(true);
    expect(isS256ChallengeMethod('plain')).toBe(false);
  });

  it('verifies a matching verifier against its S256 challenge', async () => {
    expect(await verifyS256Challenge(verifier, challenge)).toBe(true);
  });

  it('rejects a verifier that does not hash to the challenge', async () => {
    expect(await verifyS256Challenge('wrong-verifier', challenge)).toBe(false);
  });
});

describe('authorization-server metadata', () => {
  it('advertises S256-only PKCE per RFC 8414', () => {
    const meta = buildAuthorizationServerMetadata({
      issuer: 'https://idp.example',
      authorizationEndpoint: 'https://idp.example/authorize',
      tokenEndpoint: 'https://idp.example/token',
      scopesSupported: ['openid', 'vault:read'],
    });
    expect(meta.issuer).toBe('https://idp.example');
    expect(meta.code_challenge_methods_supported).toEqual(['S256']);
    expect(meta.response_types_supported).toContain('code');
    expect(meta.scopes_supported).toContain('vault:read');
  });

  it('builds RFC 9728 protected-resource metadata binding resource to auth servers', () => {
    const meta = buildProtectedResourceMetadata({
      resource: 'https://api.example/mcp',
      authorizationServers: ['https://idp.example'],
    });
    expect(meta.resource).toBe('https://api.example/mcp');
    expect(meta.authorization_servers).toEqual(['https://idp.example']);
  });
});
