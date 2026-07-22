import { describe, expect, it } from 'vitest';
import {
  buildAuthorizationServerMetadata,
  buildProtectedResourceMetadata,
} from '../oidc/metadata.js';

describe('OIDC discovery metadata builders', () => {
  it('applies RFC 8414 defaults and mandates S256 PKCE', () => {
    const metadata = buildAuthorizationServerMetadata({
      issuer: 'https://as.example.com',
      authorizationEndpoint: 'https://as.example.com/authorize',
      tokenEndpoint: 'https://as.example.com/token',
    });
    expect(metadata).toEqual({
      issuer: 'https://as.example.com',
      authorization_endpoint: 'https://as.example.com/authorize',
      token_endpoint: 'https://as.example.com/token',
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
    });
  });

  it('emits optional authorization-server fields only when configured', () => {
    const metadata = buildAuthorizationServerMetadata({
      issuer: 'https://as.example.com',
      authorizationEndpoint: 'https://as.example.com/authorize',
      tokenEndpoint: 'https://as.example.com/token',
      responseTypesSupported: ['code', 'token'],
      grantTypesSupported: ['authorization_code'],
      scopesSupported: ['payments:send'],
      jwksUri: 'https://as.example.com/jwks',
      revocationEndpoint: 'https://as.example.com/revoke',
    });
    expect(metadata.response_types_supported).toEqual(['code', 'token']);
    expect(metadata.grant_types_supported).toEqual(['authorization_code']);
    expect(metadata.scopes_supported).toEqual(['payments:send']);
    expect(metadata.jwks_uri).toBe('https://as.example.com/jwks');
    expect(metadata.revocation_endpoint).toBe('https://as.example.com/revoke');
  });

  it('builds RFC 9728 protected-resource metadata with and without scopes', () => {
    const bare = buildProtectedResourceMetadata({
      resource: 'https://mcp.example.com',
      authorizationServers: ['https://as.example.com'],
    });
    expect(bare).toEqual({
      resource: 'https://mcp.example.com',
      authorization_servers: ['https://as.example.com'],
    });
    const scoped = buildProtectedResourceMetadata({
      resource: 'https://mcp.example.com',
      authorizationServers: ['https://as.example.com'],
      scopesSupported: ['tools:call'],
    });
    expect(scoped.scopes_supported).toEqual(['tools:call']);
  });
});
