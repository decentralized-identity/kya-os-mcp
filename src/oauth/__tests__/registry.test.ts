import { describe, it, expect } from 'vitest';
import { AuthorizationServerRegistry } from '../registry.js';
import { GenericOidcAdapter } from '../oidc-adapter.js';
import type { AuthorizationServerAdapter } from '../adapter.js';

/**
 * The registry routes a tool's protection to exactly one adapter by type, with
 * a sealed lifecycle — mirroring the provider-registry pattern so the
 * authorization seam composes the same pluggable way as the policy seam.
 */

const oidc = () =>
  new GenericOidcAdapter({
    type: 'oauth',
    issuer: 'https://idp.example',
    authorizationEndpoint: 'https://idp.example/authorize',
    tokenEndpoint: 'https://idp.example/token',
    clientId: 'agent-client',
    scopes: ['openid'],
  });

describe('AuthorizationServerRegistry', () => {
  it('registers and resolves an adapter by type', () => {
    const registry = new AuthorizationServerRegistry();
    registry.register(oidc());
    expect(registry.get('oauth')?.type).toBe('oauth');
    expect(registry.list().map((a) => a.type)).toEqual(['oauth']);
  });

  it('returns undefined for an unregistered type', () => {
    expect(new AuthorizationServerRegistry().get('idv')).toBeUndefined();
  });

  it('rejects registering two adapters for the same type', () => {
    const registry = new AuthorizationServerRegistry();
    registry.register(oidc());
    expect(() => registry.register(oidc())).toThrow(/already registered/i);
  });

  it('routes a tool protection to the adapter whose type owns it', () => {
    const registry = new AuthorizationServerRegistry();
    registry.register(oidc());
    const adapter = registry.resolve({
      toolName: 'vault.read',
      requirement: { type: 'oauth', provider: 'generic-oidc' },
    });
    expect(adapter?.type).toBe('oauth');
  });

  it('resolves to undefined for an unprotected tool', () => {
    const registry = new AuthorizationServerRegistry();
    registry.register(oidc());
    expect(registry.resolve({ toolName: 'ping', requirement: { type: 'none' } })).toBeUndefined();
  });

  it('seals against further registration', () => {
    const registry = new AuthorizationServerRegistry();
    registry.register(oidc());
    registry.seal();
    expect(registry.isSealed()).toBe(true);
    const another: AuthorizationServerAdapter = { ...oidc(), type: 'idv' } as AuthorizationServerAdapter;
    expect(() => registry.register(another)).toThrow(/sealed/i);
  });
});
