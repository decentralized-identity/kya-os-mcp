import { describe, it, expect } from 'vitest';
import {
  AuthorizationRequirementSchema,
  ToolProtectionSchema,
  type AuthorizationRequirement,
} from '../requirement.js';

/**
 * The AuthorizationRequirement union is the neutral description of *what kind*
 * of authorization a tool needs, independent of any concrete authorization
 * server. It is the input vocabulary the AuthorizationServerAdapter dispatches
 * on. These tests pin the discriminants and the fail-closed parsing.
 */
describe('AuthorizationRequirement', () => {
  it('accepts an oauth requirement with provider and optional scopes', () => {
    const parsed = AuthorizationRequirementSchema.parse({
      type: 'oauth',
      provider: 'generic-oidc',
      requiredScopes: ['vault:read'],
    });
    expect(parsed.type).toBe('oauth');
  });

  it('accepts the none requirement (no authorization needed)', () => {
    expect(AuthorizationRequirementSchema.parse({ type: 'none' }).type).toBe('none');
  });

  it.each(['mdl', 'idv', 'credential'])('accepts the %s requirement discriminant', (type) => {
    expect(AuthorizationRequirementSchema.parse({ type }).type).toBe(type);
  });

  it('rejects an unknown discriminant', () => {
    expect(() => AuthorizationRequirementSchema.parse({ type: 'telepathy' })).toThrow();
  });

  it('rejects an oauth requirement missing its provider', () => {
    expect(() => AuthorizationRequirementSchema.parse({ type: 'oauth' })).toThrow();
  });

  it('narrows by discriminant at the type level', () => {
    const req: AuthorizationRequirement = { type: 'oauth', provider: 'generic-oidc' };
    if (req.type === 'oauth') {
      // `provider` is only reachable on the oauth variant — compile-time proof
      // the union discriminates correctly.
      expect(req.provider).toBe('generic-oidc');
    }
  });
});

describe('ToolProtection', () => {
  it('parses a tool protection declaring a required authorization', () => {
    const parsed = ToolProtectionSchema.parse({
      toolName: 'vault.read',
      requirement: { type: 'oauth', provider: 'generic-oidc', requiredScopes: ['vault:read'] },
    });
    expect(parsed.toolName).toBe('vault.read');
    expect(parsed.requirement.type).toBe('oauth');
  });

  it('rejects a tool protection with no tool name', () => {
    expect(() =>
      ToolProtectionSchema.parse({ requirement: { type: 'none' } }),
    ).toThrow();
  });
});
