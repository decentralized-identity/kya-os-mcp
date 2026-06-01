import { describe, it, expect } from 'vitest';
import {
  requirementMatchesAdapter,
  type AuthorizationServerAdapter,
} from '../adapter.js';
import type { ToolProtection } from '../requirement.js';

/**
 * AuthorizationServerAdapter is the neutral, one-responsibility port: given a
 * tool's protection, decide whether this adapter must run, produce a
 * challenge, and consume the result. `requirementMatchesAdapter` is the shared
 * dispatch predicate every adapter's `isRequired` is built on — exercised here
 * as real runtime code (the interface alone is erased at runtime).
 */

const protect = (toolName: string, requirement: ToolProtection['requirement']): ToolProtection => ({
  toolName,
  requirement,
});

describe('requirementMatchesAdapter', () => {
  it('matches when the protection requirement type equals the adapter type', () => {
    expect(
      requirementMatchesAdapter('oauth', protect('vault.read', { type: 'oauth', provider: 'generic-oidc' })),
    ).toBe(true);
  });

  it('does not match an unprotected tool (type none)', () => {
    expect(requirementMatchesAdapter('oauth', protect('ping', { type: 'none' }))).toBe(false);
  });

  it('does not match when another adapter type owns the requirement', () => {
    expect(requirementMatchesAdapter('oauth', protect('verify.id', { type: 'idv' }))).toBe(false);
  });
});

describe('AuthorizationServerAdapter (contract)', () => {
  it('a conforming adapter wires isRequired to the shared predicate', () => {
    const adapter: AuthorizationServerAdapter = {
      type: 'oauth',
      isRequired: (protection) => requirementMatchesAdapter('oauth', protection),
      async initiateFlow() {
        throw new Error('not exercised in this test');
      },
      async verifyAuthorization() {
        throw new Error('not exercised in this test');
      },
    };
    expect(adapter.type).toBe('oauth');
    expect(adapter.isRequired(protect('vault.read', { type: 'oauth', provider: 'generic-oidc' }))).toBe(true);
    expect(adapter.isRequired(protect('ping', { type: 'none' }))).toBe(false);
  });
});
