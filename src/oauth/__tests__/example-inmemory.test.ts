import { describe, it, expect } from 'vitest';
import { runInMemoryAuthorizationFlow } from '../examples/inmemory-oidc.js';

/**
 * End-to-end showcase of the authorization seam with zero network: a registry
 * holding the generic-OIDC reference adapter wired to an in-memory token
 * endpoint. Deterministic and CI-safe — it is the reliable demonstration that
 * the pluggable adapter pattern works edge to edge (protect a tool -> resolve
 * an adapter -> challenge -> verify -> delegation outcome -> policy principal).
 */
describe('in-memory OIDC authorization flow', () => {
  it('routes a protected tool through challenge, verification, and a policy principal', async () => {
    const outcome = await runInMemoryAuthorizationFlow({
      toolName: 'vault.read',
      requiredScopes: ['vault:read'],
      agentDid: 'did:key:zAgent',
      accountableAdminDid: 'did:web:org.example:admins:alice',
    });

    // A challenge was produced for the protected tool.
    expect(outcome.challenge.error).toBe('needs_authorization');
    expect(new URL(outcome.challenge.authorizationUrl).searchParams.get('code_challenge_method')).toBe('S256');

    // Verification succeeded through the in-memory token endpoint (no network).
    expect(outcome.result.valid).toBe(true);
    expect(outcome.result.credential?.agent_did).toBe('did:key:zAgent');
    expect(outcome.result.credential?.scopes).toContain('vault:read');

    // The accountability chain reached the policy principal.
    expect(outcome.policyPrincipal.agentDid).toBe('did:key:zAgent');
    expect(outcome.policyPrincipal.responsibleParty).toBe('did:web:org.example:admins:alice');

    // No external network was used.
    expect(outcome.networkCalls).toBe(0);
  });

  it('produces a stable, deterministic result across runs', async () => {
    const a = await runInMemoryAuthorizationFlow({
      toolName: 'vault.read',
      requiredScopes: ['vault:read'],
      agentDid: 'did:key:zAgent',
    });
    const b = await runInMemoryAuthorizationFlow({
      toolName: 'vault.read',
      requiredScopes: ['vault:read'],
      agentDid: 'did:key:zAgent',
    });
    expect(a.result.credential?.scopes).toEqual(b.result.credential?.scopes);
    expect(a.result.valid).toBe(b.result.valid);
  });
});
