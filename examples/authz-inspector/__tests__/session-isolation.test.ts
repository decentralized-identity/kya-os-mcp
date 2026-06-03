/**
 * The security property that distinguishes this demo from a tool-name-keyed
 * lookup: an approved grant is bound to the SESSION that initiated it, so one
 * session can never auto-apply another session's approval.
 *
 * This is the confused-deputy-shaped selection bug avoided: authority is bound
 * to the caller's session, not selected by ambient context (the tool name).
 */
import { describe, it, expect } from 'vitest';
import { createAuthzSession, READ_VAULT_PROTECTION } from '../src/session.js';
import { createDemoAuthServer } from '../src/auth-server.js';

function harness() {
  const authServer = createDemoAuthServer();
  const tokenEndpoint = 'http://as.local/token';
  const session = createAuthzSession({
    issuer: 'http://as.local',
    authorizationEndpoint: 'http://as.local/authorize',
    tokenEndpoint,
    clientId: 'demo',
    scopes: ['vault:read'],
    resource: 'http://rs.local/vault',
    fetchImpl: async (url, init) => {
      if (url !== tokenEndpoint) throw new Error(`unexpected ${url}`);
      const form = new URLSearchParams(String(init?.body ?? ''));
      const token = await authServer.exchangeToken({
        grant_type: 'authorization_code',
        code: form.get('code') ?? '',
        redirect_uri: form.get('redirect_uri') ?? '',
        client_id: form.get('client_id') ?? '',
        code_verifier: form.get('code_verifier') ?? '',
      });
      return new Response(JSON.stringify(token), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });

  async function approveFlow(authorizeUrl: string): Promise<{ code: string; state: string }> {
    const p = new URL(authorizeUrl).searchParams;
    const { code } = authServer.approve({
      clientId: p.get('client_id')!, redirectUri: p.get('redirect_uri')!, scope: p.get('scope')!,
      state: p.get('state')!, codeChallenge: p.get('code_challenge')!, codeChallengeMethod: p.get('code_challenge_method')!,
    });
    return { code, state: p.get('state')! };
  }

  return { session, approveFlow };
}

describe('session-bound grants', () => {
  it('auto-applies an approved grant for the same session with no token', async () => {
    const { session, approveFlow } = harness();
    const ch = await session.challenge(READ_VAULT_PROTECTION, 'did:key:zA', 'http://as.local/callback', 'session-1');
    const { code, state } = await approveFlow(ch.authorizationUrl);
    await session.completeFromCallback(state, code);

    const grant = session.grantForSession('session-1', READ_VAULT_PROTECTION.toolName);
    expect(grant?.valid).toBe(true);
    expect(grant?.credential?.scopes).toContain('vault:read');
  });

  it('does NOT leak one session\'s approval to another session', async () => {
    const { session, approveFlow } = harness();
    // Session A initiates and approves.
    const chA = await session.challenge(READ_VAULT_PROTECTION, 'did:key:zA', 'http://as.local/callback', 'session-A');
    const { code, state } = await approveFlow(chA.authorizationUrl);
    await session.completeFromCallback(state, code);

    // Session B has NOT approved anything → must see no grant for the same tool.
    expect(session.grantForSession('session-A', READ_VAULT_PROTECTION.toolName)?.valid).toBe(true);
    expect(session.grantForSession('session-B', READ_VAULT_PROTECTION.toolName)).toBeUndefined();
  });

  it('keeps the explicit resume_token path working as a stateless fallback', async () => {
    const { session, approveFlow } = harness();
    const ch = await session.challenge(READ_VAULT_PROTECTION, 'did:key:zA', 'http://as.local/callback', 'session-1');
    const { code, state } = await approveFlow(ch.authorizationUrl);
    await session.completeFromCallback(state, code);
    // Even without the session id, the resume_token resolves the same grant.
    expect(session.grantFor(ch.resumeToken)?.valid).toBe(true);
  });
});
