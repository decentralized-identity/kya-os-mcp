/**
 * Tests for the demo's authorization session — the shared brain that lets the
 * caller handle only a `resume_token`.
 *
 * It ties together three things the MCP tool and the HTTP callback both touch:
 * issuing a challenge (mint resume_token + authorize URL), completing the flow
 * server-side when the human approves (the OAuth + PKCE exchange happens here,
 * not in the tool), and caching the resulting grant by resume_token so a retry
 * auto-applies it. No authorization code, state, or verifier is ever surfaced
 * to the caller.
 */
import { describe, it, expect } from 'vitest';
import { createAuthzSession, READ_VAULT_PROTECTION } from '../src/session.js';
import { createDemoAuthServer } from '../src/auth-server.js';

/**
 * Build a session whose adapter token-exchange is wired to a local in-process
 * authorization server (no network), and a helper that performs the
 * approve→callback the way the browser would.
 */
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
    // Route the adapter's token exchange straight into the in-process AS.
    fetchImpl: async (url, init) => {
      if (url !== tokenEndpoint) throw new Error(`unexpected ${url}`);
      const form = new URLSearchParams(String(init?.body ?? ''));
      try {
        const token = await authServer.exchangeToken({
          grant_type: 'authorization_code',
          code: form.get('code') ?? '',
          redirect_uri: form.get('redirect_uri') ?? '',
          client_id: form.get('client_id') ?? '',
          code_verifier: form.get('code_verifier') ?? '',
        });
        return new Response(JSON.stringify(token), { status: 200, headers: { 'content-type': 'application/json' } });
      } catch (e) {
        return new Response(JSON.stringify({ error: 'invalid_grant', error_description: (e as Error).message }), { status: 400 });
      }
    },
  });

  /** Simulate the human approving in the browser, returning {code, state}. */
  function approve(authorizeUrl: string): { code: string; state: string } {
    const p = new URL(authorizeUrl).searchParams;
    const { code } = authServer.approve({
      clientId: p.get('client_id')!, redirectUri: p.get('redirect_uri')!, scope: p.get('scope')!,
      state: p.get('state')!, codeChallenge: p.get('code_challenge')!, codeChallengeMethod: p.get('code_challenge_method')!,
    });
    return { code, state: p.get('state')! };
  }

  return { session, approve };
}

describe('authz session', () => {
  it('issues a challenge with a resume_token and an authorize URL', async () => {
    const { session } = harness();
    const ch = await session.challenge(READ_VAULT_PROTECTION, 'did:key:zA', 'http://as.local/callback');
    expect(ch.resumeToken).toBeTruthy();
    expect(ch.authorizationUrl).toContain('/authorize');
    expect(new URL(ch.authorizationUrl).searchParams.get('code_challenge_method')).toBe('S256');
    expect(ch.scopes).toContain('vault:read');
  });

  it('has no grant for a resume_token before approval', async () => {
    const { session } = harness();
    const ch = await session.challenge(READ_VAULT_PROTECTION, 'did:key:zA', 'http://as.local/callback');
    expect(session.grantFor(ch.resumeToken)).toBeUndefined();
  });

  it('caches a grant after the callback completes the exchange — keyed by resume_token', async () => {
    const { session, approve } = harness();
    const ch = await session.challenge(READ_VAULT_PROTECTION, 'did:key:zA', 'http://as.local/callback');
    const { code, state } = approve(ch.authorizationUrl);

    const outcome = await session.completeFromCallback(state, code);
    expect(outcome.ok).toBe(true);

    const grant = session.grantFor(ch.resumeToken);
    expect(grant?.valid).toBe(true);
    expect(grant?.credential?.scopes).toContain('vault:read');
  });

  it('fails the callback for an unknown state', async () => {
    const { session } = harness();
    const outcome = await session.completeFromCallback('never-issued', 'whatever');
    expect(outcome.ok).toBe(false);
  });
});
