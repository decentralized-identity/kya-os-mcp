/**
 * Tests for the demo's real OAuth 2.1 + PKCE authorization server.
 *
 * The demo hosts an actual authorization server (a consent page, an authorize
 * endpoint that issues a code, and a token endpoint that verifies the PKCE
 * challenge before issuing a token). These tests drive that server's handlers
 * directly — no MCP, no browser — to pin the standards behavior: PKCE binding,
 * one-time codes, and scope issuance. Deterministic and network-free.
 */
import { describe, it, expect } from 'vitest';
import { computeS256Challenge } from '@kya-os/mcp/authz';
import { createDemoAuthServer } from '../src/auth-server.js';

const REDIRECT = 'http://localhost:3030/callback';

describe('demo authorization server', () => {
  it('registers a pending authorization and renders an approve action', async () => {
    const as = createDemoAuthServer();
    const challenge = await computeS256Challenge('verifier-abc');
    const page = as.renderConsent({
      clientId: 'demo',
      redirectUri: REDIRECT,
      scope: 'vault:read',
      state: 'st-1',
      codeChallenge: challenge,
      codeChallengeMethod: 'S256',
    });
    // The consent page is real HTML with an approve form pointing at /approve.
    expect(page).toContain('vault:read');
    expect(page).toContain('/approve');
    expect(page).toContain('action=');
  });

  it('issues a one-time code on approval and exchanges it for a token (PKCE verified)', async () => {
    const as = createDemoAuthServer();
    const verifier = 'verifier-abc';
    const codeChallenge = await computeS256Challenge(verifier);

    const { code } = as.approve({
      clientId: 'demo',
      redirectUri: REDIRECT,
      scope: 'vault:read',
      state: 'st-1',
      codeChallenge,
      codeChallengeMethod: 'S256',
    });
    expect(code).toBeTruthy();

    const token = await as.exchangeToken({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT,
      client_id: 'demo',
      code_verifier: verifier,
    });
    expect(token.access_token).toBeTruthy();
    expect(token.scope).toBe('vault:read');
  });

  it('rejects a token exchange whose verifier does not match the challenge', async () => {
    const as = createDemoAuthServer();
    const codeChallenge = await computeS256Challenge('right-verifier');
    const { code } = as.approve({
      clientId: 'demo', redirectUri: REDIRECT, scope: 'vault:read', state: 'st-1',
      codeChallenge, codeChallengeMethod: 'S256',
    });
    await expect(
      as.exchangeToken({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT,
        client_id: 'demo',
        code_verifier: 'WRONG-verifier',
      }),
    ).rejects.toThrow(/pkce|verifier|invalid_grant/i);
  });

  it('rejects reuse of an authorization code (one-time use)', async () => {
    const as = createDemoAuthServer();
    const verifier = 'v';
    const codeChallenge = await computeS256Challenge(verifier);
    const { code } = as.approve({
      clientId: 'demo', redirectUri: REDIRECT, scope: 'vault:read', state: 'st-1',
      codeChallenge, codeChallengeMethod: 'S256',
    });
    const args = {
      grant_type: 'authorization_code' as const,
      code, redirect_uri: REDIRECT, client_id: 'demo', code_verifier: verifier,
    };
    await as.exchangeToken(args);
    await expect(as.exchangeToken(args)).rejects.toThrow(/invalid_grant|unknown|used/i);
  });
});
