/**
 * A minimal but real OAuth 2.1 + PKCE authorization server for the demo.
 *
 * This is what makes the authorize URL actually visitable: the demo hosts its
 * own authorization server with a consent page (`/authorize` → approve →
 * `/callback`) and a token endpoint (`/token`). The token endpoint verifies the
 * PKCE challenge using the package's own `verifyS256Challenge` (DRY — the same
 * primitive the adapter relies on), issues one-time authorization codes, and
 * returns a scoped token. It is in-process and network-free, so the demo stays
 * deterministic, but the flow is a genuine authorization-code + PKCE exchange
 * rather than a stub.
 *
 * Production note: a real deployment does not host its own consent page — it
 * runs a *proxy* authorization server whose `/authorize` redirects to an
 * external enterprise IdP (the pattern in the product's OAuth router). This
 * self-hosted server is the demo's deterministic stand-in for that external
 * IdP, so the flow is clickable offline. The validation contract mirrors that
 * router: S256-only PKCE, PKCE required for the authorization_code grant, and
 * the RFC 6749 `{ error, error_description }` error shape.
 */
import { base64url } from 'jose';
import { verifyS256Challenge } from '@kya-os/mcp/authz';

export interface AuthorizeParams {
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: string;
}

export interface TokenRequest {
  grant_type: 'authorization_code';
  code: string;
  redirect_uri: string;
  client_id: string;
  code_verifier: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  scope: string;
  expires_in: number;
}

interface PendingCode {
  clientId: string;
  redirectUri: string;
  scope: string;
  codeChallenge: string;
}

export interface DemoAuthServer {
  /** Render the consent page HTML for an authorize request. */
  renderConsent(params: AuthorizeParams): string;
  /** Approve a request: mint a one-time authorization code bound to the PKCE challenge. */
  approve(params: AuthorizeParams): { code: string };
  /** Exchange a code + verifier for a token. Throws on PKCE failure or unknown/used code. */
  exchangeToken(req: TokenRequest): Promise<TokenResponse>;
}

export function createDemoAuthServer(): DemoAuthServer {
  const codes = new Map<string, PendingCode>();

  function approve(params: AuthorizeParams): { code: string } {
    if (params.codeChallengeMethod !== 'S256') {
      throw new Error('invalid_request: only S256 PKCE is supported');
    }
    const code = randomToken(24);
    codes.set(code, {
      clientId: params.clientId,
      redirectUri: params.redirectUri,
      scope: params.scope,
      codeChallenge: params.codeChallenge,
    });
    return { code };
  }

  async function exchangeToken(req: TokenRequest): Promise<TokenResponse> {
    const pending = codes.get(req.code);
    if (!pending) {
      throw new Error('invalid_grant: unknown or already-used authorization code');
    }
    // One-time use: consume the code regardless of outcome.
    codes.delete(req.code);

    if (req.client_id !== pending.clientId || req.redirect_uri !== pending.redirectUri) {
      throw new Error('invalid_grant: client_id / redirect_uri mismatch');
    }
    const pkceOk = await verifyS256Challenge(req.code_verifier, pending.codeChallenge);
    if (!pkceOk) {
      throw new Error('invalid_grant: PKCE verifier does not match the challenge');
    }

    return {
      access_token: `demo.${randomToken(16)}`,
      token_type: 'Bearer',
      scope: pending.scope,
      expires_in: 3600,
    };
  }

  function renderConsent(params: AuthorizeParams): string {
    // The approve form re-submits the same authorize parameters to /approve,
    // which mints the code and 302-redirects to redirect_uri?code=...&state=...
    const scopes = params.scope.split(' ').filter(Boolean);
    const hidden = (name: string, value: string): string =>
      `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}" />`;
    return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8" /><title>KYA-OS demo — authorize</title>
<style>
  body { font: 15px/1.5 system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem; color: #1a1a2e; }
  .card { border: 1px solid #ddd; border-radius: 12px; padding: 1.5rem 1.75rem; }
  h1 { font-size: 1.1rem; } code { background: #f3f3f7; padding: .1rem .35rem; border-radius: 4px; }
  ul { padding-left: 1.2rem; } button { font: inherit; padding: .6rem 1.2rem; border: 0; border-radius: 8px; background: #4338ca; color: #fff; cursor: pointer; }
  .muted { color: #666; font-size: .85rem; }
</style></head>
<body>
  <div class="card">
    <h1>Authorize <code>${escapeHtml(params.clientId)}</code></h1>
    <p>An agent is requesting access to:</p>
    <ul>${scopes.map((s) => `<li><code>${escapeHtml(s)}</code></li>`).join('')}</ul>
    <form method="POST" action="/approve">
      ${hidden('client_id', params.clientId)}
      ${hidden('redirect_uri', params.redirectUri)}
      ${hidden('scope', params.scope)}
      ${hidden('state', params.state)}
      ${hidden('code_challenge', params.codeChallenge)}
      ${hidden('code_challenge_method', params.codeChallengeMethod)}
      <button type="submit">Approve</button>
    </form>
    <p class="muted">Demo authorization server — approving issues a one-time, PKCE-bound code.</p>
  </div>
</body>
</html>`;
  }

  return { renderConsent, approve, exchangeToken };
}

function randomToken(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(bytes);
  return base64url.encode(bytes);
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
