import type { S256 } from './pkce.js';

/**
 * Inputs to the authorization-code request URL. PKCE is mandatory and S256-only
 * (see {@link S256}); the optional `resource` is an RFC 8707 resource indicator
 * binding the issued token's audience to the protected resource.
 */
export interface AuthorizeUrlParams {
  authorizationEndpoint: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
  state: string;
  codeChallenge: string;
  /** Always S256; present so a caller cannot silently request `plain`. */
  codeChallengeMethod?: S256;
  /** RFC 8707 resource indicator (optional). */
  resource?: string;
}

/**
 * Build an OAuth 2.1 authorization-code request URL. Pure: constructs a URL,
 * no network. Throws if a non-S256 challenge method is supplied — S256 is
 * mandatory.
 */
export function buildAuthorizeUrl(params: AuthorizeUrlParams): string {
  const method = params.codeChallengeMethod ?? 'S256';
  if (method !== 'S256') {
    throw new Error(`Unsupported code_challenge_method "${method}"; S256 is required.`);
  }

  const url = new URL(params.authorizationEndpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', params.clientId);
  url.searchParams.set('redirect_uri', params.redirectUri);
  url.searchParams.set('scope', params.scopes.join(' '));
  url.searchParams.set('state', params.state);
  url.searchParams.set('code_challenge', params.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  if (params.resource !== undefined) {
    url.searchParams.set('resource', params.resource);
  }
  return url.toString();
}
