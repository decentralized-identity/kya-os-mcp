import { base64url } from 'jose';
import {
  createNeedsAuthorizationError,
  type NeedsAuthorizationError,
} from '../../types/protocol.js';
import type { VerifyDelegationResult } from '../../auth/types.js';
import type { AuthorizationServerAdapter, FlowParams } from '../adapter.js';
import { requirementMatchesAdapter } from '../adapter.js';
import { buildAuthorizeUrl } from './authorize.js';
import { computeS256Challenge } from './pkce.js';
import type { ToolProtection } from '../requirement.js';

/** A minimal fetch signature — the injectable seam for IdP HTTP calls. */
export type FetchImpl = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<Response>;

export interface GenericOidcAdapterConfig {
  readonly type: 'oauth';
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  scopes: string[];
  /** RFC 8707 resource indicator bound into the authorize request + token audience. */
  resource?: string;
  clientSecret?: string;
  /** Resume-token lifetime in ms (default 10 minutes). */
  resumeTokenTtlMs?: number;
  /** Injected fetch seam; defaults to the runtime global fetch. */
  fetchImpl?: FetchImpl;
}

interface PendingFlow {
  agentDid: string;
  scopes: string[];
  state: string;
  codeVerifier: string;
  redirectUri: string;
}

/**
 * Reference generic-OIDC authorization-server adapter.
 *
 * Implements {@link AuthorizationServerAdapter} for a standards-only OpenID
 * Connect / OAuth 2.1 provider. No named vendor identity provider appears
 * here; concrete commercial providers are downstream adapters binding the same
 * port. The pure pieces (authorize URL, PKCE) run inline; the single IdP HTTP
 * call (token
 * exchange) goes through an injectable fetch seam, so the adapter is fully
 * deterministic under test with no network.
 *
 * The PKCE code verifier is held server-side keyed by the resume token and is
 * never placed in the authorization URL — only the S256 challenge travels.
 */
export class GenericOidcAdapter implements AuthorizationServerAdapter {
  readonly type = 'oauth' as const;
  private readonly pending = new Map<string, PendingFlow>();
  private readonly fetchImpl: FetchImpl;

  constructor(private readonly config: GenericOidcAdapterConfig) {
    this.fetchImpl = config.fetchImpl ?? ((url, init) => fetch(url, init));
  }

  isRequired(protection: ToolProtection): boolean {
    return requirementMatchesAdapter(this.type, protection);
  }

  async initiateFlow(params: FlowParams): Promise<NeedsAuthorizationError> {
    const requiredScopes =
      params.protection.requirement.type === 'oauth'
        ? (params.protection.requirement.requiredScopes ?? this.config.scopes)
        : this.config.scopes;
    const scopes = unique([...this.config.scopes, ...requiredScopes]);

    const codeVerifier = randomToken(32);
    const codeChallenge = await computeS256Challenge(codeVerifier);
    const resumeToken = randomToken(24);

    this.pending.set(resumeToken, {
      agentDid: params.agentDid,
      scopes,
      state: params.state,
      codeVerifier,
      redirectUri: params.redirectUri,
    });

    const authorizationUrl = buildAuthorizeUrl({
      authorizationEndpoint: this.config.authorizationEndpoint,
      clientId: this.config.clientId,
      redirectUri: params.redirectUri,
      scopes,
      state: params.state,
      codeChallenge,
      resource: this.config.resource,
    });

    return createNeedsAuthorizationError({
      message: `Authorization required for "${params.protection.toolName}".`,
      authorizationUrl,
      resumeToken,
      expiresAt: nowMs() + (this.config.resumeTokenTtlMs ?? 600_000),
      scopes,
    });
  }

  async verifyAuthorization(flowState: string, result: unknown): Promise<VerifyDelegationResult> {
    const pending = this.pending.get(flowState);
    if (!pending) {
      return { valid: false, reason: 'unknown or expired resume token' };
    }
    const { code, state } = (result ?? {}) as { code?: string; state?: string };
    if (!code) {
      return { valid: false, reason: 'missing authorization code' };
    }
    if (state !== pending.state) {
      return { valid: false, reason: 'state mismatch' };
    }

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: pending.redirectUri,
      client_id: this.config.clientId,
      code_verifier: pending.codeVerifier,
    });
    if (this.config.resource) body.set('resource', this.config.resource);
    if (this.config.clientSecret) body.set('client_secret', this.config.clientSecret);

    let token: { scope?: string; access_token?: string };
    try {
      const response = await this.fetchImpl(this.config.tokenEndpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: body.toString(),
      });
      if (!response.ok) {
        return { valid: false, reason: `token endpoint returned ${response.status}` };
      }
      token = (await response.json()) as { scope?: string; access_token?: string };
    } catch (error) {
      return { valid: false, reason: `token exchange failed: ${(error as Error).message}` };
    }

    // One-time use: a resume token is consumed on verification.
    this.pending.delete(flowState);

    const grantedScopes = token.scope ? token.scope.split(' ') : pending.scopes;
    return {
      valid: true,
      credential: {
        agent_did: pending.agentDid,
        user_did: '',
        scopes: grantedScopes,
        authorization: { type: 'oauth', provider: 'generic-oidc' },
      },
    };
  }

  /** Test/inspection seam: the pending code verifier for a resume token, if any. */
  pendingVerifierFor(resumeToken: string): string | undefined {
    return this.pending.get(resumeToken)?.codeVerifier;
  }
}

function randomToken(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(bytes);
  return base64url.encode(bytes);
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function nowMs(): number {
  return Date.now();
}
