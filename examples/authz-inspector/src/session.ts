/**
 * Authorization session — the shared brain that lets the caller handle only a
 * `resume_token`.
 *
 * The MCP tool and the HTTP callback both talk to this session:
 *
 *   - `challenge()` mints a resume_token, starts an adapter flow, and returns
 *     the authorize URL. It records `state → resume_token` so the callback can
 *     find the right pending flow.
 *   - `completeFromCallback()` runs server-side when the human approves: it
 *     performs the adapter's OAuth + PKCE token exchange and caches the
 *     resulting grant under the resume_token. The caller never sees the code,
 *     state, or verifier.
 *   - `grantFor()` lets a retried tool call auto-apply a cached grant.
 *
 * This mirrors the consent-full pattern (approve once, retry once) while the
 * underlying authorization is the @kya-os/mcp/authz seam.
 */
import {
  AuthorizationServerRegistry,
  GenericOidcAdapter,
  type FetchImpl,
  type ToolProtection,
} from '@kya-os/mcp/authz';
import type { VerifyDelegationResult } from '@kya-os/mcp';

export const READ_VAULT_PROTECTION: ToolProtection = {
  toolName: 'read_vault',
  requirement: { type: 'oauth', provider: 'generic-oidc', requiredScopes: ['vault:read'] },
};

export interface AuthzSessionConfig {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  scopes: string[];
  resource?: string;
  fetchImpl?: FetchImpl;
}

export interface Challenge {
  resumeToken: string;
  authorizationUrl: string;
  scopes: string[];
}

interface PendingFlow {
  resumeToken: string;
  state: string;
}

export interface AuthzSession {
  /** Start a flow: mint a resume_token, return the authorize URL + scopes. */
  challenge(protection: ToolProtection, agentDid: string, callbackUri: string): Promise<Challenge>;
  /** Run the server-side token exchange after approval; cache the grant. */
  completeFromCallback(state: string, code: string): Promise<{ ok: boolean; reason?: string }>;
  /** The cached grant for a resume_token, or undefined if not yet authorized. */
  grantFor(resumeToken: string): VerifyDelegationResult | undefined;
  /** A still-pending (unapproved) challenge for a resume_token, if any. */
  pendingFor(resumeToken: string): Challenge | undefined;
}

export function createAuthzSession(config: AuthzSessionConfig): AuthzSession {
  const adapter = new GenericOidcAdapter({
    type: 'oauth',
    issuer: config.issuer,
    authorizationEndpoint: config.authorizationEndpoint,
    tokenEndpoint: config.tokenEndpoint,
    clientId: config.clientId,
    scopes: config.scopes,
    resource: config.resource,
    fetchImpl: config.fetchImpl,
  });
  const registry = new AuthorizationServerRegistry();
  registry.register(adapter);
  registry.seal();

  // state → pending flow (so the callback finds the right resume_token)
  const byState = new Map<string, PendingFlow>();
  // resume_token → the issued challenge, while it is still pending approval
  const pending = new Map<string, Challenge>();
  // resume_token → completed grant (so a retried tool call auto-applies it)
  const grants = new Map<string, VerifyDelegationResult>();

  async function challenge(
    protection: ToolProtection,
    agentDid: string,
    callbackUri: string,
  ): Promise<Challenge> {
    const resolved = registry.resolve(protection);
    if (!resolved) throw new Error(`no adapter for ${protection.toolName}`);

    // A per-flow state binds the authorize round trip to this resume token.
    const state = randomToken(12);
    const ch = await resolved.initiateFlow({ protection, agentDid, redirectUri: callbackUri, state });
    byState.set(state, { resumeToken: ch.resumeToken, state });

    const challengeRecord: Challenge = {
      resumeToken: ch.resumeToken,
      authorizationUrl: ch.authorizationUrl,
      scopes: ch.scopes,
    };
    pending.set(ch.resumeToken, challengeRecord);
    return challengeRecord;
  }

  async function completeFromCallback(state: string, code: string): Promise<{ ok: boolean; reason?: string }> {
    const flow = byState.get(state);
    if (!flow) return { ok: false, reason: 'unknown state' };
    byState.delete(state);

    const resolved = registry.resolve(READ_VAULT_PROTECTION);
    if (!resolved) return { ok: false, reason: 'no adapter' };

    const result = await resolved.verifyAuthorization(flow.resumeToken, { code, state });
    if (!result.valid) return { ok: false, reason: result.reason };

    grants.set(flow.resumeToken, result);
    pending.delete(flow.resumeToken);
    return { ok: true };
  }

  function grantFor(resumeToken: string): VerifyDelegationResult | undefined {
    return grants.get(resumeToken);
  }

  function pendingFor(resumeToken: string): Challenge | undefined {
    return pending.get(resumeToken);
  }

  return { challenge, completeFromCallback, grantFor, pendingFor };
}

function randomToken(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString('base64url');
}
