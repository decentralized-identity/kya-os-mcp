import type { NeedsAuthorizationError } from '../../types/protocol.js';
import type { VerifyDelegationResult } from '../../auth/types.js';
import type { PolicyRequestInput } from '../../policy/projection.js';
import { AuthorizationServerRegistry } from '../registry.js';
import { GenericOidcAdapter, type FetchImpl } from '../oidc/oidc-adapter.js';
import { accountabilityToPolicyPrincipal, type AccountabilityContext } from '../accountability.js';
import type { ToolProtection } from '../requirement.js';

/**
 * A deterministic, network-free demonstration of the authorization seam.
 *
 * Wires the generic-OIDC reference adapter into a registry and backs its single
 * IdP call (the token exchange) with an in-memory token endpoint, so the full
 * path runs edge to edge with zero network: protect a tool -> resolve the
 * adapter -> produce a challenge -> verify the returned code -> map to a
 * delegation outcome -> derive the policy principal. This is the reliable,
 * CI-safe showcase of the pluggable adapter pattern; richer live-IdP demos bind
 * the same port without changing the core.
 */

export interface InMemoryFlowParams {
  toolName: string;
  requiredScopes: string[];
  agentDid: string;
  accountableAdminDid?: string;
}

export interface InMemoryFlowOutcome {
  challenge: NeedsAuthorizationError;
  result: VerifyDelegationResult;
  policyPrincipal: PolicyRequestInput['principal'];
  /** Count of real (non in-memory) network calls — always 0 here. */
  networkCalls: number;
}

/** An in-memory token endpoint standing in for a live OIDC provider. */
function inMemoryTokenEndpoint(grantedScopes: string[]): { fetchImpl: FetchImpl; externalCalls: () => number } {
  let external = 0;
  const fetchImpl: FetchImpl = async (url, init) => {
    // Only the configured in-memory token endpoint is served; anything else
    // would be a real network call, which this example never makes.
    if (url !== 'memory://idp/token') {
      external += 1;
      throw new Error(`unexpected external call to ${url}`);
    }
    const body = String(init?.body ?? '');
    if (!body.includes('grant_type=authorization_code') || !body.includes('code_verifier=')) {
      return new Response('invalid_request', { status: 400 });
    }
    return new Response(
      JSON.stringify({ access_token: 'memory-access-token', token_type: 'Bearer', scope: grantedScopes.join(' ') }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  };
  return { fetchImpl, externalCalls: () => external };
}

export async function runInMemoryAuthorizationFlow(
  params: InMemoryFlowParams,
): Promise<InMemoryFlowOutcome> {
  const { fetchImpl, externalCalls } = inMemoryTokenEndpoint(params.requiredScopes);

  const adapter = new GenericOidcAdapter({
    type: 'oauth',
    issuer: 'memory://idp',
    authorizationEndpoint: 'memory://idp/authorize',
    tokenEndpoint: 'memory://idp/token',
    clientId: 'example-agent-client',
    scopes: params.requiredScopes,
    resource: 'memory://resource/mcp',
    fetchImpl,
  });

  const registry = new AuthorizationServerRegistry();
  registry.register(adapter);
  registry.seal();

  const protection: ToolProtection = {
    toolName: params.toolName,
    requirement: { type: 'oauth', provider: 'generic-oidc', requiredScopes: params.requiredScopes },
  };

  const resolved = registry.resolve(protection);
  if (!resolved) throw new Error('no adapter resolved for the protected tool');

  const state = 'example-state';
  const challenge = await resolved.initiateFlow({
    protection,
    agentDid: params.agentDid,
    redirectUri: 'memory://app/callback',
    state,
  });

  // The user "authorizes": the provider redirects back with a code + state.
  const result = await resolved.verifyAuthorization(challenge.resumeToken, {
    code: 'example-auth-code',
    state,
  });

  const accountability: AccountabilityContext = {
    agentDid: params.agentDid,
    accountableAdminDid: params.accountableAdminDid,
    scopes: result.credential?.scopes ?? [],
  };

  return {
    challenge,
    result,
    policyPrincipal: accountabilityToPolicyPrincipal(accountability),
    networkCalls: externalCalls(),
  };
}
