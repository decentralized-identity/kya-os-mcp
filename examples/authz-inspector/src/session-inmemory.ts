/**
 * In-memory authorization session for the stdio entrypoint.
 *
 * stdio has no HTTP server to host a consent page or receive a callback, so
 * this session satisfies the same `AuthzSession` interface but simulates
 * approval in-process: issuing a challenge also caches a valid grant for that
 * resume_token. The caller experience is identical (call read_vault → get a
 * resume_token → re-call with it → vault reads); only the human approval step
 * is stubbed. For the genuine browser consent flow, use the HTTP entrypoint.
 */
import type { VerifyDelegationResult } from '@kya-os/mcp';
import type { AuthzSession, Challenge } from './session.js';
import type { ToolProtection } from '@kya-os/mcp/authz';

export function createInMemorySession(scopes: string[]): AuthzSession {
  const grants = new Map<string, VerifyDelegationResult>();
  const pending = new Map<string, Challenge>();
  let counter = 0;

  async function challenge(
    protection: ToolProtection,
    agentDid: string,
    _callbackUri: string,
  ): Promise<Challenge> {
    const resumeToken = `inmem-${(counter += 1)}-${randomToken(8)}`;
    const requiredScopes =
      protection.requirement.type === 'oauth'
        ? (protection.requirement.requiredScopes ?? scopes)
        : scopes;
    const granted = unique([...scopes, ...requiredScopes]);

    // Simulated approval: cache a valid grant immediately so the retry succeeds.
    grants.set(resumeToken, {
      valid: true,
      credential: {
        agent_did: agentDid,
        user_did: '',
        scopes: granted,
        authorization: { type: 'oauth', provider: 'in-memory' },
      },
    });

    // The "authorize URL" shows the request shape; there is nothing to visit.
    const url = new URL('memory://idp/authorize');
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', granted.join(' '));
    url.searchParams.set('code_challenge_method', 'S256');
    const challengeRecord: Challenge = { resumeToken, authorizationUrl: url.toString(), scopes: granted };
    pending.set(resumeToken, challengeRecord);
    return challengeRecord;
  }

  async function completeFromCallback(): Promise<{ ok: boolean; reason?: string }> {
    // No callback in stdio; approval is simulated at challenge time.
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

function unique(values: string[]): string[] {
  return [...new Set(values)];
}
