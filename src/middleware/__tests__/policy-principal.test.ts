/**
 * `extractPolicyPrincipal`, what a `withPolicyGate` with no delegation gate before it reads from a
 * `_kyaos_delegation` argument nothing verified. It is only a claim, so it reads what it can and
 * never throws: a credential whose scopes cannot be read lists none, and one that cannot be read
 * at all names no agent.
 */

import { describe, expect, it } from 'vitest';
import { extractPolicyPrincipal } from '../with-kya-os.helpers.js';

describe('extractPolicyPrincipal', () => {
  it('keeps the subject a credential names when its scopes cannot be read, and lists no scopes', () => {
    expect(extractPolicyPrincipal({ credentialSubject: { id: 'did:key:zAgent' } })).toEqual({
      agentDid: 'did:key:zAgent',
      delegatedScopes: [],
    });
  });

  it('names no agent and no scopes for a credential that throws as it is read', () => {
    const unreadable = {
      get credentialSubject(): never {
        throw new Error('unreadable');
      },
    };
    expect(extractPolicyPrincipal(unreadable)).toEqual({ agentDid: 'unknown', delegatedScopes: [] });
  });
});
