import { describe, it, expect } from 'vitest';
import { projectAccountability, accountabilityToPolicyPrincipal } from '../accountability.js';
import type { DelegationCredentialSubject } from '../../types/protocol.js';

/**
 * AccountabilityContext is the agent -> accountable-admin -> user -> intent
 * chain. It is a read-only projection from a delegation credential subject and
 * feeds PolicyRequest.principal, so policy can gate on accountability. The
 * admin rung is sourced from the credential `controller` until a dedicated
 * org-admin field lands; `orgRootDid` is a forward-compatible slot that stays
 * undefined until the Org Root DID work exists.
 */

function subject(over: Partial<DelegationCredentialSubject['delegation']> = {}): DelegationCredentialSubject {
  return {
    id: 'did:key:zAgent',
    delegation: {
      id: 'del-1',
      issuerDid: 'did:web:org.example',
      subjectDid: 'did:key:zAgent',
      userDid: 'did:web:user.example',
      controller: 'did:web:org.example:admins:alice',
      scopes: ['vault:read'],
      constraints: {},
      status: 'active',
      ...over,
    } as DelegationCredentialSubject['delegation'],
  };
}

describe('projectAccountability', () => {
  it('projects agent, user, intent scopes, and the admin from controller', () => {
    const ctx = projectAccountability(subject());
    expect(ctx.agentDid).toBe('did:key:zAgent');
    expect(ctx.userDid).toBe('did:web:user.example');
    expect(ctx.accountableAdminDid).toBe('did:web:org.example:admins:alice');
    expect(ctx.scopes).toEqual(['vault:read']);
  });

  it('leaves orgRootDid undefined (Org Root DID not yet landed)', () => {
    expect(projectAccountability(subject()).orgRootDid).toBeUndefined();
  });

  it('omits accountableAdminDid when no controller is present', () => {
    const ctx = projectAccountability(subject({ controller: undefined }));
    expect(ctx.accountableAdminDid).toBeUndefined();
  });

  it('defaults scopes to an empty array when none are delegated', () => {
    expect(projectAccountability(subject({ scopes: undefined })).scopes).toEqual([]);
  });
});

describe('accountabilityToPolicyPrincipal', () => {
  it('maps the accountable admin onto PolicyRequest principal.responsibleParty', () => {
    const principal = accountabilityToPolicyPrincipal(projectAccountability(subject()));
    expect(principal.agentDid).toBe('did:key:zAgent');
    expect(principal.responsibleParty).toBe('did:web:org.example:admins:alice');
  });

  it('omits responsibleParty when there is no accountable admin', () => {
    const principal = accountabilityToPolicyPrincipal(
      projectAccountability(subject({ controller: undefined })),
    );
    expect(principal.agentDid).toBe('did:key:zAgent');
    expect('responsibleParty' in principal).toBe(false);
  });
});
