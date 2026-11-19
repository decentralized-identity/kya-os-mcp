/**
 * What a server sends downstream does not let its receiver call the server's own gate as the agent.
 * A grant the gate binds in a session is resolved by the session's id, so that id is a bearer of the
 * session. The outbound headers name the session to a downstream service by an anchor derived for
 * that service's host, never by the id, so the service, and whatever logs or proxies its headers,
 * holds nothing it could present to the gate for the session.
 */
import { describe, expect, it } from 'vitest';
import { buildOutboundDelegationHeaders } from '../../delegation/outbound-headers.js';
import { MemoryGrantStore } from '../../providers/grant-store.js';
import { extractDelegationFromVC, type SessionContext } from '../../types/protocol.js';
import { delegationGate } from './helpers/delegation-gate.js';
import { delegate, party } from './helpers/delegating-party.js';

describe('the session a server names downstream', () => {
  it('is named by nothing that authorizes a call at the gate in that session', async () => {
    const [user, agent, forwarder] = await Promise.all([party(), party(), party()]);
    const delegation = await delegate(user, agent.did, { scopes: ['orders:place'] });
    const gate = await delegationGate({ trustedRootIssuers: [user.did], grantStore: new MemoryGrantStore() });
    const sessionId = await gate.session();
    // The agent's call in its session binds a grant, which the next call in the session uses.
    expect(await gate.callIn(sessionId, delegation)).toBe('ran');
    expect(await gate.callIn(sessionId)).toBe('ran');

    const now = Math.floor(Date.now() / 1000);
    const session: SessionContext = {
      sessionId,
      audience: forwarder.did,
      nonce: 'n',
      timestamp: now,
      createdAt: now,
      lastActivity: now,
      ttlMinutes: 60,
      identityState: 'anonymous',
      agentDid: agent.did,
    };
    const sent = await buildOutboundDelegationHeaders({
      session,
      delegation: extractDelegationFromVC(delegation),
      serverIdentity: { did: forwarder.did, kid: forwarder.kid, privateKey: forwarder.privateKey },
      targetUrl: 'https://downstream.example/api',
    });

    expect(Object.values(sent).some((value) => value?.includes(sessionId))).toBe(false);
    expect(await gate.callIn(sent['KYA-OS-Session-Id'])).toBe('needs_authorization');
    expect(gate.runs()).toBe(2);
  });
});
