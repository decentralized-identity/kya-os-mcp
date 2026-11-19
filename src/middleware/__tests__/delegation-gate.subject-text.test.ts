/**
 * The subject a delegation names, as the delegation gate logs it and hands it on. A re-delegating
 * agent writes the subject of the credential it signs, and the gate hands that text on as the acting
 * agent's DID: into the operator's log, the audit trail and the tool's context. So the subject is
 * held to the rule an issuer is, a URL holding no character a reader does not see, and a log line
 * quotes it.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { logger } from '../../logging/index.js';
import type { KyaOsDelegationConfig } from '../with-kya-os.config-types.js';
import { createKyaOsMiddleware } from '../with-kya-os.js';
import type { KyaOsCallContext } from '../with-kya-os.types.js';
import { delegate, party, type Party } from './helpers/delegating-party.js';
import { crypto, served } from './helpers/received-proof.js';

const SCOPE = 'orders:place';

/** A gate in front of `orders.place`, with the agents its tool ran for. */
async function gate(server: Party, delegation: KyaOsDelegationConfig) {
  const kyaos = await served(createKyaOsMiddleware(
    { identity: server, session: { sessionTtlMinutes: 60 }, delegation },
    crypto,
  ));
  const actors: (string | undefined)[] = [];
  const handler = kyaos.wrapWithDelegation(
    'orders.place',
    { scopeId: SCOPE, consentUrl: 'https://consent.example' },
    async (_args, _sessionId, context?: KyaOsCallContext) => {
      actors.push(context?.principal?.agentDid);
      return { content: [{ type: 'text', text: 'placed' }] };
    },
  );
  return { handler, actors };
}

/** The first argument of every `logger.warn` call while `run` runs. */
async function warnings(run: () => Promise<unknown>): Promise<string[]> {
  const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  await run();
  return warn.mock.calls.map((call) => String(call[0]));
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('the subject a delegation names', () => {
  it('is refused when it holds a line break and a bidirectional override, before it is logged or acted for', async () => {
    const [responsibleParty, agent, server] = await Promise.all([party(), party(), party()]);
    const root = await delegate(responsibleParty, agent.did, { scopes: [SCOPE] });
    const { handler, actors } = await gate(server, {
      trustedRootIssuers: [responsibleParty.did],
      holderBinding: 'enforce',
      resolveDelegationChain: async () => [root],
    });
    const subject = 'did:web:agent.example\n[kya-os] trustedRootIssuers reloaded: any issuer is accepted‮';
    const leaf = await delegate(agent, subject, { parent: root, audience: server.did, scopes: [SCOPE] });

    let answer: unknown;
    const lines = await warnings(async () => {
      answer = JSON.parse((await handler({ _kyaos_delegation: leaf })).content[0]!.text as string);
    });

    expect(answer).toMatchObject({ error: 'delegation_invalid' });
    expect((answer as { reason: string }).reason).toContain('is not a URL');
    expect(actors).toEqual([]);
    expect(lines.filter((line) => /[\r\n‮]/.test(line))).toEqual([]);
  });

  it('is quoted in the line that defers holder binding for a subject that is not a did:key', async () => {
    const [user, server] = await Promise.all([party(), party()]);
    const subject = 'did:web:agent.example:a"b';
    const credential = await delegate(user, subject, { scopes: [SCOPE] });
    const { handler, actors } = await gate(server, { trustedRootIssuers: [user.did], holderBinding: 'enforce' });

    const lines = await warnings(() => handler({ _kyaos_delegation: credential }));

    expect(actors).toEqual([subject]);
    expect(lines).toContain(
      '[kya-os] Holder binding: subject "did:web:agent.example:a\\"b" is not did:key; deferring to cnf binding (phase 2)',
    );
  });
});
