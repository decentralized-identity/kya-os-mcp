/**
 * The delegation gate holds a request proof to the delegation it names (SPEC §7.8). An agent holds
 * two delegations for one scope, from two Responsible Parties, and makes a call under the first.
 * Its proof names that delegation, so a party on the path that has seen the second cannot put it in
 * place of the first, or take the delegation away and let a durable grant of the second stand for
 * it: the call runs under the delegation the agent chose, or not at all. A proof that names no
 * delegation is taken beside any of its subject's, as before.
 */
import { describe, expect, it } from 'vitest';
import { generateRequestProof } from '../../delegation/holder-binding.js';
import { MemoryGrantStore } from '../../providers/grant-store.js';
import type { DelegationCredential } from '../../types/protocol.js';
import type { KyaOsDelegationConfig } from '../with-kya-os.config-types.js';
import { createKyaOsMiddleware } from '../with-kya-os.js';
import type { KyaOsCallContext } from '../with-kya-os.types.js';
import { delegate, party, type Party } from './helpers/delegating-party.js';
import { crypto, served } from './helpers/received-proof.js';

const TOOL = 'payments.send';
const SCOPE = 'payments:send';
const ARGS = { amount: 100, to: 'acct-7' };

/**
 * A gate of `server`'s, with a durable grant store, in front of `payments.send`, and how `signer`
 * calls it: with a request proof that names `named` when it is given. A call's outcome is `ran`, or
 * the error it was refused with; `ranFor` holds the Responsible Party of each call the tool ran.
 */
async function gate(server: Party, signer: Party, delegation: KyaOsDelegationConfig) {
  const kyaos = await served(createKyaOsMiddleware(
    {
      identity: server,
      session: { sessionTtlMinutes: 60 },
      delegation: { holderBinding: 'enforce', ...delegation },
      grantStore: new MemoryGrantStore(),
    },
    crypto,
  ));
  const ranFor: (string | undefined)[] = [];
  const handler = kyaos.wrapWithDelegation(
    TOOL,
    { scopeId: SCOPE, consentUrl: 'https://consent.example' },
    async (_args, _sessionId, context?: KyaOsCallContext) => {
      ranFor.push(context?.principal?.responsibleParty);
      return { content: [{ type: 'text', text: 'sent' }] };
    },
  );
  const call = async (args: Record<string, unknown>, named?: DelegationCredential[]) => {
    const proof = await generateRequestProof({
      identity: signer,
      crypto,
      toolName: TOOL,
      args,
      audience: server.did,
      ...(named === undefined ? {} : { delegationChain: named }),
    });
    const text = (await handler({ ...args, _kyaos_proof: proof })).content[0]!.text as string;
    return text === 'sent' ? 'ran' : (JSON.parse(text) as { error: string }).error;
  };
  return { call, ranFor };
}

/**
 * Two Responsible Parties, an agent each of them delegated `payments:send` to, and a gate that
 * trusts both. Party two also delegated another scope, so the two durable grants the gate binds for
 * the agent are two rows of the store, not one.
 */
async function twoParties() {
  const [partyOne, partyTwo, agent, server] = await Promise.all([party(), party(), party(), party()]);
  return {
    partyOne,
    partyTwo,
    ...(await gate(server, agent, { trustedRootIssuers: [partyOne.did, partyTwo.did] })),
    forPartyOne: await delegate(partyOne, agent.did, { scopes: [SCOPE] }),
    forPartyTwo: await delegate(partyTwo, agent.did, { scopes: [SCOPE, 'payments:refund'] }),
  };
}

describe('the delegation gate and the delegation a request proof names', () => {
  it('runs a call beside the delegation its proof names, and refuses one beside another', async () => {
    const { call, ranFor, partyOne, forPartyOne, forPartyTwo } = await twoParties();

    expect(await call({ ...ARGS, _kyaos_delegation: forPartyTwo }, [forPartyOne])).toBe('holder_binding_failed');
    expect(ranFor).toEqual([]);
    expect(await call({ ...ARGS, _kyaos_delegation: forPartyOne }, [forPartyOne])).toBe('ran');
    expect(ranFor).toEqual([partyOne.did]);
  });

  it('runs a call whose proof names no delegation beside either, as before', async () => {
    const { call, ranFor, partyTwo, forPartyTwo } = await twoParties();

    expect(await call({ ...ARGS, _kyaos_delegation: forPartyTwo })).toBe('ran');
    expect(ranFor).toEqual([partyTwo.did]);
  });

  it('compares the chain it evaluated, ancestors it resolved included, with the chain the proof names', async () => {
    const [user, agent, subAgent, server] = await Promise.all([party(), party(), party(), party()]);
    const root = await delegate(user, agent.did, { scopes: [SCOPE] });
    const leaf = await delegate(agent, subAgent.did, { parent: root, audience: server.did, scopes: [SCOPE] });
    const { call } = await gate(server, subAgent, {
      trustedRootIssuers: [user.did],
      resolveDelegationChain: async () => [root],
    });

    expect(await call({ ...ARGS, _kyaos_delegation: leaf }, [root, leaf])).toBe('ran');
    // The leaf alone is another chain than the one the gate evaluated.
    expect(await call({ ...ARGS, _kyaos_delegation: leaf }, [leaf])).toBe('holder_binding_failed');
  });

  it('resolves only the durable grant of the delegation the proof names, for a call that presents none', async () => {
    const { call, ranFor, partyOne, forPartyOne, forPartyTwo } = await twoParties();
    // Each call binds an agent-anchored grant; party two's is bound first.
    expect(await call({ ...ARGS, _kyaos_delegation: forPartyTwo }, [forPartyTwo])).toBe('ran');
    expect(await call({ ...ARGS, _kyaos_delegation: forPartyOne }, [forPartyOne])).toBe('ran');
    ranFor.length = 0;

    expect(await call(ARGS, [forPartyOne])).toBe('ran');
    expect(ranFor).toEqual([partyOne.did]);
  });

  it('resolves no durable grant of another delegation for a proof that names one', async () => {
    const { call, ranFor, forPartyOne, forPartyTwo } = await twoParties();
    expect(await call({ ...ARGS, _kyaos_delegation: forPartyTwo }, [forPartyTwo])).toBe('ran');
    ranFor.length = 0;

    expect(await call(ARGS, [forPartyOne])).toBe('needs_authorization');
    expect(ranFor).toEqual([]);
  });
});
