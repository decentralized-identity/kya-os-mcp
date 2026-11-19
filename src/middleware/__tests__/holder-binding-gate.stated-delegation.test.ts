/**
 * The delegation gate holds a request proof to the delegation its call presents (SPEC §7.8). An
 * agent holds two delegations for one scope, from two Responsible Parties, and makes a call under
 * the first with the default generator and no input beyond the arguments it sends. A party on the
 * path has seen the second delegation and holds no key. It can put that delegation in place of the
 * first, take the delegation away so that a durable grant answers, or add one to a call that sent
 * none: the call runs under the delegation the agent chose, or not at all.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { generateRequestProof } from '../../delegation/holder-binding.js';
import {
  NONE_AMONG_GRANTS_WARNED,
  NONE_BESIDE_DELEGATION_WARNED,
  UNNAMED_PROOF_WARNED,
} from '../../delegation/unnamed-proof-warning.js';
import { ARGS, TOOL, proofStating } from '../../delegation/__tests__/helpers/request-proofs.js';
import { logger } from '../../logging/index.js';
import { MemoryGrantStore } from '../../providers/grant-store.js';
import type { DelegationCredential } from '../../types/protocol.js';
import type { KyaOsDelegationConfig } from '../with-kya-os.config-types.js';
import { createKyaOsMiddleware } from '../with-kya-os.js';
import type { KyaOsCallContext } from '../with-kya-os.types.js';
import { delegate, party, reissued, type Party } from './helpers/delegating-party.js';
import { crypto, served } from './helpers/received-proof.js';

const SCOPE = 'payments:send';
type Args = Record<string, unknown>;
/** What a party on the path does to the arguments of a call it forwards. */
type OnPath = (sent: Args) => Args;

const WARNED = [UNNAMED_PROOF_WARNED, NONE_BESIDE_DELEGATION_WARNED, NONE_AMONG_GRANTS_WARNED];
const forgetWarnings = (): void => {
  for (const key of WARNED) delete (globalThis as { [key: symbol]: unknown })[key];
};

/**
 * A gate of `server`'s, with a durable grant store, in front of `payments.send`, and how `agent`
 * calls it: `send` makes the proof with the default generator from the arguments it sends, and
 * `onPath` then changes what arrives. A call's outcome is `ran`, or the error it was refused with;
 * `ranFor` holds the Responsible Party of each call the tool ran.
 */
async function gate(server: Party, agent: Party, delegation: KyaOsDelegationConfig) {
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
  const arrive = async (args: Args, sessionId?: string) => {
    const text = (await handler(args, sessionId)).content[0]!.text as string;
    return text === 'sent' ? 'ran' : (JSON.parse(text) as { error: string }).error;
  };
  const send = async (args: Args, onPath: OnPath = (sent) => sent, more: { delegation?: DelegationCredential } = {}) => {
    const proof = await generateRequestProof({ identity: agent, crypto, toolName: TOOL, args, audience: server.did, ...more });
    return arrive(onPath({ ...args, _kyaos_proof: proof }));
  };
  /** A call as a client on an earlier release makes it: its proof states nothing of its delegation. */
  const sendUnnamed = async (args: Args) => arrive({ ...args, _kyaos_proof: await proofStating(agent, undefined, {}, server.did) });
  return { send, sendUnnamed, arrive, ranFor, kyaos };
}

/**
 * Two Responsible Parties, an agent each of them delegated `payments:send` to, and a gate that
 * trusts both. Party two also delegated another scope, so the two durable grants the gate binds for
 * the agent are two rows of the store, not one.
 */
async function twoParties(delegation: KyaOsDelegationConfig = {}) {
  const [partyOne, partyTwo, agent, server] = await Promise.all([party(), party(), party(), party()]);
  return {
    partyOne,
    partyTwo,
    agent,
    server,
    ...(await gate(server, agent, { trustedRootIssuers: [partyOne.did, partyTwo.did], ...delegation })),
    forPartyOne: await delegate(partyOne, agent.did, { scopes: [SCOPE] }),
    forPartyTwo: await delegate(partyTwo, agent.did, { scopes: [SCOPE, 'payments:refund'] }),
  };
}

const swapFor = (delegation: DelegationCredential): OnPath => (sent) => ({ ...sent, _kyaos_delegation: delegation });
const remove: OnPath = ({ _kyaos_delegation: _removed, ...rest }) => rest;

afterEach(() => {
  vi.restoreAllMocks();
  forgetWarnings();
});

describe('the delegation gate and the delegation a request proof states', () => {
  it('refuses a delegation swapped in beside a proof the default generator made, with no extra input', async () => {
    const { send, ranFor, partyOne, forPartyOne, forPartyTwo } = await twoParties();

    expect(await send({ ...ARGS, _kyaos_delegation: forPartyOne }, swapFor(forPartyTwo))).toBe('holder_binding_failed');
    expect(ranFor).toEqual([]);
    expect(await send({ ...ARGS, _kyaos_delegation: forPartyOne })).toBe('ran');
    expect(ranFor).toEqual([partyOne.did]);
  });

  it('resolves only the grant of the delegation the proof names when the delegation is taken away', async () => {
    const { send, ranFor, partyOne, forPartyOne, forPartyTwo } = await twoParties();
    // Party two's grant is bound first, so it is the one the store lists first.
    expect(await send({ ...ARGS, _kyaos_delegation: forPartyTwo })).toBe('ran');
    ranFor.length = 0;

    // Only party two's grant is retained: the call the agent made under party one's does not run under it.
    expect(await send({ ...ARGS, _kyaos_delegation: forPartyOne }, remove)).toBe('needs_authorization');
    expect(ranFor).toEqual([]);

    // With both retained, it runs under the one the proof names, not the first listed.
    expect(await send({ ...ARGS, _kyaos_delegation: forPartyOne })).toBe('ran');
    ranFor.length = 0;
    expect(await send({ ...ARGS, _kyaos_delegation: forPartyOne }, remove)).toBe('ran');
    expect(ranFor).toEqual([partyOne.did]);
  });

  describe('for a call that presents no delegation', () => {
    it('resolves the one grant retained for the agent, its proof stating "none"', async () => {
      const { send, ranFor, partyOne, forPartyOne } = await twoParties({ requestBinding: 'require' });
      expect(await send({ ...ARGS, _kyaos_delegation: forPartyOne })).toBe('ran');
      ranFor.length = 0;

      expect(await send(ARGS)).toBe('ran');
      expect(ranFor).toEqual([partyOne.did]);
    });

    it('resolves no grant of another delegation for a proof that names one', async () => {
      const { send, ranFor, forPartyOne, forPartyTwo } = await twoParties();
      expect(await send({ ...ARGS, _kyaos_delegation: forPartyTwo })).toBe('ran');
      ranFor.length = 0;

      expect(await send(ARGS, undefined, { delegation: forPartyOne })).toBe('needs_authorization');
      expect(ranFor).toEqual([]);
    });

    it('resolves the grant a proof names among several, whichever the store lists first', async () => {
      const { send, ranFor, partyOne, partyTwo, forPartyOne, forPartyTwo } = await twoParties({ requestBinding: 'require' });
      expect(await send({ ...ARGS, _kyaos_delegation: forPartyTwo })).toBe('ran');
      expect(await send({ ...ARGS, _kyaos_delegation: forPartyOne })).toBe('ran');
      ranFor.length = 0;

      expect(await send(ARGS, undefined, { delegation: forPartyOne })).toBe('ran');
      expect(await send(ARGS, undefined, { delegation: forPartyTwo })).toBe('ran');
      expect(ranFor).toEqual([partyOne.did, partyTwo.did]);
    });

    it('takes the first of several grants for a proof that states "none" under prefer, with one warning', async () => {
      const warned = vi.spyOn(logger, 'warn');
      const { send, ranFor, partyTwo, forPartyOne, forPartyTwo } = await twoParties();
      expect(await send({ ...ARGS, _kyaos_delegation: forPartyTwo })).toBe('ran');
      expect(await send({ ...ARGS, _kyaos_delegation: forPartyOne })).toBe('ran');
      ranFor.length = 0;

      expect(await send(ARGS)).toBe('ran');
      expect(await send(ARGS)).toBe('ran');
      expect(ranFor).toEqual([partyTwo.did, partyTwo.did]);
      expect(warned.mock.calls.filter(([line]) => String(line).includes('retained for its subject, which hold more than one'))).toHaveLength(1);
    });

    it('resolves none of several grants for a proof that states "none" under require', async () => {
      const { send, ranFor, forPartyOne, forPartyTwo } = await twoParties({ requestBinding: 'require' });
      expect(await send({ ...ARGS, _kyaos_delegation: forPartyTwo })).toBe('ran');
      expect(await send({ ...ARGS, _kyaos_delegation: forPartyOne })).toBe('ran');
      ranFor.length = 0;

      expect(await send(ARGS)).toBe('needs_authorization');
      expect(ranFor).toEqual([]);
    });

    it('refuses a delegation added beside a proof that states "none" under require, and warns once under prefer', async () => {
      const strict = await twoParties({ requestBinding: 'require' });
      expect(await strict.send(ARGS, swapFor(strict.forPartyTwo))).toBe('holder_binding_failed');
      expect(strict.ranFor).toEqual([]);

      // A client that signed its business arguments and attached its delegation afterwards arrives the same way.
      const warned = vi.spyOn(logger, 'warn');
      const lenient = await twoParties();
      expect(await lenient.send(ARGS, swapFor(lenient.forPartyTwo))).toBe('ran');
      expect(await lenient.send(ARGS, swapFor(lenient.forPartyTwo))).toBe('ran');
      expect(warned.mock.calls.filter(([line]) => String(line).includes('states its call presents no delegation'))).toHaveLength(1);
    });
  });

  describe('for a proof that states nothing, as a client on an earlier release makes it', () => {
    it('runs the call beside either delegation under prefer, the default, with one warning', async () => {
      const warned = vi.spyOn(logger, 'warn');
      const { sendUnnamed, ranFor, partyOne, partyTwo, forPartyOne, forPartyTwo } = await twoParties();

      expect(await sendUnnamed({ ...ARGS, _kyaos_delegation: forPartyTwo })).toBe('ran');
      expect(await sendUnnamed({ ...ARGS, _kyaos_delegation: forPartyOne })).toBe('ran');
      expect(ranFor).toEqual([partyTwo.did, partyOne.did]);
      expect(warned.mock.calls.filter(([line]) => String(line).includes('does not state the delegation its call is made under'))).toHaveLength(1);
    });

    it('refuses the call under require, with a delegation and without one', async () => {
      const { send, sendUnnamed, ranFor, forPartyOne } = await twoParties({ requestBinding: 'require' });
      expect(await send({ ...ARGS, _kyaos_delegation: forPartyOne })).toBe('ran');
      ranFor.length = 0;

      expect(await sendUnnamed({ ...ARGS, _kyaos_delegation: forPartyOne })).toBe('holder_binding_failed');
      expect(await sendUnnamed(ARGS)).toBe('needs_authorization');
      expect(ranFor).toEqual([]);
    });
  });

  it('holds a proof to what it names for a session grant too, where holder binding only warns', async () => {
    const { kyaos, arrive, ranFor, agent, server, partyTwo, forPartyOne, forPartyTwo } = await twoParties({ holderBinding: 'warn' });
    const sessionId = (await kyaos.handleHandshake({
      nonce: `nonce-${Math.random().toString(36).slice(2)}`,
      audience: server.did,
      timestamp: Math.floor(Date.now() / 1000),
    })).sessionId as string;
    const proofNaming = (delegation: DelegationCredential) =>
      generateRequestProof({ identity: agent, crypto, toolName: TOOL, args: ARGS, audience: server.did, sessionId, delegation });
    // Party two's delegation binds a grant for the session.
    expect(await arrive({ ...ARGS, _kyaos_delegation: forPartyTwo, _kyaos_proof: await proofNaming(forPartyTwo) }, sessionId)).toBe('ran');
    ranFor.length = 0;

    expect(await arrive({ ...ARGS, _kyaos_proof: await proofNaming(forPartyOne) }, sessionId)).toBe('needs_authorization');
    expect(await arrive({ ...ARGS, _kyaos_proof: await proofNaming(forPartyTwo) }, sessionId)).toBe('ran');
    expect(ranFor).toEqual([partyTwo.did]);
  });

  it('runs a re-delegated call whose holder knows its own credential alone, the gate resolving the ancestors', async () => {
    const [user, agent, subAgent, server] = await Promise.all([party(), party(), party(), party()]);
    const root = await delegate(user, agent.did, { scopes: [SCOPE] });
    const leaf = await delegate(agent, subAgent.did, { parent: root, audience: server.did, scopes: [SCOPE] });
    const { send } = await gate(server, subAgent, {
      trustedRootIssuers: [user.did],
      resolveDelegationChain: async () => [root],
      requestBinding: 'require',
    });

    expect(await send({ ...ARGS, _kyaos_delegation: leaf })).toBe('ran');
  });

  it('refuses a re-delegated call under an ancestor issued again under the same id, where the leaf states its parent digest', async () => {
    const [user, agent, subAgent, server] = await Promise.all([party(), party(), party(), party()]);
    const root = await delegate(user, agent.did, { scopes: [SCOPE] });
    const leaf = await delegate(agent, subAgent.did, { parent: root, commits: true, audience: server.did, scopes: [SCOPE] });
    const again = await reissued(user, root, { scopes: [SCOPE, 'payments:refund'] });
    const resolved = { ancestors: [root] };
    const { send, ranFor } = await gate(server, subAgent, {
      trustedRootIssuers: [user.did],
      resolveDelegationChain: async () => resolved.ancestors,
      requestBinding: 'require',
    });

    expect(await send({ ...ARGS, _kyaos_delegation: leaf })).toBe('ran');
    ranFor.length = 0;
    resolved.ancestors = [again];
    expect(await send({ ...ARGS, _kyaos_delegation: leaf })).toBe('delegation_invalid');
    expect(ranFor).toEqual([]);
  });

  it('refuses a requestBinding it does not know when the middleware is created', async () => {
    const server = await party();
    const create = (requestBinding: unknown) =>
      createKyaOsMiddleware(
        { identity: server, delegation: { holderBinding: 'enforce', requestBinding } as KyaOsDelegationConfig },
        crypto,
      );
    await expect(async () => create('required')).rejects.toThrow(/delegation\.requestBinding must be "prefer" or "require"/);
    await expect(async () => create('required')).rejects.toThrow(TypeError);
  });
});
