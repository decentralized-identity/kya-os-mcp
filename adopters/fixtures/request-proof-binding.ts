/**
 * An agent holds two delegations of one scope, from two owners, and calls a gated tool under the
 * first. Its request proof is the one `generateRequestProof` makes from the arguments the call
 * sends, with no other input, and it states the delegation among them (SPEC.md §7.8). A party on
 * the path that has seen the second delegation and holds no key puts it in place of the first: a
 * server that enforces holder binding refuses the call, with no setting beyond that. A proof that
 * names no credential, as a client on an earlier release makes it, still runs under the default,
 * and is refused once the server sets `delegation.requestBinding: 'require'`. Every party is a
 * did:key, so nothing is read over a network.
 */
import assert from 'node:assert/strict';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  ProofGenerator,
  base64urlEncodeFromBytes,
  generateRequestProof,
  serveInProcess,
  toHolderBindingRequest,
  withKyaOs,
  type DelegationCredential,
  type DetachedProof,
  type KyaOsToolHandler,
  type WithKyaOsOptions,
} from '@kya-os/mcp';
import { runCases } from './shared/cases.js';
import { issueDelegation } from './shared/credentials.js';
import { crypto, didKeyParty, type Party } from './shared/keys.js';

const TOOL = 'payments.send';
const SCOPE = 'payments:send';
const CONSENT = { scopeId: SCOPE, consentUrl: 'https://payments.example/consent' };
const PAYMENT = { to: 'acct-7', amount: 10 };

type Args = Record<string, unknown>;

/** A payments server that enforces holder binding and trusts `owners`, and how a call reaches it. */
async function paymentsServer(owners: Party[], delegation: NonNullable<WithKyaOsOptions['delegation']> = {}) {
  const kyaos = await withKyaOs(new McpServer({ name: 'payments', version: '1.0.0' }), {
    crypto,
    delegation: { holderBinding: 'enforce', trustedRootIssuers: owners.map((owner) => owner.did), ...delegation },
  });
  const local = serveInProcess(kyaos);
  /** The owner each call the tool ran was decided under. */
  const ranFor: (string | undefined)[] = [];
  const sendPayment: KyaOsToolHandler = async (_args, _sessionId, context) => {
    ranFor.push(context?.principal?.responsibleParty);
    return { content: [{ type: 'text', text: 'sent' }] };
  };
  const send = local.tool(TOOL, kyaos.wrapWithDelegation(TOOL, CONSENT, sendPayment));
  /** What a call that arrives with `args` comes to: `ran`, or the error it was refused with. */
  const arrive = async (args: Args): Promise<string> => {
    const text = String((await send(args)).content[0]?.text);
    return text === 'sent' ? 'ran' : (JSON.parse(text) as { error: string }).error;
  };
  return { did: kyaos.identity.did, arrive, ranFor, close: () => local.close() };
}

/** A delegation of {@link SCOPE} that `owner` signs to `agent` for the server `audience`. */
const delegationFrom = (owner: Party, agent: Party, audience: string): Promise<DelegationCredential> =>
  issueDelegation(owner, { id: `${owner.did}:payments`, subjectDid: agent.did, scopes: [SCOPE], audience });

/** A request proof as a client made it before proofs stated their delegation: the proof generator alone. */
async function proofOfAnEarlierClient(agent: Party, args: Args, audience: string): Promise<DetachedProof> {
  const now = Math.floor(Date.now() / 1000);
  return new ProofGenerator(agent, crypto).generateProof(toHolderBindingRequest(TOOL, args), undefined, {
    sessionId: `req-${base64urlEncodeFromBytes(await crypto.randomBytes(9))}`,
    audience,
    nonce: base64urlEncodeFromBytes(await crypto.randomBytes(16)),
    timestamp: now,
    createdAt: now,
    lastActivity: now,
    ttlMinutes: 30,
    identityState: 'anonymous',
  });
}

/** Two owners, the agent both delegated to, a server set up with `delegation`, and both delegations. */
async function twoOwners(delegation: NonNullable<WithKyaOsOptions['delegation']> = {}) {
  const [ownerOne, ownerTwo, agent] = await Promise.all([didKeyParty(), didKeyParty(), didKeyParty()]);
  const server = await paymentsServer([ownerOne, ownerTwo], delegation);
  return {
    ownerOne,
    agent,
    server,
    fromOwnerOne: await delegationFrom(ownerOne, agent, server.did),
    fromOwnerTwo: await delegationFrom(ownerTwo, agent, server.did),
  };
}

await runCases('request-proof-binding', 'a proof generateRequestProof makes from the arguments a call sends is refused beside any other delegation, and requestBinding: require refuses a proof that names none', [
  {
    name: 'control: the call the agent sends runs under the delegation it chose',
    run: async () => {
      const { ownerOne, agent, server, fromOwnerOne } = await twoOwners();
      const args = { ...PAYMENT, _kyaos_delegation: fromOwnerOne };
      const proof = await generateRequestProof({ identity: agent, crypto, toolName: TOOL, args, audience: server.did });
      assert.equal(await server.arrive({ ...args, _kyaos_proof: proof }), 'ran');
      assert.deepEqual(server.ranFor, [ownerOne.did]);
      await server.close();
    },
  },
  {
    name: 'another delegation of the agent, put in place of the one it sent, is refused, and the tool does not run',
    run: async () => {
      const { agent, server, fromOwnerOne, fromOwnerTwo } = await twoOwners();
      const args = { ...PAYMENT, _kyaos_delegation: fromOwnerOne };
      const proof = await generateRequestProof({ identity: agent, crypto, toolName: TOOL, args, audience: server.did });
      assert.equal(await server.arrive({ ...args, _kyaos_delegation: fromOwnerTwo, _kyaos_proof: proof }), 'holder_binding_failed');
      assert.deepEqual(server.ranFor, []);
      await server.close();
    },
  },
  {
    name: 'a client that attaches its delegation after signing names it with the delegation input',
    run: async () => {
      const { ownerOne, agent, server, fromOwnerOne, fromOwnerTwo } = await twoOwners({ requestBinding: 'require' });
      const proof = () => generateRequestProof({ identity: agent, crypto, toolName: TOOL, args: PAYMENT, audience: server.did, delegation: fromOwnerOne });
      assert.equal(await server.arrive({ ...PAYMENT, _kyaos_delegation: fromOwnerOne, _kyaos_proof: await proof() }), 'ran');
      assert.equal(await server.arrive({ ...PAYMENT, _kyaos_delegation: fromOwnerTwo, _kyaos_proof: await proof() }), 'holder_binding_failed');
      assert.deepEqual(server.ranFor, [ownerOne.did]);
      await server.close();
    },
  },
  {
    name: 'a proof that names no credential, as an earlier client makes it, runs under the default',
    run: async () => {
      const { ownerOne, agent, server, fromOwnerOne } = await twoOwners();
      const args = { ...PAYMENT, _kyaos_delegation: fromOwnerOne };
      assert.equal(await server.arrive({ ...args, _kyaos_proof: await proofOfAnEarlierClient(agent, args, server.did) }), 'ran');
      assert.deepEqual(server.ranFor, [ownerOne.did]);
      await server.close();
    },
  },
  {
    name: "requestBinding: 'require' refuses that proof, and runs the one generateRequestProof makes",
    run: async () => {
      const { ownerOne, agent, server, fromOwnerOne } = await twoOwners({ requestBinding: 'require' });
      const args = { ...PAYMENT, _kyaos_delegation: fromOwnerOne };
      assert.equal(await server.arrive({ ...args, _kyaos_proof: await proofOfAnEarlierClient(agent, args, server.did) }), 'holder_binding_failed');
      assert.deepEqual(server.ranFor, []);
      const proof = await generateRequestProof({ identity: agent, crypto, toolName: TOOL, args, audience: server.did });
      assert.equal(await server.arrive({ ...args, _kyaos_proof: proof }), 'ran');
      assert.deepEqual(server.ranFor, [ownerOne.did]);
      await server.close();
    },
  },
  {
    name: 'a requestBinding that is neither prefer nor require is refused at startup',
    run: async () => {
      const owner = await didKeyParty();
      await assert.rejects(paymentsServer([owner], { requestBinding: 'required' as 'require' }), /delegation\.requestBinding/);
    },
  },
]);
