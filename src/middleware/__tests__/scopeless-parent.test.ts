/**
 * A delegation that grants no scope grants none to a re-delegation under it (SPEC.md §6.4). A
 * `withKyaOs` server trusts Alice as its one root issuer and gates a tool on `admin:delete`. Alice
 * signs Bob a delegation that names the server and no scope, as an identity-only or audience-only
 * grant does, so presented alone it does not run the tool. Bob then signs his own agent a
 * re-delegation under it that adds `admin:delete`: the gate refuses the chain, naming Alice's
 * delegation, and the tool does not run. A re-delegation under it that adds no scope keeps the chain
 * valid, and the tool still refuses it for want of the scope. Real Ed25519 did:keys sign every
 * credential, and an MCP client calls the tool as an agent would.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { z } from 'zod';
import type { DelegationCredential } from '../../types/protocol.js';
import { toMcpToolCallback } from '../mcp-tool-callback.js';
import { withKyaOs } from '../with-kya-os-server.js';
import { delegate, party, type Party } from './helpers/delegating-party.js';
import { crypto } from './helpers/received-proof.js';

const TOOL = 'records.delete';
const SCOPE = 'admin:delete';

/** What the server answered a call: `ran` when the tool ran, else the error it refused with and its reason. */
interface Answer {
  outcome: string;
  reason?: string;
}

/**
 * A `withKyaOs` server that trusts `root` alone and gates {@link TOOL} on {@link SCOPE}, with an MCP
 * client connected to it. Its chain resolver hands back whatever ancestors the call names.
 */
async function serverTrusting(root: string) {
  let ancestors: DelegationCredential[] = [];
  let runs = 0;
  const server = new McpServer({ name: 'records', version: '1.0.0' });
  const kyaos = await withKyaOs(server, {
    crypto,
    delegation: { trustedRootIssuers: [root], resolveDelegationChain: async () => ancestors },
  });
  const gated = kyaos.wrapWithDelegation(TOOL, { scopeId: SCOPE, consentUrl: 'https://records.example/consent' }, async () => {
    runs += 1;
    return { content: [{ type: 'text', text: 'deleted' }] };
  });
  server.registerTool(TOOL, { inputSchema: { _kyaos_delegation: z.unknown().optional() } }, toMcpToolCallback(gated));
  const client = new Client({ name: 'agent', version: '1.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return {
    did: kyaos.identity.did,
    /** The server's answer to a call presenting `credential`, whose ancestors are `chain`, root first. */
    call: async (credential: DelegationCredential, chain: DelegationCredential[] = []): Promise<Answer> => {
      ancestors = chain;
      const before = runs;
      const result = await client.callTool({ name: TOOL, arguments: { _kyaos_delegation: credential } });
      if (runs > before) return { outcome: 'ran' };
      const [first] = result.content as { text: string }[];
      const { error, reason } = JSON.parse(first!.text) as { error: string; reason?: string };
      return { outcome: error, ...(reason === undefined ? {} : { reason }) };
    },
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

let alice: Party, bob: Party, agent: Party;
beforeAll(async () => {
  [alice, bob, agent] = await Promise.all([party(), party(), party()]);
});

let close: (() => Promise<void>) | undefined;
afterEach(async () => {
  await close?.();
  close = undefined;
});

/** The server trusting Alice, and Alice's delegation to Bob for it, granting `scopes`. */
async function aliceDelegatesToBob(scopes: string[]) {
  const server = await serverTrusting(alice.did);
  close = server.close;
  const root = await delegate(alice, bob.did, { scopes, audience: server.did });
  return { server, root };
}

describe('a re-delegation under a delegation that grants no scope', () => {
  it('runs the tool for a chain whose root grants the scope, the control', async () => {
    const { server, root } = await aliceDelegatesToBob([SCOPE]);
    const leaf = await delegate(bob, agent.did, { parent: root, scopes: [SCOPE], audience: server.did });

    expect(await server.call(leaf, [root])).toEqual({ outcome: 'ran' });
  });

  it('does not run the tool for the root that grants no scope, presented alone', async () => {
    const { server, root } = await aliceDelegatesToBob([]);

    expect((await server.call(root)).outcome).toBe('insufficient_scope');
  });

  it('is refused when it adds a scope, with a reason that names the root and says it grants none', async () => {
    const { server, root } = await aliceDelegatesToBob([]);
    const leaf = await delegate(bob, agent.did, { parent: root, scopes: [SCOPE], audience: server.did });

    const answer = await server.call(leaf, [root]);

    expect(answer.outcome).toBe('delegation_invalid');
    const [rootId, leafId] = [root, leaf].map((credential) => credential.credentialSubject.delegation.id);
    expect(answer.reason).toBe(`Delegation ${leafId} widens scopes beyond parent ${rootId}, which grants no scope`);
  });

  it('keeps the chain valid when it adds no scope, and the tool still refuses it for want of the scope', async () => {
    const { server, root } = await aliceDelegatesToBob([]);
    const leaf = await delegate(bob, agent.did, { parent: root, scopes: [], audience: server.did });

    expect((await server.call(leaf, [root])).outcome).toBe('insufficient_scope');
  });
});
