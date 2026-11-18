/**
 * A server gates a tool with `withKyaOs` and gives the delegation gate a DID resolver of its own,
 * as `delegation.didResolver` or as the resolver `delegation.didResolvers` configures for did:web,
 * which passes its failure on as `DIDResolver.lastFailure` documents. When that resolver finds no
 * document for an issuer's DID, the gate still asks its own did:web resolver, and a document that
 * one finds is used. When neither finds one, the refusal shows the failure the host's resolver
 * reported, never the one the gate's own read reported after it, whichever of the two reads local
 * hosts in development.
 *
 * A client connected over MCP presents a two-hop chain: a did:key root the server trusts delegates
 * to an agent on a `*.localhost` did:web name, and the agent delegates on to the client. The host's
 * resolver serves no did:key DID, so the gate's own did:key resolver reads the root's. Every DID
 * document is served by a fetch provider in memory, and the package is used through its public
 * exports, as an adopter uses it.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import {
  buildDidWebDocument,
  createDidWebResolver,
  generateIdentity,
  logger,
  NodeCryptoProvider,
  toMcpToolCallback,
  withKyaOs,
  type AgentIdentity,
  type DelegationCredential,
  type DIDResolver,
  type FetchProvider,
  type KyaOsDelegationConfig,
  type KyaOsIdentityConfig,
} from '../../index.js';
import { AnsweringFetchProvider } from '../../__tests__/utils/adopter-providers.js';
import { delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { delegate, party } from './helpers/delegating-party.js';

const crypto = new NodeCryptoProvider();
const AGENT = 'did:web:agent.localhost%3A4102';
const AGENT_DOCUMENT_URL = 'https://agent.localhost:4102/.well-known/did.json';
const TOOL = 'notes.read';
const SCOPE = 'notes:read';

/** The refusal of the agent's delegation as unresolvable, before any detail it ends with. */
const UNRESOLVED = `Delegation leaf invalid: Could not resolve issuer DID: "${AGENT}"`;
/** The detail of a refusal of the agent's local name by the private-network rule, before any request. */
const LOCAL_NAME_REFUSED = ' (Request to "agent.localhost:4102" refused: a private or local host. In local development, set development: true;';

let serverIdentity: KyaOsIdentityConfig;
let rootDid: string;
let agent: AgentIdentity;
let grant: DelegationCredential;
let leaf: DelegationCredential;

beforeAll(async () => {
  serverIdentity = await generateIdentity(crypto);
  const root = await party();
  rootDid = root.did;
  agent = await keyOf(AGENT, 'key-1');
  grant = await delegate(root, AGENT, { id: 'grant', scopes: [SCOPE], audience: serverIdentity.did });
  const constraints = { scopes: [SCOPE], audience: serverIdentity.did, notAfter: Math.floor(Date.now() / 1000) + 3600 };
  leaf = await signedCredential(agent, {
    record: delegationRecord(AGENT, { id: 'leaf', parentId: 'grant', subjectDid: 'did:web:client.example', constraints }),
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** A provider that answers the agent's DID document URL with `body`, and 404 for any other URL. */
const serving = (body?: unknown) =>
  new AnsweringFetchProvider((url) =>
    body !== undefined && url === AGENT_DOCUMENT_URL ? Response.json(body) : new Response('not found', { status: 404 }),
  );

/** A resolver of the host's over `inner`, passing on its failure as `DIDResolver.lastFailure` documents. */
const forwarding = (inner: DIDResolver): DIDResolver => ({
  resolve: (did) => inner.resolve(did),
  lastFailure: (did) => inner.lastFailure?.(did),
});

/** Where a host puts its resolver in the middleware's `delegation` options. */
type Slot = (resolver: DIDResolver) => KyaOsDelegationConfig;
const SLOTS: [string, Slot][] = [
  ['its own resolver, delegation.didResolver', (resolver) => ({ didResolver: resolver })],
  ['the resolver delegation.didResolvers configures for did:web', (resolver) => ({ didResolvers: { web: resolver } })],
];

/** What the operator's log and the client were told of one call. */
interface Outcome {
  allowed: boolean;
  reason?: string;
  /** The refusal code the gate's log line carries. */
  code?: string;
}

/**
 * The outcome of a client's call of {@link TOOL} under the agent's delegation, on a `withKyaOs`
 * server that trusts the root, finds the root's grant with its chain resolver, and takes `delegation`
 * and `development`.
 */
async function callUnder(delegation: KyaOsDelegationConfig, development = false): Promise<Outcome> {
  const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  const server = new McpServer({ name: 'notes', version: '1.0.0' });
  const kyaos = await withKyaOs(server, {
    crypto,
    identity: serverIdentity,
    development,
    delegation: { trustedRootIssuers: [rootDid], resolveDelegationChain: async () => [grant], ...delegation },
  });
  const gated = kyaos.wrapWithDelegation(TOOL, { scopeId: SCOPE, consentUrl: 'https://notes.example/consent' }, async () => ({
    content: [{ type: 'text', text: 'note 7' }],
  }));
  server.registerTool(TOOL, { inputSchema: { _kyaos_delegation: z.unknown().optional() } }, toMcpToolCallback(gated));
  const client = new Client({ name: 'agent', version: '1.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  try {
    const result = await client.callTool({ name: TOOL, arguments: { _kyaos_delegation: leaf } });
    if (result.isError !== true) return { allowed: true };
    const [first] = result.content as { text: string }[];
    const { reason } = JSON.parse(first!.text) as { reason?: string };
    const logged = warn.mock.calls.find(([line]) => String(line).startsWith(`[kya-os] Delegation verification failed for "${TOOL}"`));
    return { allowed: false, reason, code: (logged?.[1] as { code?: string } | undefined)?.code };
  } finally {
    await client.close();
    await server.close();
  }
}

describe.each(SLOTS)('a withKyaOs server with %s', (_label, slot) => {
  it("refuses with the failure the host's resolver reports, not the one the gate's own did:web read reports after it", async () => {
    // The host's resolver holds the agent's local name to the private-network rule, and refuses it
    // before any request. The gate reads local hosts in development, and finds no document there.
    const hostReads = serving(buildDidWebDocument(agent));
    const gateReads = serving();
    const outcome = await callUnder({ ...slot(forwarding(createDidWebResolver(hostReads))), fetchProvider: gateReads }, true);

    expect(outcome).toMatchObject({ allowed: false, code: 'host_refused' });
    expect(outcome.reason).toContain(`${UNRESOLVED}${LOCAL_NAME_REFUSED}`);
    expect(hostReads.requested).toEqual([]);
    expect(gateReads.requested).toEqual([AGENT_DOCUMENT_URL]);
  });

  it("refuses with the failure of the host's resolver built with development: true, not the gate's refusal of the local name", async () => {
    // The host's resolver reads the agent's local name in development and finds a document of another
    // DID there, which tells the presenter nothing more. The gate, not in development, refuses the name.
    const hostReads = serving({ ...buildDidWebDocument(agent), id: 'did:web:somewhere.example' });
    const gateReads = serving(buildDidWebDocument(agent));
    const outcome = await callUnder({ ...slot(forwarding(createDidWebResolver(hostReads, { development: true }))), fetchProvider: gateReads });

    expect(outcome).toEqual({ allowed: false, reason: UNRESOLVED, code: 'did_invalid' });
    expect(hostReads.requested).toEqual([AGENT_DOCUMENT_URL]);
    expect(gateReads.requested).toEqual([]);
  });

  it("still asks the gate's own did:web resolver, and allows the call on the document it finds", async () => {
    const hostReads = serving(buildDidWebDocument(agent));
    const gateReads = serving(buildDidWebDocument(agent));
    const outcome = await callUnder({ ...slot(forwarding(createDidWebResolver(hostReads))), fetchProvider: gateReads }, true);

    expect(outcome).toEqual({ allowed: true });
    expect(gateReads.requested).toEqual([AGENT_DOCUMENT_URL]);
  });
});

it("keeps the failure the host's own resolver reports when the resolver configured after it throws", async () => {
  const hostReads = serving({ ...buildDidWebDocument(agent), id: 'did:web:somewhere.example' });
  const outcome = await callUnder({
    didResolver: forwarding(createDidWebResolver(hostReads, { development: true })),
    didResolvers: { web: { resolve: () => Promise.reject(new Error('the configured resolver is down')) } },
    fetchProvider: serving(),
  });

  expect(outcome).toEqual({ allowed: false, reason: UNRESOLVED, code: 'did_invalid' });
});
