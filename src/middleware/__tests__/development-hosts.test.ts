/**
 * A developer runs a server with `withKyaOs`, and the root it trusts on a `*.localhost` did:web name,
 * as every local demo does. The gate reads that root's DID document under the private-network rule,
 * which refuses the name, as it must in production. `development: true` on `withKyaOs`, or on
 * `KyaOsConfig`, admits private and local hosts for every resolver the middleware builds, through
 * the provider the developer gives it or the one it builds itself, and tells each resolver factory so.
 * It refuses to start while `NODE_ENV` is `production`. Every test uses the package's public exports,
 * as an adopter would.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  buildDidWebDocument,
  createDidWebResolver,
  createKyaOsMiddleware,
  generateIdentity,
  logger,
  NodeCryptoProvider,
  serveInProcess,
  withKyaOs,
  type AgentIdentity,
  type DelegationCredential,
  type DIDDocument,
  type DIDResolverFactoryContext,
  type KyaOsConfig,
  type KyaOsDelegationConfig,
  type KyaOsMiddleware,
} from '../../index.js';
import { AnsweringFetchProvider } from '../../__tests__/utils/adopter-providers.js';
import { delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';

const crypto = new NodeCryptoProvider();
const ROOT = 'did:web:root.localhost%3A4101';
const DOCUMENT_URL = 'https://root.localhost:4101/.well-known/did.json';
const TOOL = 'notes.read';
const SCOPE = 'notes:read';

let key: AgentIdentity;
let document: DIDDocument;
beforeAll(async () => {
  key = await keyOf(ROOT, 'key-1');
  document = buildDidWebDocument(key);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

/** A provider that serves the root's DID document at its URL, and 404 for any other URL. */
const servingRoot = () =>
  new AnsweringFetchProvider((url) => (url === DOCUMENT_URL ? Response.json(document) : new Response('not found', { status: 404 })));

/** The root's delegation of {@link SCOPE} on `server`'s DID, which the caller presents. */
function rootDelegation(server: KyaOsMiddleware): Promise<DelegationCredential> {
  const constraints = { scopes: [SCOPE], audience: server.identity.did, notAfter: Math.floor(Date.now() / 1000) + 3600 };
  return signedCredential(key, { record: delegationRecord(ROOT, { constraints }) });
}

/** What a client sees when it calls {@link TOOL} on `server` under the root's delegation. */
async function callUnderRoot(server: KyaOsMiddleware): Promise<{ allowed: boolean; refusal?: { error?: string; reason?: string } }> {
  const local = serveInProcess(server);
  try {
    const readNote = local.tool(
      TOOL,
      server.wrapWithDelegation(TOOL, { scopeId: SCOPE, consentUrl: 'https://notes.example/consent' }, async () => ({
        content: [{ type: 'text', text: 'note 7' }],
      })),
    );
    const result = await readNote({ id: '7', _kyaos_delegation: await rootDelegation(server) });
    if (result.isError !== true) return { allowed: true };
    return { allowed: false, refusal: JSON.parse(String(result.content[0]?.text)) as { error?: string; reason?: string } };
  } finally {
    await local.close();
  }
}

/** A `withKyaOs` server that trusts the root and reads through `delegation`'s provider, with `development` if given. */
const serverWith = (delegation: KyaOsDelegationConfig, development?: boolean) =>
  withKyaOs(new McpServer({ name: 'notes', version: '1.0.0' }), {
    crypto,
    delegation: { trustedRootIssuers: [ROOT], ...delegation },
    ...(development === undefined ? {} : { development }),
  });

describe('withKyaOs with a root on a *.localhost did:web name', () => {
  // Kept first: the warning is given once per process, and each test file runs in a process of its own.
  it('allows a call under the root with development: true, after one warning naming the setting', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const provider = servingRoot();
    expect(await callUnderRoot(await serverWith({ fetchProvider: provider }, true))).toEqual({ allowed: true });
    expect(provider.requested).toEqual([DOCUMENT_URL]);
    expect(warn.mock.calls.map(([message]) => String(message))).toContain(
      '[kya-os] development: true is on (KyaOsConfig.development), so private and local hosts such as *.localhost are read. ' +
        'Never use it in production.',
    );
  });

  it('refuses the call without it, before any request', async () => {
    for (const development of [undefined, false]) {
      const provider = servingRoot();
      const outcome = await callUnderRoot(await serverWith({ fetchProvider: provider }, development));
      expect(outcome).toMatchObject({ allowed: false, refusal: { error: 'delegation_invalid' } });
      expect(provider.requested).toEqual([]);
    }
  });

  it("reads through the provider the middleware builds over the runtime's fetch when none is given", async () => {
    const requested: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => {
      requested.push(String(url));
      return String(url) === DOCUMENT_URL ? Response.json(document) : new Response('not found', { status: 404 });
    });
    const config: KyaOsConfig = {
      identity: await generateIdentity(crypto),
      delegation: { trustedRootIssuers: [ROOT] },
      development: true,
    };
    expect(await callUnderRoot(createKyaOsMiddleware(config, crypto))).toEqual({ allowed: true });
    expect(requested).toEqual([DOCUMENT_URL]);
  });

  it('tells a did:web resolver factory it runs in development, and says nothing of it otherwise', async () => {
    for (const development of [true, undefined]) {
      const contexts: (DIDResolverFactoryContext | undefined)[] = [];
      const didResolvers = {
        web: (fetchProvider: Parameters<typeof createDidWebResolver>[0], context?: DIDResolverFactoryContext) => {
          contexts.push(context);
          return createDidWebResolver(fetchProvider, { development: context?.development });
        },
      };
      const outcome = await callUnderRoot(await serverWith({ fetchProvider: servingRoot(), didResolvers }, development));
      expect(outcome.allowed).toBe(development === true);
      expect(contexts).toEqual([{ dependencyTimeoutMs: 5000, ...(development ? { development: true } : {}) }]);
    }
  });
});

describe('development: true on the middleware', () => {
  const refusal = (setting: string) =>
    new Error(
      `${setting} is true while NODE_ENV is "production": development: true reads private and local hosts and must never ` +
        'run in production. Remove it; to read private hosts in production, give the fetch provider allowPrivateNetworkHosts: true.',
    );

  it('throws at startup while NODE_ENV is production, from createKyaOsMiddleware and from withKyaOs', async () => {
    const identity = await generateIdentity(crypto);
    vi.stubEnv('NODE_ENV', 'production');
    expect(() => createKyaOsMiddleware({ identity, development: true }, crypto)).toThrow(refusal('KyaOsConfig.development'));
    await expect(serverWith({ fetchProvider: servingRoot() }, true)).rejects.toThrow(refusal('KyaOsConfig.development'));
    expect(() => createKyaOsMiddleware({ identity, development: false }, crypto)).not.toThrow();
  });

  it('refuses a value that is not a boolean, naming the setting', async () => {
    const identity = await generateIdentity(crypto);
    expect(() => createKyaOsMiddleware({ identity, development: 'yes' as unknown as boolean }, crypto)).toThrow(
      new TypeError('KyaOsConfig.development must be true or false'),
    );
  });
});
