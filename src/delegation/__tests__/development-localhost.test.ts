/**
 * A local demo runs every party on a `*.localhost` name. The private-network rule refuses those
 * names, as it must in production, and the refusal says what admits them: `development: true` in
 * local development, and `allowPrivateNetworkHosts: true` on the fetch provider in production.
 * `development: true` on a reader admits private and local hosts for its reads and changes nothing
 * else; it refuses to be turned on while `NODE_ENV` is `production`, and warns once per process.
 * Every test uses the package's public exports, as an adopter would.
 */

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  buildDidWebDocument,
  createDidWebResolver,
  logger,
  NodeCryptoProvider,
  statusListGzipCodec,
  type AgentIdentity,
  type CredentialStatus,
  type DIDDocument,
} from '../../index.js';
import { createSafeFetch } from '../../card/index.js';
import { CheqdStatusListResolver } from '../../integrations/cheqd/index.js';
import { AnsweringFetchProvider } from '../../__tests__/utils/adopter-providers.js';
import { keyOf } from '../../__tests__/utils/delegation-credentials.js';

const ISSUER = 'did:web:issuer.localhost%3A4101';
const DOCUMENT_URL = 'https://issuer.localhost:4101/.well-known/did.json';
const REFUSAL =
  'Request to "issuer.localhost:4101" refused: a private or local host. In local development, set development: true; ' +
  'to read private hosts in production, give the fetch provider allowPrivateNetworkHosts: true.';

let key: AgentIdentity;
let document: DIDDocument;
beforeAll(async () => {
  key = await keyOf(ISSUER, 'key-1');
  document = buildDidWebDocument(key);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

/** A provider that answers each body at its URL as a JSON `Response`, and 404 for any other URL. */
const serving = (bodies: Readonly<Record<string, unknown>>) =>
  new AnsweringFetchProvider((url) =>
    Object.prototype.hasOwnProperty.call(bodies, url) ? Response.json(bodies[url]) : new Response('not found', { status: 404 }),
  );

/** The messages `logger.warn` was given while `work` ran. */
async function warnings(work: () => unknown): Promise<string[]> {
  const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  await work();
  return warn.mock.calls.map(([message]) => String(message));
}

describe('a did:web DID on a *.localhost name', () => {
  // Kept first: the warning is given once per process, and each test file runs in a process of its own.
  it('resolves with development: true, after one warning for the process, and the provider is asked', async () => {
    const provider = serving({ [DOCUMENT_URL]: document });
    const said = await warnings(async () => {
      expect(await createDidWebResolver(provider, { development: true }).resolve(ISSUER)).toEqual(document);
      expect(await createDidWebResolver(provider, { development: true }).resolve(ISSUER)).toEqual(document);
    });
    expect(said).toEqual([
      '[kya-os] development: true is on (DidWebResolverOptions.development), so private and local hosts such as ' +
        '*.localhost are read. Never use it in production.',
    ]);
    expect(provider.requested).toEqual([DOCUMENT_URL, DOCUMENT_URL]);
  });

  it('is refused without it, before any request, and the refusal names both settings', async () => {
    const provider = serving({ [DOCUMENT_URL]: document });
    const said = await warnings(async () => expect(await createDidWebResolver(provider).resolve(ISSUER)).toBeNull());
    expect(said).toEqual([`[DidWebResolver] Error resolving ${ISSUER}: ${REFUSAL}`]);
    expect(provider.requested).toEqual([]);
  });

  it('is read with development: false, or none, exactly as without it', async () => {
    for (const options of [{ development: false }, { development: undefined }, {}]) {
      expect(await createDidWebResolver(serving({ [DOCUMENT_URL]: document }), options).resolve(ISSUER)).toBeNull();
    }
  });

  it('keeps every other rule with development: true: the scheme of a redirect, and the byte cap', async () => {
    const redirecting = new AnsweringFetchProvider(() => new Response(null, { status: 302, headers: { location: 'file:///etc/passwd' } }));
    const said = await warnings(async () => {
      expect(await createDidWebResolver(redirecting, { development: true }).resolve(ISSUER)).toBeNull();
      const oversized = serving({ [DOCUMENT_URL]: { ...document, padding: 'x'.repeat(2 * 1024 * 1024) } });
      expect(await createDidWebResolver(oversized, { development: true }).resolve(ISSUER)).toBeNull();
    });
    expect(said).toEqual([
      `[DidWebResolver] Error resolving ${ISSUER}: Redirect to a "file:" URL refused`,
      `[DidWebResolver] Error resolving ${ISSUER}: DID resolution byte limit exceeded`,
    ]);
  });

  it('refuses a value that is not a boolean, naming the option', () => {
    expect(() => createDidWebResolver(serving({}), { development: 'true' as unknown as boolean })).toThrow(
      new TypeError('DidWebResolverOptions.development must be true or false'),
    );
  });
});

describe('development: true while NODE_ENV is production', () => {
  const refusal = (setting: string, optIn = 'give the fetch provider allowPrivateNetworkHosts: true') =>
    new Error(
      `${setting} is true while NODE_ENV is "production": development: true reads private and local hosts and must never ` +
        `run in production. Remove it; to read private hosts in production, ${optIn}.`,
    );

  it('throws when the did:web resolver is built, naming the setting', () => {
    vi.stubEnv('NODE_ENV', 'production');
    expect(() => createDidWebResolver(serving({}), { development: true })).toThrow(refusal('DidWebResolverOptions.development'));
    expect(() => createDidWebResolver(serving({}))).not.toThrow();
  });

  it('throws when the cheqd status-list resolver is built, naming the setting', () => {
    vi.stubEnv('NODE_ENV', 'production');
    expect(() => cheqdResolver(true)).toThrow(refusal('CheqdStatusListResolverOptions.development'));
  });

  it('throws when SafeFetch is built, naming the setting and its own production opt-in', () => {
    vi.stubEnv('NODE_ENV', 'production');
    expect(() => createSafeFetch({ development: true })).toThrow(
      refusal('SafeFetchOptions.development', "list each origin you own in SafeFetch's allowOrigins"),
    );
  });

  it('turns development on in a runtime whose environment cannot be read', async () => {
    const env = Object.getOwnPropertyDescriptor(process, 'env')!;
    Object.defineProperty(process, 'env', { configurable: true, get: () => { throw new Error('no environment access'); } });
    try {
      expect(() => createDidWebResolver(serving({}), { development: true })).not.toThrow();
    } finally {
      Object.defineProperty(process, 'env', env);
    }
  });
});

/** A cheqd status-list resolver for `ISSUER`'s lists, with `development` as given. */
function cheqdResolver(development: boolean, provider = serving({})): CheqdStatusListResolver {
  return new CheqdStatusListResolver({
    fetchProvider: provider,
    didResolver: { resolve: async () => null },
    cryptoProvider: new NodeCryptoProvider(),
    expectedIssuerDid: ISSUER,
    decompressor: statusListGzipCodec,
    development,
  });
}

describe('a status list on a *.localhost name', () => {
  const LIST_URL = 'https://status.localhost:4101/lists/1';
  const entry: CredentialStatus = {
    id: `${LIST_URL}#7`, type: 'StatusList2021Entry', statusPurpose: 'revocation', statusListIndex: '7', statusListCredential: LIST_URL,
  };
  const list = {
    id: LIST_URL, type: ['VerifiableCredential', 'StatusList2021Credential'], issuer: ISSUER,
    credentialSubject: { type: 'StatusList2021', statusPurpose: 'revocation', encodedList: 'H4sIAAAAAAAAA2NgAAAAAP__AwAAAAAAAAA' },
    proof: { type: 'Ed25519Signature2020', verificationMethod: `${ISSUER}#key-1`, proofPurpose: 'assertionMethod', proofValue: 'z1' },
  };

  it('is refused by the cheqd status-list resolver without development: true, naming both settings', async () => {
    const provider = serving({ [LIST_URL]: list });
    await expect(cheqdResolver(false, provider).checkStatus(entry)).rejects.toThrow(
      REFUSAL.replace('issuer.localhost:4101', 'status.localhost:4101'),
    );
    expect(provider.requested).toEqual([]);
  });

  it('is read by the cheqd status-list resolver with development: true, which then holds the list to its issuer', async () => {
    const provider = serving({ [LIST_URL]: list });
    await expect(cheqdResolver(true, provider).checkStatus(entry)).rejects.toThrow(`Could not resolve issuer DID ${ISSUER}`);
    expect(provider.requested).toEqual([LIST_URL]);
  });
});

describe('SafeFetch reading a host whose address is a loopback one', () => {
  const safeFetch = (development: boolean) =>
    createSafeFetch({
      development,
      lookup: async () => [{ address: '127.0.0.1', family: 4 }],
      transport: async () => ({ status: 200, headers: { get: () => null }, text: async () => '{"ok":true}' }),
    });

  it('refuses it without development: true, saying what admits it', async () => {
    await expect(safeFetch(false)('https://status.localhost/lists/1')).rejects.toThrow(
      'safe-fetch: refusing non-public address 127.0.0.1 for host "status.localhost": in local development, set development: true; ' +
        "to read a host you own in production, list each origin you own in SafeFetch's allowOrigins",
    );
  });

  it('reads it with development: true, still over https alone', async () => {
    expect(await (await safeFetch(true)('https://status.localhost/lists/1')).json()).toEqual({ ok: true });
    await expect(safeFetch(true)('http://status.localhost/lists/1')).rejects.toThrow('safe-fetch: only https is allowed (got "http:")');
  });
});
