/**
 * `RuntimeFetchProvider` reads did:web documents and status lists through the private-network
 * rule, whose refusal of a `*.localhost` name says to set `development: true` in local development.
 * The provider takes that setting as every other reader does: it admits private and local hosts for
 * its reads, `resolveDID` and `fetchStatusList` (and so a `ProofVerifier` built over it), warns once
 * per process, refuses to be built with it while `NODE_ENV` is `production`, and refuses a value
 * that is not a boolean. Every test uses the package's public exports.
 */

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { buildDidWebDocument, logger, RuntimeFetchProvider, type DIDDocument } from '../../index.js';
import { keyOf } from '../../__tests__/utils/delegation-credentials.js';

const ISSUER = 'did:web:issuer.localhost%3A4101';
const DOCUMENT_URL = 'https://issuer.localhost:4101/.well-known/did.json';
const LIST_URL = 'https://status.localhost:4101/lists/1';
const LIST = {
  id: LIST_URL,
  type: ['VerifiableCredential', 'StatusList2021Credential'],
  issuer: ISSUER,
  credentialSubject: { type: 'StatusList2021', statusPurpose: 'revocation', encodedList: 'H4sIAAAAAAAAA2NgAAAAAP__AwAAAAAAAAA' },
};

let document: DIDDocument;
let requested: string[];
beforeAll(async () => {
  document = buildDidWebDocument(await keyOf(ISSUER, 'key-1'));
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

/** Serve the issuer's document and its list over the global `fetch`, recording each URL asked for. */
function serveLocally(): void {
  requested = [];
  const bodies: Record<string, unknown> = { [DOCUMENT_URL]: document, [LIST_URL]: LIST };
  vi.stubGlobal('fetch', async (url: string) => {
    requested.push(url);
    return url in bodies ? Response.json(bodies[url]) : new Response('not found', { status: 404 });
  });
}

/** The messages `logger.warn` was given while `work` ran. */
async function warnings(work: () => Promise<unknown>): Promise<string[]> {
  const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  try {
    await work();
    return warn.mock.calls.map(([message]) => String(message));
  } finally {
    warn.mockRestore();
  }
}

describe('RuntimeFetchProvider with development: true', () => {
  // Kept first: the warning is given once per process, and each test file runs in a process of its own.
  it('resolves a did:web DID and reads a status list on *.localhost names, after one warning for the process', async () => {
    serveLocally();
    const said = await warnings(async () => {
      const provider = new RuntimeFetchProvider({ development: true });
      expect(provider.allowPrivateNetworkHosts).toBe(true);
      expect(await provider.resolveDID(ISSUER)).toEqual(document);
      expect(await provider.fetchStatusList(LIST_URL)).toEqual(LIST);
      expect(await new RuntimeFetchProvider({ development: true }).resolveDID(ISSUER)).toEqual(document);
    });
    expect(said).toEqual([
      '[kya-os] development: true is on (RuntimeFetchProviderOptions.development), so private and local hosts such as ' +
        '*.localhost are read. Never use it in production.',
    ]);
    expect(requested).toEqual([DOCUMENT_URL, LIST_URL, DOCUMENT_URL]);
  });

  it('refuses those hosts without it, before any request, with a refusal that names it', async () => {
    serveLocally();
    for (const options of [undefined, {}, { development: false }]) {
      const said = await warnings(async () => {
        const provider = new RuntimeFetchProvider(options);
        expect(provider.allowPrivateNetworkHosts).toBe(false);
        expect(await provider.resolveDID(ISSUER)).toBeNull();
        expect(await provider.fetchStatusList(LIST_URL)).toBeNull();
      });
      expect(said).toEqual([
        `[DidWebResolver] Error resolving ${ISSUER}: Request to "issuer.localhost:4101" refused: a private or local host. ` +
          'In local development, set development: true; to read private hosts in production, give the fetch provider allowPrivateNetworkHosts: true.',
      ]);
    }
    expect(requested).toEqual([]);
  });

  it('throws when it is built while NODE_ENV is production, naming the setting', () => {
    vi.stubEnv('NODE_ENV', 'production');
    expect(() => new RuntimeFetchProvider({ development: true })).toThrow(
      new Error(
        'RuntimeFetchProviderOptions.development is true while NODE_ENV is "production": development: true reads private and ' +
          'local hosts and must never run in production. Remove it; to read private hosts in production, give the fetch ' +
          'provider allowPrivateNetworkHosts: true.',
      ),
    );
    expect(new RuntimeFetchProvider({ allowPrivateNetworkHosts: true }).allowPrivateNetworkHosts).toBe(true);
  });

  it('refuses a value that is not a boolean, naming the option', () => {
    expect(() => new RuntimeFetchProvider({ development: 'true' as unknown as boolean })).toThrow(
      new TypeError('RuntimeFetchProviderOptions.development must be true or false'),
    );
  });
});
