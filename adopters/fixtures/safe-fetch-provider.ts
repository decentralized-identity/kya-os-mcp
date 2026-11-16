/**
 * An adopter reads every DID document through the library's SSRF-hardened `createSafeFetch`, and
 * hands the did:web resolver a `FetchProvider` whose `fetch` returns what SafeFetch returns. The
 * library's own fetch then has to work with the library's own resolver.
 *
 * SafeFetch's `lookup` seam names a public address for the issuer's host and its `transport` seam
 * answers from memory, so SafeFetch screens the host as it would in production and no network is
 * touched.
 */
import assert from 'node:assert/strict';
import {
  DelegationCredentialVerifier,
  FetchProvider,
  createDidWebResolver,
  type DIDDocument,
  type DelegationRecord,
  type StatusList2021Credential,
} from '@kya-os/mcp';
import { createSafeFetch, type SafeFetch } from '@kya-os/mcp/card';
import { runCases } from './shared/cases.js';
import { ed25519SignatureVerifier, issueDelegation } from './shared/credentials.js';
import { didDocumentOf, didKeyParty, didWebParty } from './shared/keys.js';
import { MemoryWeb } from './shared/web.js';

/** A public unicast address the lookup seam gives for every host. It is never contacted. */
const PUBLIC_ADDRESS = '93.184.215.14';

/**
 * The adopter's provider: SafeFetch decides which hosts are read and bounds each read, and this
 * hands its answer to the resolver. SafeFetch answers `{ ok, status, json }`, which is what a
 * did:web read used of a response, so the adopter returns it as the `Response` the type names.
 */
class SafeFetchProvider extends FetchProvider {
  readonly #safeFetch: SafeFetch;

  constructor(safeFetch: SafeFetch) {
    super();
    this.#safeFetch = safeFetch;
  }

  override async fetch(url: string): Promise<Response> {
    return (await this.#safeFetch(url)) as unknown as Response;
  }

  override async resolveDID(): Promise<DIDDocument | null> {
    return null;
  }

  override async fetchStatusList(): Promise<StatusList2021Credential | null> {
    return null;
  }

  override async fetchDelegationChain(): Promise<DelegationRecord[]> {
    return [];
  }
}

const issuer = await didWebParty('did:web:issuer.example');
const agent = await didKeyParty();
const web = new MemoryWeb();
web.serveDidDocument(didDocumentOf(issuer));

const safeFetch = createSafeFetch({
  lookup: async () => [{ address: PUBLIC_ADDRESS, family: 4 }],
  transport: web.transport(),
});
const resolver = createDidWebResolver(new SafeFetchProvider(safeFetch));
const credential = await issueDelegation(issuer, { id: 'issuer-to-agent', subjectDid: agent.did, scopes: ['notes:read'] });

await runCases('safe-fetch-provider', 'a did:web document read through createSafeFetch resolves, and a credential its DID issued verifies', [
  {
    name: 'control: the same document over a WHATWG Response resolves',
    run: async () => {
      const document = await createDidWebResolver(web.fetchProvider()).resolve(issuer.did);
      assert.equal(document?.id, issuer.did);
    },
  },
  {
    name: 'control: createSafeFetch itself reads the document through its seams',
    run: async () => {
      const response = await safeFetch('https://issuer.example/.well-known/did.json');
      assert.equal(response.ok, true);
      assert.equal((await response.json() as { id?: unknown }).id, issuer.did);
    },
  },
  {
    name: 'the did:web document resolves through a FetchProvider over createSafeFetch',
    run: async () => {
      const document = await resolver.resolve(issuer.did);
      assert.equal(document?.id, issuer.did, 'createDidWebResolver returned no document');
    },
  },
  {
    name: 'a credential that DID issued verifies',
    run: async () => {
      const verifier = new DelegationCredentialVerifier({ didResolver: resolver, signatureVerifier: ed25519SignatureVerifier });
      const result = await verifier.verifyDelegationCredential(credential);
      assert.equal(result.valid, true, result.reason ?? 'no reason given');
    },
  },
]);
