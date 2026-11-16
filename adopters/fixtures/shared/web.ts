/**
 * The network of a fixture: JSON bodies held in memory by URL, served in each of the three shapes an
 * adopter hands the library. Nothing here opens a socket.
 */
import {
  FetchProvider,
  didWebToUrl,
  type DIDDocument,
  type DelegationRecord,
  type StatusList2021Credential,
} from '@kya-os/mcp';
import type { SafeFetch, SafeFetchTransport } from '@kya-os/mcp/card';

/** Bodies by URL, each kept as the JSON text a server would send. */
export class MemoryWeb {
  readonly #bodies = new Map<string, string>();

  /** Serve `body` as JSON at `url`. */
  serve(url: string, body: unknown): void {
    this.#bodies.set(url, JSON.stringify(body));
  }

  /** Serve a did:web DID document at the URL its `id` resolves to. */
  serveDidDocument(document: DIDDocument): void {
    const url = didWebToUrl(document.id);
    if (url === null) throw new Error(`${document.id} is not a did:web DID`);
    this.serve(url, document);
  }

  /** The JSON text served at `url`, or `undefined` when nothing is. */
  textAt(url: string): string | undefined {
    return this.#bodies.get(url);
  }

  /** A `FetchProvider` whose `fetch` answers with a WHATWG `Response`, as `fetch` itself does. */
  fetchProvider(): FetchProvider {
    return new MemoryFetchProvider(this);
  }

  /** A `SafeFetch` that answers `{ ok, status, json }` from memory, as an adopter's test double does. */
  safeFetch(): SafeFetch {
    return async (url) => {
      const text = this.textAt(url);
      return {
        ok: text !== undefined,
        status: text === undefined ? 404 : 200,
        json: async () => JSON.parse(text ?? 'null') as unknown,
      };
    };
  }

  /** The `transport` seam of `createSafeFetch`, answering from memory once SafeFetch has screened the host. */
  transport(): SafeFetchTransport {
    return async (url) => {
      const text = this.textAt(url);
      return {
        status: text === undefined ? 404 : 200,
        headers: { get: (name) => (name.toLowerCase() === 'content-type' ? 'application/json' : null) },
        text: async () => text ?? '',
      };
    };
  }
}

/** The provider `MemoryWeb.fetchProvider` builds. Only `fetch` is read by the did:web resolver. */
class MemoryFetchProvider extends FetchProvider {
  readonly #web: MemoryWeb;

  constructor(web: MemoryWeb) {
    super();
    this.#web = web;
  }

  override async fetch(url: string): Promise<Response> {
    const text = this.#web.textAt(url);
    if (text === undefined) return new Response('not found', { status: 404 });
    return new Response(text, { status: 200, headers: { 'content-type': 'application/json' } });
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
