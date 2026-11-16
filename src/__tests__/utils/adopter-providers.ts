/**
 * Fetch providers written the way adopters write them, over the package's public exports: one whose
 * `fetch` answers with what the library's own `createSafeFetch` returns, cast to `Response`, and one
 * that answers whatever object a test gives it. SafeFetch runs through its `lookup` and `transport`
 * seams, so every name resolves to a public address and nothing touches the network.
 */

import { FetchProvider, type DIDDocument, type DelegationRecord, type StatusList2021Credential } from '../../index.js';
import { createSafeFetch, type SafeFetch } from '../../card/index.js';

/** A public unicast address SafeFetch's screen admits. */
const PUBLIC_ADDRESS = '93.184.216.34';

/**
 * A `createSafeFetch` that serves each body at its URL, as JSON text unless it is a string, and
 * answers 404 for any other URL.
 */
export function safeFetchServing(bodies: Readonly<Record<string, unknown>>): SafeFetch {
  return createSafeFetch({
    lookup: async () => [{ address: PUBLIC_ADDRESS, family: 4 }],
    transport: async (url) => {
      const served = Object.prototype.hasOwnProperty.call(bodies, url);
      const body = served ? bodies[url] : undefined;
      const text = typeof body === 'string' ? body : JSON.stringify(body ?? null);
      return { status: served ? 200 : 404, headers: { get: () => null }, text: async () => text };
    },
  });
}

/**
 * A `FetchProvider` whose `fetch` answers with what `answer` returns for the URL, cast to `Response`,
 * as an adopter's adapter does. Its other lookups find nothing.
 */
export class AnsweringFetchProvider extends FetchProvider {
  readonly requested: string[] = [];

  constructor(private readonly answer: (url: string) => unknown) {
    super();
  }

  async resolveDID(): Promise<DIDDocument | null> {
    return null;
  }

  async fetchStatusList(): Promise<StatusList2021Credential | null> {
    return null;
  }

  async fetchDelegationChain(): Promise<DelegationRecord[]> {
    return [];
  }

  async fetch(url: string): Promise<Response> {
    this.requested.push(url);
    return (await this.answer(url)) as Response;
  }
}

/** An adopter's `FetchProvider` over `safeFetch`: each answer is SafeFetch's response, cast to `Response`. */
export function safeFetchProvider(safeFetch: SafeFetch): AnsweringFetchProvider {
  return new AnsweringFetchProvider((url) => safeFetch(url));
}
