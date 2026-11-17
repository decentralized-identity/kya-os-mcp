/**
 * The connections of a read under the private-network rule on a runtime that resolves names: the
 * {@link AddressPinning} a transport offers, built from SafeFetch's own seams, and one request made
 * through it, connected to the address the read checked and answered as a `Response` the rule's
 * redirect handling and the bounded reader read. Nothing here decides what to refuse:
 * `./private-network-rule` and `./private-network-read` do.
 */

import type { AddressPinning } from './fetch-port.js';
import { fetchRoutedThrough } from './routed-fetch.js';
import { defaultLookup, runtimeResolvesNames, selectDefaultTransport } from './safe-fetch-transports.js';
import type { DnsAddress, DnsLookup, RawResponse, SafeFetchTransport } from './safe-fetch-types.js';

/** The seams of an {@link AddressPinning}, each optional, as SafeFetch's options take them. */
export interface PinningSeams {
  readonly lookup?: DnsLookup;
  readonly transport?: SafeFetchTransport;
}

/**
 * The {@link AddressPinning} of a runtime: `seams.lookup`, or else SafeFetch's default lookup where
 * the runtime resolves names ({@link runtimeResolvesNames}), and `seams.transport`, or else
 * SafeFetch's default transport, which pins the connection through `node:https` where it loads. It
 * resolves to `undefined` where no lookup was given and the runtime resolves no name, as in a
 * Worker or a browser, or the application routes the runtime's `fetch` through a proxy or another
 * dispatcher of its own (`./routed-fetch`), and the rule then refuses hosts by the URL alone.
 */
export function addressPinning(seams: PinningSeams = {}): () => Promise<AddressPinning | undefined> {
  const transport = seams.transport ?? selectDefaultTransport();
  if (seams.lookup !== undefined) {
    const given: AddressPinning = { lookup: seams.lookup, transport };
    return () => Promise.resolve(given);
  }
  const runtime: AddressPinning = { lookup: defaultLookup, transport };
  return async () => ((await runtimeResolvesNames()) && fetchRoutedThrough() === undefined ? runtime : undefined);
}

/** One request through a pinned transport. */
export interface PinnedRequest {
  /** The URL to request, its host the name that resolved to `pin`. */
  readonly url: string;
  /** The request's headers and its signal; any other member is the transport's to ignore. */
  readonly init: RequestInit;
  /** The host name the URL names, without trailing dots: the TLS server name. */
  readonly hostname: string;
  /** The checked address to connect to. */
  readonly pin: DnsAddress;
  /** Bytes of body the transport reads before it refuses the response. */
  readonly maxBytes: number;
}

/**
 * Make `request` through `transport`, connected to its pinned address, without following a
 * redirect, and answer it as a `Response`: the transport's status and headers, and its body as the
 * bytes that were sent when the transport keeps them, so the bounded reader refuses a body that is
 * not UTF-8, or else as its text.
 */
export async function requestPinned(transport: SafeFetchTransport, request: PinnedRequest): Promise<Response> {
  const { url, init, hostname, pin, maxBytes } = request;
  const raw = await transport(url, {
    signal: init.signal ?? new AbortController().signal,
    hostname,
    pinnedAddress: pin.address,
    family: pin.family,
    maxBytes,
    headers: Object.fromEntries(new Headers(init.headers ?? {})),
  });
  return answeredAsResponse(raw);
}

/**
 * `raw` as the `Response` a provider's `fetch` answers. It names no URL and was not redirected,
 * since the transport follows no redirect, and its headers are read by name alone.
 */
async function answeredAsResponse(raw: RawResponse): Promise<Response> {
  const bytes = raw.bytes === undefined ? undefined : await raw.bytes();
  const response = {
    ok: raw.status >= 200 && raw.status < 300,
    status: raw.status,
    headers: raw.headers,
    redirected: false,
    url: '',
    body: bytes === undefined ? null : new Response(bytes as Uint8Array<ArrayBuffer>).body,
    text: () => raw.text(),
  };
  return response as unknown as Response;
}
