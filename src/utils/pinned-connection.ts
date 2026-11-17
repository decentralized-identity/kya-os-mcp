/**
 * The connections of a read under the private-network rule on a runtime that resolves names: the
 * {@link AddressPinning} a transport offers, built from SafeFetch's own seams, and one request made
 * through it, connected to the address the read checked and answered as a `Response` the rule's
 * redirect handling and the bounded reader read. Nothing here decides what to refuse:
 * `./private-network-rule` and `./private-network-read` do.
 */

import { pinnedTo, type CheckedAddresses } from './address-check.js';
import { describeValue } from './describe-value.js';
import type { AddressPinning } from './fetch-port.js';
import { ReadFailureError } from './read-failure.js';
import { fetchRoutedThrough } from './routed-fetch.js';
import { warnHeldToUrlAlone } from './url-only-reads.js';
import { defaultLookup, runtimeResolvesNames, selectDefaultTransport } from './safe-fetch-transports.js';
import type { DnsLookup, RawResponse, SafeFetchTransport } from './safe-fetch-types.js';

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
 * Worker or a browser, or the runtime's `fetch` sends the request for the URL it is asked about
 * through a proxy (`./routed-fetch`), and the rule then refuses that host by the URL alone.
 */
export function addressPinning(seams: PinningSeams = {}): (url: string) => Promise<AddressPinning | undefined> {
  const transport = seams.transport ?? selectDefaultTransport();
  if (seams.lookup !== undefined) {
    const given: AddressPinning = { lookup: seams.lookup, transport };
    return () => Promise.resolve(given);
  }
  const runtime: AddressPinning = { lookup: defaultLookup, transport };
  return async (url) => {
    if (!(await runtimeResolvesNames())) {
      warnHeldToUrlAlone('this runtime resolves no host name, as its node:dns is missing or not implemented');
      return undefined;
    }
    return fetchRoutedThrough(url) === undefined ? runtime : undefined;
  };
}

/** One request through a pinned transport. */
export interface PinnedRequest {
  /** The URL to request, its host the name that resolved to `pin`. */
  readonly url: string;
  /** The request's headers and its signal; any other member is the transport's to ignore. */
  readonly init: RequestInit;
  /** The host name the URL names, without trailing dots: the TLS server name. */
  readonly hostname: string;
  /** The checked addresses to connect to, the first tried first. */
  readonly pins: CheckedAddresses;
  /** Bytes of body the transport reads before it refuses the response. */
  readonly maxBytes: number;
}

/**
 * Make `request` through `transport`, connected to its pinned address, without following a
 * redirect, and answer it as a `Response`: the transport's status, the response headers a read under
 * the rule reads ({@link READ_HEADERS}), and its body as the bytes that were sent when the transport
 * keeps them, so the bounded reader refuses a body that is not UTF-8, or else as its text.
 */
export async function requestPinned(transport: SafeFetchTransport, request: PinnedRequest): Promise<Response> {
  const { url, init, hostname, pins, maxBytes } = request;
  const raw = await transport(url, {
    signal: init.signal ?? new AbortController().signal,
    hostname,
    ...pinnedTo(pins),
    maxBytes,
    headers: Object.fromEntries(new Headers(init.headers ?? {})),
  });
  return answeredAsResponse(raw);
}

/** The response headers a read under the rule reads: where a redirect goes, and what the body is. */
const READ_HEADERS = ['location', 'content-type'] as const;

/** The statuses whose response has no body (Fetch standard, "null body status"). */
const NULL_BODY_STATUSES: ReadonlySet<number> = new Set([101, 103, 204, 205, 304]);

/**
 * `raw` as the `Response` a provider's `fetch` answers, with the headers in {@link READ_HEADERS}.
 * It names no URL and was not redirected, since the transport follows no redirect. A status no
 * `Response` may have, outside 200 to 599, is answered as the host being unavailable.
 */
async function answeredAsResponse(raw: RawResponse): Promise<Response> {
  if (!Number.isInteger(raw.status) || raw.status < 200 || raw.status > 599) {
    const status = typeof raw.status === 'number' ? String(raw.status) : describeValue(raw.status);
    throw new ReadFailureError('unavailable', `The host answered HTTP ${status}, which is no final response`);
  }
  const headers = new Headers();
  for (const name of READ_HEADERS) {
    const value = raw.headers.get(name);
    if (value !== null) headers.set(name, value);
  }
  if (NULL_BODY_STATUSES.has(raw.status)) return new Response(null, { status: raw.status, headers });
  const body = raw.bytes === undefined ? await raw.text() : ((await raw.bytes()) as Uint8Array<ArrayBuffer>);
  return new Response(body, { status: raw.status, headers });
}
