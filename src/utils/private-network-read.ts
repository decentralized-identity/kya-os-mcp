/**
 * A read whose URL a counterparty named, held to what the private-network rule
 * (`./private-network-rule`) cannot decide from the URL alone, request by request, the first and
 * then each redirect the rule admits.
 *
 * A name that looks public may resolve to a private address. A transport that offers its
 * connections ({@link ADDRESS_PINNING}), as `RuntimeFetchProvider` does on a runtime that resolves
 * names, such as Node, is read by SafeFetch's own means: each request resolves its host once, is
 * refused when any address the host resolves to is not public (`./address-check`), and is connected
 * to the first address, pinned, so a second lookup cannot rebind it (`./pinned-connection`). That
 * refusal was learned from a lookup, not from the URL, so a verifier tells whoever named the URL only
 * that it could not be read, and the address goes to the log. A host written as an IP literal names
 * its own address, which the rule has checked, and is read through the transport's own `fetch`, as
 * is every request through a transport that offers no connections or admits private hosts.
 *
 * A read held to https ({@link PrivateNetworkRead.httpsOnly}), as a status list is (SPEC §4.4.2),
 * refuses an http URL, first or redirected, unless its host is a private or local one the opt-out
 * admits, as a local demo serves its lists.
 */

import { logger } from '../logging/index.js';
import { checkResolvedAddresses } from './address-check.js';
import { describeValue } from './describe-value.js';
import { ADDRESS_PINNING, type AddressPinning, type FetchPort, type PrivateNetworkTransport } from './fetch-port.js';
import { hostForm } from './host-form.js';
import { OUTBOUND_READ_MAX_BYTES } from './outbound-read-limits.js';
import { requestPinned } from './pinned-connection.js';
import { isPrivateHost, PRIVATE_HOST_SETTINGS, underPrivateNetworkRule } from './private-network-rule.js';
import { ReadFailureError } from './read-failure.js';
import { providerName, warnHeldToUrlAlone } from './url-only-reads.js';

/** How a read is held beside the rule and the opt-out of its transport. */
export interface PrivateNetworkRead {
  /**
   * Hold the URL and each redirect to https, and admit http only from a private or local host the
   * opt-out admits, as a status-list read is held (SPEC §4.4.2).
   */
  readonly httpsOnly?: boolean;
  /**
   * Bytes of body a pinned connection reads before it refuses the response: the read's own cap,
   * which the bounded reader holds the body to again. Default 1 MiB, the package's limit for one
   * outbound read.
   */
  readonly maxBytes?: number;
}

/**
 * What the refusal of a name that resolves to a private address says after what it refused: the two
 * settings, and how an operator reads a host it names itself wherever that host is.
 */
const RESOLVED_HOST_SETTINGS =
  `${PRIVATE_HOST_SETTINGS} To read a host you name yourself, give the resolver or fetch provider that reads it ` +
  'the DIDs you pin in trustedRootIssuers, or the status-list URLs your statusListIssuers binds.';

/** What the refusal of an http URL in a read held to https says after what it refused. */
const HTTPS_REMEDY =
  ': this read takes https, and http only from a private or local host that development: true or ' +
  'allowPrivateNetworkHosts: true admits';

/**
 * `transport`'s `fetch` under the private-network rule, each request it makes held as this module
 * opens by saying. A refused request throws a `host_refused` {@link ReadFailureError}: an http URL
 * is refused before any lookup, as `Request to a "http:" URL refused` or `Redirect to ...`; a name
 * that resolves to a private address as `Request to <name> refused: it resolves to a private or
 * local address`, or for a redirect without naming the host, going on with what admits it.
 */
export function underPrivateNetworkRead(transport: PrivateNetworkTransport, read: PrivateNetworkRead = {}): FetchPort {
  return {
    // Each read has its own requests, the first and then its redirects.
    fetch: (url, init) => underPrivateNetworkRule(heldRequests(transport, read)).fetch(url, init),
  };
}

/** `transport` as one read's requests are made through it, each held as this module opens by saying. */
function heldRequests(transport: PrivateNetworkTransport, read: PrivateNetworkRead): PrivateNetworkTransport {
  const admitPrivate = transport.allowPrivateNetworkHosts === true;
  const maxBytes = read.maxBytes ?? OUTBOUND_READ_MAX_BYTES;
  let made = 0;
  return {
    allowPrivateNetworkHosts: admitPrivate,
    async fetch(url, options) {
      // The rule hands every request the read's own init.
      const init = (options ?? {}) as RequestInit;
      const redirected = made++ > 0;
      const { protocol, hostname } = new URL(url);
      if (read.httpsOnly === true && protocol === 'http:' && !(admitPrivate && isPrivateHost(hostname))) {
        const refused = `${redirected ? 'Redirect' : 'Request'} to a ${describeValue(protocol)} URL refused${HTTPS_REMEDY}`;
        throw new ReadFailureError('host_refused', refused, redirected ? {} : { beforeRequest: true });
      }
      // An IP literal names its own address, which the rule has checked.
      const form = hostForm(hostname);
      if (admitPrivate || form === undefined || 'literal' in form) return transport.fetch(url, init);
      const pinning = await pinningOf(transport);
      if (pinning === undefined) return transport.fetch(url, init);
      return pinnedRequest(pinning, { url, init, name: form.name, redirected, maxBytes });
    },
  };
}

/**
 * How `transport` connects a request to an address the read checks, or `undefined` where it does not,
 * as for a `FetchProvider` that offers none, which is said once.
 */
async function pinningOf(transport: PrivateNetworkTransport): Promise<AddressPinning | undefined> {
  const offered = transport[ADDRESS_PINNING];
  if (offered !== undefined) return offered();
  warnHeldToUrlAlone(`${providerName(transport, 'A FetchProvider')} has a fetch of its own, which makes its own connections`);
  return undefined;
}

/** One request through a pinned connection, to the host `name` the URL names. */
interface HeldRequest {
  readonly url: string;
  readonly init: RequestInit;
  readonly name: string;
  readonly redirected: boolean;
  readonly maxBytes: number;
}

/** `request` connected to the first address its name resolves to, once every address is shown public. */
async function pinnedRequest(pinning: AddressPinning, request: HeldRequest): Promise<Response> {
  const { url, init, name, redirected, maxBytes } = request;
  const checked = checkResolvedAddresses(await pinning.lookup(name));
  if ('unresolved' in checked) throw new Error(`DNS lookup for ${describeValue(name)} returned no addresses`);
  if ('nonPublic' in checked) throw resolvedToPrivate(name, checked.nonPublic, redirected);
  init.signal?.throwIfAborted();
  return requestPinned(pinning.transport, { url, init, hostname: name, pin: checked.pinned, maxBytes });
}

/**
 * The refusal of `name`, which resolved to the private `address`. It was learned from a lookup, not
 * from the URL, so it does not say it was decided before the request. The address goes to the log;
 * the refusal of a redirect names neither, since the server chose the host.
 */
function resolvedToPrivate(name: string, address: string, redirected: boolean): ReadFailureError {
  const host = describeValue(name);
  logger.warn(`[kya-os] ${redirected ? 'Redirect' : 'Request'} to ${host} refused: it resolves to the non-public address ${address}`);
  return new ReadFailureError(
    'host_refused',
    redirected
      ? `Redirect to a host that resolves to a private or local address refused. ${RESOLVED_HOST_SETTINGS}`
      : `Request to ${host} refused: it resolves to a private or local address. ${RESOLVED_HOST_SETTINGS}`,
  );
}
