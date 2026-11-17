/**
 * A read whose URL a counterparty named, held to what the private-network rule
 * (`./private-network-rule`) cannot decide from the URL alone, request by request, the first and
 * then each redirect the rule admits.
 *
 * A name that looks public may resolve to a private address. A transport that offers its
 * connections ({@link ADDRESS_PINNING}), as `RuntimeFetchProvider` does on a runtime that resolves
 * names, such as Node, is read by SafeFetch's own means: each request resolves its host once, is
 * refused when any address the host resolves to is not public (`./address-check`), and is connected
 * to those addresses alone, the first tried first and each other in turn, pinned, so a second lookup
 * cannot rebind it (`./pinned-connection`). That
 * refusal was learned from a lookup, not from the URL, so a verifier tells whoever named the URL only
 * that it could not be read, and the address goes to the log. A host written as an IP literal names
 * its own address, which the rule has checked, and is read through the transport's own `fetch`, as
 * is every request through a transport that offers no connections or admits private hosts.
 *
 * A read held to https ({@link PrivateNetworkRead.httpsOnly}), as a status list is (SPEC §4.4.2),
 * refuses an http URL, first or redirected, under `allowPrivateNetworkHosts` and on a private host
 * too, since over http an on-path party can replay an older signed list from before a revocation. It
 * reads http only at a first URL the operator names, which for a status list is an exact URL its
 * `statusListIssuers` binds, and from a private or local host under `development: true`
 * ({@link PrivateNetworkRead.httpOnPrivateHosts}), as a local demo serves its lists.
 */

import { resolveChecked, UNTOLD, type LookupRefusals } from './address-check.js';
import type { SingleFetch } from './checked-redirects.js';
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
   * Hold the URL and each redirect to https, as a status-list read is held (SPEC §4.4.2), the
   * opt-out notwithstanding. The first request alone may still be http when `operatorNamed` names
   * its URL, and any request when {@link httpOnPrivateHosts} admits its host.
   */
  readonly httpsOnly?: boolean;
  /**
   * Whether a read held to https reads http from a private or local host as well, first or
   * redirected, as `development: true` admits for a local demo.
   */
  readonly httpOnPrivateHosts?: boolean;
  /**
   * Bytes of body a pinned connection reads before it refuses the response: the read's own cap,
   * which the bounded reader holds the body to again. Default 1 MiB, the package's limit for one
   * outbound read.
   */
  readonly maxBytes?: number;
  /**
   * Which requests of the read the operator named, asked of each by the URL it asks for, the first
   * and each redirect (`./operator-named`). Each it names is read through the transport's own
   * `fetch` wherever its host is; every other is held as this module says.
   */
  readonly operatorNamed?: (url: string) => boolean;
}

/**
 * What the refusal of a name that resolves to a private address says after what it refused: the two
 * settings, and how an operator reads a host it names itself wherever that host is.
 */
const RESOLVED_HOST_SETTINGS =
  `${PRIVATE_HOST_SETTINGS} To read a host you name yourself, give the resolver or fetch provider that reads it ` +
  'the DIDs you pin in trustedRootIssuers, or the status-list URLs your statusListIssuers binds.';

/** What the refusal of an http URL in a read held to https says after what it refused, for the first request and for a redirect. */
const HTTPS_REMEDY = {
  request: ': this read takes https, and http only at a URL the operator binds exactly, or from a private or local host under development: true',
  redirect: ': this read takes https for every redirect, and http only from a private or local host under development: true',
} as const;

/**
 * `transport`'s `fetch` under the private-network rule, each request it makes held as this module
 * opens by saying. A refused request throws a {@link ReadFailureError}: an http URL is refused
 * before any lookup, `host_refused`, as `Request to a "http:" URL refused` or `Redirect to ...`; a
 * name that resolves to a private address `unavailable`, as a name that does not resolve is, as
 * `Request to <name> refused: it resolves to a private or local address`, or for a redirect without
 * naming the host, going on with what admits it.
 */
export function underPrivateNetworkRead(transport: PrivateNetworkTransport, read: PrivateNetworkRead = {}): FetchPort {
  return underPrivateNetworkRule(transport, { request: heldRequest(transport, read), operatorNamed: read.operatorNamed });
}

/** How each request of a read through `transport` is made, held as this module opens by saying. */
function heldRequest(transport: PrivateNetworkTransport, read: PrivateNetworkRead): SingleFetch {
  const admitPrivate = transport.allowPrivateNetworkHosts === true;
  const maxBytes = read.maxBytes ?? OUTBOUND_READ_MAX_BYTES;
  return async (url, init, { redirected }) => {
    const { protocol, hostname } = new URL(url);
    // Decided request by request, so a redirect from a URL the operator named is held as any other.
    const named = read.operatorNamed?.(url) === true;
    if (read.httpsOnly === true && protocol === 'http:' && !takesHttp(read, hostname, { named, redirected })) {
      const refused = redirected
        ? `Redirect to a ${describeValue(protocol)} URL refused${HTTPS_REMEDY.redirect}`
        : `Request to a ${describeValue(protocol)} URL refused${HTTPS_REMEDY.request}`;
      throw new ReadFailureError('host_refused', refused, redirected ? {} : { beforeRequest: true });
    }
    const admitted = admitPrivate || named;
    // An IP literal names its own address, which the rule has checked.
    const form = hostForm(hostname);
    if (admitted || form === undefined || 'literal' in form) return transport.fetch(url, init);
    const pinning = await pinningOf(transport, url);
    if (pinning === undefined) return transport.fetch(url, init);
    const pins = await resolveChecked(form.name, pinning.lookup, lookupRefusals(redirected));
    init.signal?.throwIfAborted();
    return requestPinned(pinning.transport, { url, init, hostname: form.name, pins, maxBytes });
  };
}

/**
 * Whether a read held to https takes an http request for a URL whose host is `hostname`: the first
 * request, for a URL the operator named, or any request to a private or local host where `read`
 * admits http there. A redirect is read over http from such a host alone, wherever it came from.
 */
function takesHttp(read: PrivateNetworkRead, hostname: string, request: { named: boolean; redirected: boolean }): boolean {
  if (read.httpOnPrivateHosts === true && isPrivateHost(hostname)) return true;
  return request.named && !request.redirected;
}

/**
 * How `transport` connects the request for `url` to an address the read checks, or `undefined` where
 * it does not, as for a `FetchProvider` that offers none, which is said once.
 */
async function pinningOf(transport: PrivateNetworkTransport, url: string): Promise<AddressPinning | undefined> {
  const offered = transport[ADDRESS_PINNING];
  if (offered !== undefined) return offered(url);
  warnHeldToUrlAlone(`${providerName(transport, 'A FetchProvider')} has a fetch of its own, which makes its own connections`);
  return undefined;
}

/**
 * How a request's lookup is refused. A name that resolves to a private address was learned from a
 * lookup, not from the URL, so it is refused as a name that does not resolve is, `unavailable`, and
 * its refusal does not say it was decided before the request: a code that told the two apart would
 * tell whoever named the host what the verifier's DNS answered. The log says `host_refused` and
 * names the host and the address; the refusal of a redirect names neither, since the server chose
 * the host.
 */
function lookupRefusals(redirected: boolean): LookupRefusals {
  const request = redirected ? 'Redirect' : 'Request';
  return {
    unresolved: (name) => new Error(`DNS lookup for ${describeValue(name)} returned no addresses`),
    nonPublic: (name) =>
      new ReadFailureError(
        'unavailable',
        redirected
          ? `Redirect to a host that resolves to a private or local address refused. ${RESOLVED_HOST_SETTINGS}`
          : `Request to ${describeValue(name)} refused: it resolves to a private or local address. ${RESOLVED_HOST_SETTINGS}`,
      ),
    logged: (name, address) => `[kya-os] ${request} to ${describeValue(name)} refused (host_refused): ${UNTOLD(address)}`,
  };
}
