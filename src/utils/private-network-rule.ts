/**
 * The private-network rule for a read whose URL a counterparty named, such as a did:web DID or a
 * credential's status list. A URL that is not an absolute http or https URL is refused, and so is
 * one whose host is a non-public IP literal or a local name, with or without trailing dots, which a
 * resolver ignores, all before any request. Every redirect
 * is followed by hand (`./checked-redirects`), its target held to the same rule, so a runtime never
 * carries the read on to a host the rule refuses. An IP literal is classified as SafeFetch
 * classifies a resolved address (`./ip-classifier`), so an IPv4-mapped, IPv4-translated or NAT64
 * form of a private address is refused as that address is. The rule resolves no name: it refuses a
 * local name by the name alone, and admits any other name whatever its address, so a public name
 * whose address is private is not refused here. Run verifiers behind an egress control for that.
 *
 * The one opt-out is `allowPrivateNetworkHosts: true` on the transport, an option of
 * `RuntimeFetchProvider` and a member any `FetchProvider` may declare. It admits non-public IP
 * literals and local names; the scheme rule holds, and redirects are still followed by hand.
 * `development: true` on a reader turns it on for that reader's transport ({@link admittingPrivateHosts}),
 * and the refusal of a private host names both settings.
 */

import { fetchWithCheckedRedirects, type TargetRefusal } from './checked-redirects.js';
import { describeValue } from './describe-value.js';
import type { FetchPort, PrivateNetworkTransport } from './fetch-port.js';
import { PRODUCTION_PRIVATE_HOSTS } from './development-mode.js';
import { isBlockedAddress } from './ip-classifier.js';

export type { PrivateNetworkTransport } from './fetch-port.js';

/** An IPv4 host as the URL parser writes one, whatever form the URL gave it in. */
const IPV4_HOST = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/**
 * Special-use domains whose names a resolver answers from local configuration, never from public
 * DNS: `localhost` (RFC 6761 §6.3), `localdomain` (`localhost.localdomain` in many hosts files),
 * `localdomain6` (`localhost6.localdomain6`, the IPv6 loopback in RHEL and Fedora hosts files),
 * `local` (multicast DNS, RFC 6762), `internal` (reserved for private use, and the cloud metadata
 * names `metadata.google.internal` and `instance-data.ec2.internal`) and `home.arpa` (RFC 8375).
 */
const LOCAL_DOMAINS = ['localhost', 'localdomain', 'localdomain6', 'local', 'internal', 'home.arpa'];

/** `url` parsed, or `undefined` when it is not an absolute URL. */
function parsed(url: string): URL | undefined {
  try {
    return new URL(url);
  } catch {
    return undefined;
  }
}

/**
 * `hostname`, as the URL parser writes it, without the trailing dots a resolver ignores, written as
 * the parser writes the rest: it keeps `127.0.0.1..` as a name, though a resolver reads it as the
 * address `127.0.0.1`. `undefined` when the rest does not parse, as `1.2.3.4.5` does not.
 */
function withoutTrailingDots(hostname: string): string | undefined {
  let end = hostname.length;
  while (hostname[end - 1] === '.') end--;
  return end === hostname.length ? hostname : parsed(`http://${hostname.slice(0, end)}/`)?.hostname;
}

/**
 * Whether `name`, a host name as the URL parser writes it (lowercase, IDNA-mapped, percent-decoded)
 * without trailing dots, is a local name: a single label, which a resolver completes through its
 * search domains to a host of the local network (`ip6-localhost`, or a bare `metadata` on Google
 * Cloud), or one of {@link LOCAL_DOMAINS} or a name under it.
 */
function isLocalName(name: string): boolean {
  if (!name.includes('.')) return true;
  return LOCAL_DOMAINS.some(domain => name === domain || name.endsWith(`.${domain}`));
}

/** Whether the rule refuses `hostname`: a non-public IP literal, or a local name, with any trailing dots. */
function isPrivateHost(hostname: string): boolean {
  if (hostname.startsWith('[')) return isBlockedAddress(hostname.slice(1, -1));
  const host = withoutTrailingDots(hostname);
  if (host === undefined) return true;
  if (IPV4_HOST.test(host)) return isBlockedAddress(host);
  return isLocalName(host);
}

/** What the refusal of a private or local host says after `refused`: what it is, and the two settings that admit it. */
export const PRIVATE_HOST_REMEDY =
  `: a private or local host. In local development, set development: true; to read private hosts in production, ${PRODUCTION_PRIVATE_HOSTS}.`;

/** How the rule refuses a URL: the name it gives the URL, and whether it refuses it as a private host. */
interface RuleRefusal {
  readonly named: string;
  readonly privateHost: boolean;
}

/** Why the rule refuses `url`, or `undefined` when it admits it. */
function ruleRefusal(url: string, allowPrivateNetworkHosts: boolean): RuleRefusal | undefined {
  const target = parsed(url);
  if (target === undefined) return { named: 'a URL that does not parse', privateHost: false };
  if (target.protocol !== 'https:' && target.protocol !== 'http:') {
    return { named: `a ${describeValue(target.protocol)} URL`, privateHost: false };
  }
  if (!allowPrivateNetworkHosts && isPrivateHost(target.hostname)) return { named: describeValue(target.host), privateHost: true };
  return undefined;
}

/**
 * How the rule names `url` when it refuses it, or `undefined` when it admits it: a URL that does
 * not parse as an absolute URL, which a runtime might resolve against a base of its own choosing; a
 * scheme other than http and https; and, unless `allowPrivateNetworkHosts` is true, a private host.
 */
export function privateNetworkRefusal(url: string, allowPrivateNetworkHosts = false): string | undefined {
  return ruleRefusal(url, allowPrivateNetworkHosts)?.named;
}

/**
 * `transport`'s `fetch` under the rule; a transport whose `allowPrivateNetworkHosts` is true admits
 * private hosts. A refused request or redirect throws `Request to <url> refused` or
 * `Redirect to <url> refused`, and for a private host goes on with {@link PRIVATE_HOST_REMEDY}.
 */
export function underPrivateNetworkRule(transport: PrivateNetworkTransport): FetchPort {
  const allowPrivateNetworkHosts = transport.allowPrivateNetworkHosts === true;
  const refusal: TargetRefusal = url => {
    const refused = ruleRefusal(url, allowPrivateNetworkHosts);
    return refused && `${refused.named} refused${refused.privateHost ? PRIVATE_HOST_REMEDY : ''}`;
  };
  return {
    async fetch(url, init) {
      const refused = refusal(url);
      if (refused !== undefined) throw new Error(`Request to ${refused}`);
      return fetchWithCheckedRedirects((target, options) => transport.fetch(target, options), url, (init ?? {}) as RequestInit, refusal);
    },
  };
}

/**
 * `transport` with the rule's opt-out turned on, for a reader given `development: true`: the same
 * `fetch`, called on `transport`, and `allowPrivateNetworkHosts: true`.
 */
export function admittingPrivateHosts(transport: PrivateNetworkTransport): PrivateNetworkTransport {
  return { fetch: (url, options) => transport.fetch(url, options), allowPrivateNetworkHosts: true };
}
