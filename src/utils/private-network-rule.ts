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
 * and the refusal of a private host names both settings. The refusal of a request names the host
 * the URL names; the refusal of a redirect to a private host does not name it, since the server
 * chose it and whoever named the URL may not know it, and the target goes to the log.
 */

import { logger } from '../logging/index.js';
import { fetchWithCheckedRedirects } from './checked-redirects.js';
import { describeValue } from './describe-value.js';
import type { FetchPort, PrivateNetworkTransport } from './fetch-port.js';
import { PRODUCTION_PRIVATE_HOSTS } from './development-mode.js';
import { hostForm } from './host-form.js';
import { isBlockedAddress } from './ip-classifier.js';
import { ReadFailureError } from './read-failure.js';

export type { PrivateNetworkTransport } from './fetch-port.js';

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
 * Whether `name`, a host name as the URL parser writes it (lowercase, IDNA-mapped, percent-decoded)
 * without trailing dots, is a local name: a single label, which a resolver completes through its
 * search domains to a host of the local network (`ip6-localhost`, or a bare `metadata` on Google
 * Cloud), or one of {@link LOCAL_DOMAINS} or a name under it.
 */
function isLocalName(name: string): boolean {
  if (!name.includes('.')) return true;
  return LOCAL_DOMAINS.some(domain => name === domain || name.endsWith(`.${domain}`));
}

/**
 * Whether the rule refuses `hostname`: a non-public IP literal, or a local name, with any trailing
 * dots, read as `./host-form` reads a host; a host that does not parse without them is refused too.
 */
function isPrivateHost(hostname: string): boolean {
  const form = hostForm(hostname);
  if (form === undefined) return true;
  return 'literal' in form ? isBlockedAddress(form.literal) : isLocalName(form.name);
}

/** The two settings that admit a private or local host. */
const PRIVATE_HOST_SETTINGS =
  `In local development, set development: true; to read private hosts in production, ${PRODUCTION_PRIVATE_HOSTS}.`;

/** What the refusal of a private or local host says after `refused`: what it is, and the two settings that admit it. */
export const PRIVATE_HOST_REMEDY = `: a private or local host. ${PRIVATE_HOST_SETTINGS}`;

/** How the rule refuses a URL: the name it gives the URL, and whether it refuses it as a private host. */
interface RuleRefusal {
  readonly named: string;
  readonly privateHost: boolean;
}

/**
 * What the rule makes of `url`: the URL as the parser writes it, which is what a read under the rule
 * fetches, so the host it checked is the host the transport reaches; or why it refuses `url`.
 */
function ruleVerdict(url: string, allowPrivateNetworkHosts: boolean): { readonly admitted: string } | RuleRefusal {
  const target = parsed(url);
  if (target === undefined) return { named: 'a URL that does not parse', privateHost: false };
  if (target.protocol !== 'https:' && target.protocol !== 'http:') {
    return { named: `a ${describeValue(target.protocol)} URL`, privateHost: false };
  }
  if (!allowPrivateNetworkHosts && isPrivateHost(target.hostname)) return { named: describeValue(target.host), privateHost: true };
  return { admitted: target.href };
}

/** Why the rule refuses `url`, or `undefined` when it admits it. */
function ruleRefusal(url: string, allowPrivateNetworkHosts: boolean): RuleRefusal | undefined {
  const verdict = ruleVerdict(url, allowPrivateNetworkHosts);
  return 'admitted' in verdict ? undefined : verdict;
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
 * private hosts. The transport is asked for the URL as the parser writes the one the rule checked,
 * never the string as given, which a transport could parse otherwise and so reach another host. A
 * refused request throws `Request to <host> refused`, going on for a private host
 * with {@link PRIVATE_HOST_REMEDY}, before any request. A refused redirect throws `Redirect to
 * <what> refused`, where a private host is named only as one, followed by the settings that admit
 * it, and is logged. Either is a `host_refused` {@link ReadFailureError}.
 */
export function underPrivateNetworkRule(transport: PrivateNetworkTransport): FetchPort {
  const allowPrivateNetworkHosts = transport.allowPrivateNetworkHosts === true;
  return {
    async fetch(url, init) {
      const verdict = ruleVerdict(url, allowPrivateNetworkHosts);
      if (!('admitted' in verdict)) {
        throw new ReadFailureError(
          'host_refused',
          `Request to ${verdict.named} refused${verdict.privateHost ? PRIVATE_HOST_REMEDY : ''}`,
          { beforeRequest: true },
        );
      }
      return fetchWithCheckedRedirects(
        (target, options) => transport.fetch(target, options),
        verdict.admitted,
        (init ?? {}) as RequestInit,
        target => redirectRefusal(target, allowPrivateNetworkHosts),
      );
    },
  };
}

/**
 * How the rule refuses a redirect to `target`, as the text that follows `Redirect to `, or
 * `undefined` when it admits it. A private host is not named, and is logged for the operator.
 */
function redirectRefusal(target: string, allowPrivateNetworkHosts: boolean): string | undefined {
  const refused = ruleRefusal(target, allowPrivateNetworkHosts);
  if (refused === undefined) return undefined;
  if (!refused.privateHost) return `${refused.named} refused`;
  logger.warn(`[kya-os] Redirect to ${refused.named} refused: a private or local host`);
  return `a private or local host refused. ${PRIVATE_HOST_SETTINGS}`;
}

/**
 * `transport` with the rule's opt-out turned on, for a reader given `development: true`: the same
 * `fetch`, called on `transport`, and `allowPrivateNetworkHosts: true`.
 */
export function admittingPrivateHosts(transport: PrivateNetworkTransport): PrivateNetworkTransport {
  return { fetch: (url, options) => transport.fetch(url, options), allowPrivateNetworkHosts: true };
}
