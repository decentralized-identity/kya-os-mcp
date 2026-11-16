/**
 * Host names for the tests of the private-network rule (`utils/private-network-rule.ts`), which
 * resolves no name and so refuses by the name alone.
 */

/**
 * Names the rule refuses that are neither IP literals nor `localhost`: single labels, which a
 * resolver completes through its search domains to a local host (`ip6-localhost` and
 * `ip6-loopback` in many hosts files, a bare `metadata` on Google Cloud), and names under the
 * special-use domains `localdomain`, `localdomain6` (`localhost6.localdomain6`, the IPv6 loopback in
 * RHEL and Fedora hosts files), `internal` (the cloud metadata names), `local` (RFC 6762) and
 * `home.arpa` (RFC 8375). Each is written as the URL parser writes a host.
 */
export const LOCAL_HOST_NAMES = [
  'ip6-localhost', 'ip6-loopback', 'metadata', 'xn--localhost-', 'localhost.localdomain', 'localhost6.localdomain6',
  'metadata.google.internal', 'instance-data.ec2.internal', 'printer.local', 'router.home.arpa',
] as const;

/**
 * A public name whose public DNS answer is the loopback address. The rule admits it: it resolves no
 * name, so the address a public name has is known only when the runtime connects to it.
 */
export const PUBLIC_NAME_FOR_LOOPBACK = '127.0.0.1.nip.io';
