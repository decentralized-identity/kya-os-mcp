/**
 * The check SafeFetch (`./safe-fetch`) and a read under the private-network rule
 * (`./private-network-read`) make of the addresses a host name resolves to, before either connects: every address is
 * classified as `./ip-classifier` classifies one, and the connection is pinned to the first. A name
 * is resolved once for a request, so a resolver that answers a public address beside a private one,
 * as split-horizon DNS may, is refused rather than raced, and no second lookup can move the
 * connection to an address that was not checked.
 */

import { isBlockedAddress } from './ip-classifier.js';
import type { DnsAddress } from './safe-fetch-types.js';

/** What the check makes of the addresses one host name resolved to. */
export type AddressCheck =
  /** Connect to this address, pinned: every address is public, or private ones are admitted. */
  | { readonly pinned: DnsAddress }
  /** Refuse the name: this address, the first that is not public, is one it resolves to. */
  | { readonly nonPublic: string }
  /** The name resolved to no address. */
  | { readonly unresolved: true };

/**
 * The check of `addresses`, every address one host name resolved to: the first, to pin the
 * connection to, once every one is public, or whatever they are when `admitPrivate`; else the first
 * address that is not public.
 */
export function checkResolvedAddresses(addresses: readonly DnsAddress[], admitPrivate = false): AddressCheck {
  const [first] = addresses;
  if (first === undefined) return { unresolved: true };
  const blocked = admitPrivate ? undefined : addresses.find((candidate) => isBlockedAddress(candidate.address));
  return blocked === undefined ? { pinned: first } : { nonPublic: blocked.address };
}
