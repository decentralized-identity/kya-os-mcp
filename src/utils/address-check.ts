/**
 * The check SafeFetch (`./safe-fetch`) and a read under the private-network rule
 * (`./private-network-read`) make of the addresses a host name resolves to, before either connects: every address is
 * classified as `./ip-classifier` classifies one, and the connection is pinned to the first. A name
 * is resolved once for a request, so a resolver that answers a public address beside a private one,
 * as split-horizon DNS may, is refused rather than raced, and no second lookup can move the
 * connection to an address that was not checked.
 */

import { logger } from '../logging/index.js';
import { isBlockedAddress } from './ip-classifier.js';
import type { DnsAddress, DnsLookup } from './safe-fetch-types.js';

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

/** How a reader words what {@link resolveChecked} refuses, each in its own voice. */
export interface LookupRefusals {
  /** The error for `name`, whose lookup answered no address. */
  unresolved(name: string): Error;
  /** The error for `name`, which resolves to an address that is not public; it does not say the address. */
  nonPublic(name: string): Error;
  /** The operator's log line for `name`, which resolves to the address `address`, which is not public. */
  logged(name: string, address: string): string;
}

/**
 * Resolve the host `name` once through `lookup`, check every address it answers, and answer the one
 * to pin the connection to, as SafeFetch and a read under the private-network rule both do before
 * they connect. A name with no address, or with any address that is not public unless
 * `admitPrivate`, is refused in the reader's own words (`refusals`), and the address that is not
 * public goes to the log alone.
 */
export async function resolveChecked(
  name: string,
  lookup: DnsLookup,
  refusals: LookupRefusals,
  admitPrivate = false,
): Promise<DnsAddress> {
  const checked = checkResolvedAddresses(await lookup(name), admitPrivate);
  if ('unresolved' in checked) throw refusals.unresolved(name);
  if ('nonPublic' in checked) {
    logger.warn(refusals.logged(name, checked.nonPublic));
    throw refusals.nonPublic(name);
  }
  return checked.pinned;
}
