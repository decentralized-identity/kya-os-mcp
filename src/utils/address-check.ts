/**
 * The check SafeFetch (`./safe-fetch`) and a read under the private-network rule
 * (`./private-network-read`) make of the addresses a host name resolves to, before either connects: every address is
 * classified as `./ip-classifier` classifies one, and the connection is pinned to them, the first
 * tried first and the others in turn when it cannot be reached, as the runtime's own fallback tries
 * a host's addresses. A name is resolved once for a request, so a resolver that answers a public
 * address beside a private one, as split-horizon DNS may, is refused rather than raced, and no
 * second lookup can move the connection to an address that was not checked.
 */

import { logger } from '../logging/index.js';
import { isBlockedAddress } from './ip-classifier.js';
import type { DnsAddress, DnsLookup, TransportInit } from './safe-fetch-types.js';

/** Every address one host name resolved to, each checked, in the order the lookup answered. */
export type CheckedAddresses = readonly [DnsAddress, ...DnsAddress[]];

/** What the check makes of the addresses one host name resolved to. */
export type AddressCheck =
  /** Connect to these addresses, pinned: every address is public, or private ones are admitted. */
  | { readonly pinned: CheckedAddresses }
  /** Refuse the name: this address, the first that is not public, is one it resolves to. */
  | { readonly nonPublic: string }
  /** The name resolved to no address. */
  | { readonly unresolved: true };

/**
 * The check of `addresses`, every address one host name resolved to: all of them, to pin the
 * connection to, once every one is public, or whatever they are when `admitPrivate`; else the first
 * address that is not public.
 */
export function checkResolvedAddresses(addresses: readonly DnsAddress[], admitPrivate = false): AddressCheck {
  const [first, ...others] = addresses;
  if (first === undefined) return { unresolved: true };
  const blocked = admitPrivate ? undefined : addresses.find((candidate) => isBlockedAddress(candidate.address));
  return blocked === undefined ? { pinned: [first, ...others] } : { nonPublic: blocked.address };
}

/**
 * The members of a transport's `TransportInit` that pin its connection to `addresses`: the first as
 * `pinnedAddress` and its `family`, and the others, where there are any, as `fallbackAddresses`.
 */
export function pinnedTo(addresses: CheckedAddresses): Pick<TransportInit, 'pinnedAddress' | 'family' | 'fallbackAddresses'> {
  const [first, ...others] = addresses;
  return { pinnedAddress: first.address, family: first.family, ...(others.length > 0 ? { fallbackAddresses: others } : {}) };
}

/**
 * What a reader's log line says of a host that resolves to the non-public `address`, after naming
 * the host and `host_refused`: the refusal itself is coded as a name that does not resolve is.
 */
export const UNTOLD = (address: string): string =>
  `it resolves to the non-public address ${address}, and whoever named it is told only that it could not be read`;

/** How a reader words what {@link resolveChecked} refuses, each in its own voice. */
export interface LookupRefusals {
  /** The error for `name`, whose lookup answered no address. */
  unresolved(name: string): Error;
  /**
   * The error for `name`, which resolves to an address that is not public; it does not say the
   * address, and is of the kind a name that does not resolve is, as the lookup alone decided it.
   */
  nonPublic(name: string): Error;
  /** The operator's log line for `name`, which resolves to the address `address`, which is not public. */
  logged(name: string, address: string): string;
}

/**
 * Resolve the host `name` once through `lookup`, check every address it answers, and answer them, to
 * pin the connection to, as SafeFetch and a read under the private-network rule both do before they
 * connect. A name with no address, or with any address that is not public unless
 * `admitPrivate`, is refused in the reader's own words (`refusals`), and the address that is not
 * public goes to the log alone.
 */
export async function resolveChecked(
  name: string,
  lookup: DnsLookup,
  refusals: LookupRefusals,
  admitPrivate = false,
): Promise<CheckedAddresses> {
  const checked = checkResolvedAddresses(await lookup(name), admitPrivate);
  if ('unresolved' in checked) throw refusals.unresolved(name);
  if ('nonPublic' in checked) {
    logger.warn(refusals.logged(name, checked.nonPublic));
    throw refusals.nonPublic(name);
  }
  return checked.pinned;
}
