/**
 * The network a test gives `RuntimeFetchProvider` in place of DNS and a pinned connection, through
 * its `lookup` and `transport` seams, so that no test resolves a name. {@link OVER_STUBBED_FETCH}
 * has every name resolve to one public address and each request go out through the runtime's
 * `fetch`, as SafeFetch's `fetchTransport` sends it, so a test that stubs `fetch` serves the read.
 */

import { fetchTransport, type DnsAddress, type DnsLookup } from '../../utils/safe-fetch.js';

/** A public unicast address, which the address check admits. */
export const PUBLIC_ADDRESS: DnsAddress = { address: '93.184.216.34', family: 4 };

/** A lookup that resolves every name to {@link PUBLIC_ADDRESS}. */
export const publicLookup: DnsLookup = async () => [PUBLIC_ADDRESS];

/** A lookup that resolves each name `addresses` names to its addresses, and any other to {@link PUBLIC_ADDRESS}. */
export const lookupOf =
  (addresses: Readonly<Record<string, readonly DnsAddress[]>>): DnsLookup =>
  async (hostname) => [...(addresses[hostname] ?? [PUBLIC_ADDRESS])];

/** The seams of a `RuntimeFetchProvider` whose names all resolve to a public address and whose reads go out through the stubbed `fetch`. */
export const OVER_STUBBED_FETCH = { lookup: publicLookup, transport: fetchTransport } as const;
