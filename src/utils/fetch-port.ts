/**
 * The transport ports the readers in `utils` consume. They are declared here, in the layer that
 * calls them, and `FetchProvider` (`providers/base.ts`) implements them, so no module in `utils`
 * imports a provider to name what it needs of one.
 */

import type { DnsLookup, SafeFetchTransport } from './safe-fetch-types.js';

/** One HTTP request: all a bounded read needs of its transport. */
export interface FetchPort {
  fetch(url: string, options?: unknown): Promise<Response>;
}

/**
 * How a transport connects a read to an address `./private-network-read` checked: the lookup that
 * resolves a host name to every address it has, and the transport that makes one request connected
 * to the address it is given, as SafeFetch's seams do (`./safe-fetch-types`).
 */
export interface AddressPinning {
  readonly lookup: DnsLookup;
  readonly transport: SafeFetchTransport;
}

/**
 * The key under which a transport offers `./private-network-read` its {@link AddressPinning}: a function that
 * resolves to it where the runtime resolves names, and to `undefined` where it does not. Only a
 * transport that makes its own connections offers one, as `RuntimeFetchProvider` does while its
 * `fetch` is the runtime's own. It is registered by name, so every copy of the package the process
 * loads reads the one key.
 */
export const ADDRESS_PINNING: unique symbol = Symbol.for('@kya-os/mcp/address-pinning');

/** The transport of a counterparty-named read: its `fetch`, and whether it admits private hosts. */
export interface PrivateNetworkTransport extends FetchPort {
  /** The private-network rule's opt-out (`./private-network-rule`): only `true` admits private hosts. */
  readonly allowPrivateNetworkHosts?: boolean;
  /**
   * How a read through this transport is connected to the addresses it checked
   * ({@link ADDRESS_PINNING}). A transport without it is read through its own `fetch`, and the
   * private-network rule refuses its hosts by the URL alone.
   */
  readonly [ADDRESS_PINNING]?: () => Promise<AddressPinning | undefined>;
}
