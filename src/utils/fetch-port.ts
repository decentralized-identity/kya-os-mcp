/**
 * The transport ports the readers in `utils` consume. They are declared here, in the layer that
 * calls them, and `FetchProvider` (`providers/base.ts`) implements them, so no module in `utils`
 * imports a provider to name what it needs of one.
 */

/** One HTTP request: all a bounded read needs of its transport. */
export interface FetchPort {
  fetch(url: string, options?: unknown): Promise<Response>;
}

/** The transport of a counterparty-named read: its `fetch`, and whether it admits private hosts. */
export interface PrivateNetworkTransport extends FetchPort {
  /** The private-network rule's opt-out (`./private-network-rule`): only `true` admits private hosts. */
  readonly allowPrivateNetworkHosts?: boolean;
}
