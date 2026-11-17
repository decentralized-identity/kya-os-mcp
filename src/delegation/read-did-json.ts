/**
 * How a built-in resolver reads the DID document it fetches: the one bounded reader
 * (`utils/bounded-read.ts`) under the DID document's policy (SPEC §4.4.2), through the
 * private-network rule (`utils/private-network-rule.ts`), since a did:web DID names the host, each
 * request's host resolved and checked and its connection pinned where the transport offers it
 * (`utils/private-network-read.ts`).
 */

import { fetchBoundedJson } from '../utils/bounded-read.js';
import { underPrivateNetworkRead } from '../utils/private-network-read.js';
import type { PrivateNetworkTransport } from '../utils/private-network-rule.js';
import { DID_DOCUMENT_READ } from './did-resource-policy.js';

/** How one document a counterparty names is read, beside its URL and the transport it is read through. */
export interface OutboundRead {
  /** The request's headers, method and signal. */
  readonly init?: RequestInit;
  /** The deadline for the headers and the body together, in milliseconds; by default the policy's. */
  readonly timeoutMs?: number;
  /**
   * Which requests of the read the operator named, by the URL each asks for, the first and each
   * redirect (`../utils/operator-named.ts`): each is read wherever its host is.
   */
  readonly operatorNamed?: (url: string) => boolean;
}

/**
 * GET `url` and parse it as a DID document's JSON, within the document's byte and shape limits and
 * `read.timeoutMs`, by default the policy's, each request `read.operatorNamed` names read wherever
 * its host is.
 */
export function fetchDidJson(fetcher: PrivateNetworkTransport, url: string, read: OutboundRead = {}): Promise<unknown> {
  const { init = {}, timeoutMs = DID_DOCUMENT_READ.timeoutMs, operatorNamed } = read;
  const held = underPrivateNetworkRead(fetcher, { maxBytes: DID_DOCUMENT_READ.maxBytes, ...(operatorNamed ? { operatorNamed } : {}) });
  return fetchBoundedJson(held, url, init, { ...DID_DOCUMENT_READ, timeoutMs });
}
