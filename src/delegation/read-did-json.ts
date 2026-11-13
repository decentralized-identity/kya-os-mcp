/**
 * How a built-in resolver reads the DID document it fetches: the one bounded reader
 * (`utils/bounded-read.ts`) under the DID document's policy (SPEC §4.4.2), through the
 * private-network rule (`utils/private-network-rule.ts`), since a did:web DID names the host.
 */

import { fetchBoundedJson } from '../utils/bounded-read.js';
import { underPrivateNetworkRule, type PrivateNetworkTransport } from '../utils/private-network-rule.js';
import { DID_DOCUMENT_READ } from './did-resource-policy.js';

/** GET `url` and parse it as a DID document's JSON, within the document's byte, shape and time limits. */
export function fetchDidJson(fetcher: PrivateNetworkTransport, url: string, init: RequestInit = {}): Promise<unknown> {
  return fetchBoundedJson(underPrivateNetworkRule(fetcher), url, init, DID_DOCUMENT_READ);
}
