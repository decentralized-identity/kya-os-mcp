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

/**
 * GET `url` and parse it as a DID document's JSON, within the document's byte and shape limits and
 * `timeoutMs`, by default the policy's, each request `operatorNamed` names read wherever its host is.
 */
export function fetchDidJson(
  fetcher: PrivateNetworkTransport,
  url: string,
  init: RequestInit = {},
  timeoutMs = DID_DOCUMENT_READ.timeoutMs,
  operatorNamed?: (url: string) => boolean,
): Promise<unknown> {
  const read = underPrivateNetworkRead(fetcher, { maxBytes: DID_DOCUMENT_READ.maxBytes, ...(operatorNamed ? { operatorNamed } : {}) });
  return fetchBoundedJson(read, url, init, { ...DID_DOCUMENT_READ, timeoutMs });
}
