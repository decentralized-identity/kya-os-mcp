/**
 * How a status list named by a credential is read (SPEC §4.4.2): the one bounded reader, with at
 * most 1 MiB of response body and one 5,000 ms deadline for the headers and the body together,
 * through the private-network rule (`utils/private-network-rule.ts`), since the credential names
 * the host.
 *
 * A list holds at least 131,072 entries (16 KiB) under both StatusList2021 and Bitstring Status
 * List 1.0, gzip-compressed and base64url-encoded. Even an incompressible list of that minimum
 * encodes to about 22 KB, and 1 MiB holds an incompressible list of over six million entries, 48
 * times the minimum. The JSON text meets the same shape limits as a DID document.
 */

import { fetchBoundedJson, type BoundedJsonPolicy } from '../utils/bounded-read.js';
import { underPrivateNetworkRule, type PrivateNetworkTransport } from '../utils/private-network-rule.js';
import { DID_DOCUMENT_JSON, DID_RESOLUTION_TIMEOUT_MS, MAX_DID_DOCUMENT_BYTES } from './did-resource-policy.js';

/** Bytes of status-list response body read before the read is refused: the DID document's limit. */
export const MAX_STATUS_LIST_RESPONSE_BYTES = MAX_DID_DOCUMENT_BYTES;
/** One deadline for a status-list request's headers and body: a DID resolution's. */
export const STATUS_LIST_TIMEOUT_MS = DID_RESOLUTION_TIMEOUT_MS;

const STATUS_LIST_READ: BoundedJsonPolicy = {
  label: 'Status list fetch',
  maxBytes: MAX_STATUS_LIST_RESPONSE_BYTES,
  timeoutMs: STATUS_LIST_TIMEOUT_MS,
  json: DID_DOCUMENT_JSON,
};

/** GET the status list at `url` and parse its JSON, within the status-list limits. */
export function fetchStatusListJson(fetcher: PrivateNetworkTransport, url: string, init: RequestInit = {}): Promise<unknown> {
  return fetchBoundedJson(underPrivateNetworkRule(fetcher), url, init, STATUS_LIST_READ);
}
