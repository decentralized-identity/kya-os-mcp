/**
 * How a status list named by a credential is read (SPEC §4.4.2): the one bounded reader, with at
 * most 1 MiB of response body and one deadline for the headers and the body together, 5,000 ms
 * unless the reader's `dependencyTimeoutMs` sets another,
 * through the private-network rule (`utils/private-network-rule.ts`), since the credential names
 * the host, each request's host resolved and checked and its connection pinned where the transport
 * offers it (`utils/private-network-read.ts`). The read takes https, every redirect included, since
 * over http an on-path party can replay an older signed list from before a revocation. It reads http
 * only at a first URL the operator binds exactly in `statusListIssuers`, on any host, and from a
 * private or local host under `development: true`, as a local demo serves its lists.
 *
 * A list holds at least 131,072 entries (16 KiB) under both StatusList2021 and Bitstring Status
 * List 1.0, gzip-compressed and base64url-encoded. Even an incompressible list of that minimum
 * encodes to about 22 KB, and 1 MiB holds an incompressible list of over six million entries, 48
 * times the minimum. The JSON text meets the same shape limits as a DID document.
 */

import { fetchBoundedJson, type BoundedJsonPolicy } from '../utils/bounded-read.js';
import { underPrivateNetworkRead } from '../utils/private-network-read.js';
import type { PrivateNetworkTransport } from '../utils/private-network-rule.js';
import type { OutboundRead } from './read-did-json.js';
import { DID_DOCUMENT_JSON, DID_RESOLUTION_TIMEOUT_MS, MAX_DID_DOCUMENT_BYTES } from './did-resource-policy.js';

/** Bytes of status-list response body read before the read is refused: the DID document's limit. */
export const MAX_STATUS_LIST_RESPONSE_BYTES = MAX_DID_DOCUMENT_BYTES;

/** The default deadline for a status-list request's headers and body: a DID resolution's. */
export const STATUS_LIST_TIMEOUT_MS = DID_RESOLUTION_TIMEOUT_MS;

const STATUS_LIST_READ: BoundedJsonPolicy = {
  label: 'Status list fetch',
  maxBytes: MAX_STATUS_LIST_RESPONSE_BYTES,
  timeoutMs: STATUS_LIST_TIMEOUT_MS,
  json: DID_DOCUMENT_JSON,
};

/** How one status list is read, beside its URL and the transport it is read through. */
export interface StatusListRead extends OutboundRead {
  /**
   * Whether the reader was built with `development: true`: http is then read from a private or
   * local host too, first or redirected, as a local demo serves its lists.
   */
  readonly development?: boolean;
}

/**
 * GET the status list at `url` and parse its JSON, within the status-list limits and
 * `read.timeoutMs`, by default the policy's. Each request `read.operatorNamed` names is read wherever
 * its host is, and the first may be http, as only an exact URL `statusListIssuers` binds can be.
 */
export function fetchStatusListJson(fetcher: PrivateNetworkTransport, url: string, read: StatusListRead = {}): Promise<unknown> {
  const { init = {}, timeoutMs = STATUS_LIST_READ.timeoutMs, operatorNamed, development = false } = read;
  const held = underPrivateNetworkRead(fetcher, {
    httpsOnly: true,
    httpOnPrivateHosts: development,
    maxBytes: STATUS_LIST_READ.maxBytes,
    ...(operatorNamed ? { operatorNamed } : {}),
  });
  return fetchBoundedJson(held, url, init, { ...STATUS_LIST_READ, timeoutMs });
}
