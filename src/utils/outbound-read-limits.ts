/**
 * What one outbound read of a document that counterparty-controlled data names may cost: how long
 * it may take and how many bytes of body it may hold. Each number is declared once, here, in the
 * lowest layer. The DID and status-list policy of SPEC §4.4.2 (`delegation/did-resource-policy.ts`)
 * takes them as fixed limits whose one deadline covers a whole read, redirects included. SafeFetch
 * (`./safe-fetch.ts`) takes them as the defaults of its `timeoutMs` and `maxBytes` options, which a
 * caller may override and which bound each hop on its own.
 */

/** Milliseconds: 5 seconds. */
export const OUTBOUND_READ_TIMEOUT_MS = 5_000;
/** Bytes of body: 1 MiB. */
export const OUTBOUND_READ_MAX_BYTES = 1_048_576;
