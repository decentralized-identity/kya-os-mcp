/**
 * Utility exports
 */

export {
  ED25519_PKCS8_DER_HEADER,
  ED25519_SPKI_DER_HEADER_LENGTH,
  ED25519_KEY_SIZE,
} from './ed25519-constants.js';

export { isRecord } from './guards.js';
export { stripTrailingSlashes } from './url.js';
export {
  createSafeFetch,
  fetchTransport,
  isBlockedAddress,
  type SafeFetch,
  type SafeFetchResponse,
  type SafeFetchOptions,
  type SafeFetchTransport,
  type TransportInit,
  type RawResponse,
  type DnsLookup,
  type DnsAddress,
} from './safe-fetch.js';
