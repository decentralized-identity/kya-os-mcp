/**
 * The resource policy for DID resolution, stated in SPEC §4.4.2. Internal constants of the
 * implementation, not a configuration surface and not limits of DID syntax.
 */

import type { JsonLimits } from '../utils/json-preflight.js';
import type { BoundedJsonPolicy } from '../utils/bounded-read.js';

/** A DID, a document's `id` and a method's `controller`, in UTF-16 code units. */
export const MAX_DID_LENGTH = 2_048;
/** A key identifier, a method's `id` and a relationship reference, in UTF-16 code units. */
export const MAX_KEY_ID_LENGTH = 4_096;
/** A DID document's compact JSON in UTF-8, and a did:web response body. */
export const MAX_DID_DOCUMENT_BYTES = 1_048_576;
export const MAX_JSON_DEPTH = 64;
export const MAX_JSON_MEMBER_LENGTH = 256;
export const MAX_JSON_MEMBERS = 8_192;
/** Entries of `verificationMethod` and the five verification relationships, in all. */
export const MAX_VERIFICATION_ENTRIES = 8_192;
/** One deadline for a resolution: the fetch and its body, or a resolver's promise. */
export const DID_RESOLUTION_TIMEOUT_MS = 5_000;
/** Each built-in network resolver's cache: documents, and their compact JSON bytes in all. */
export const MAX_CACHED_DOCUMENTS = 128;
export const MAX_CACHED_BYTES = 8 * MAX_DID_DOCUMENT_BYTES;

/** The shape a DID document's JSON text may have before it is parsed. */
export const DID_DOCUMENT_JSON: JsonLimits = {
  maxDepth: MAX_JSON_DEPTH,
  maxMembers: MAX_JSON_MEMBERS,
  maxMemberLength: MAX_JSON_MEMBER_LENGTH,
};

/** How a built-in resolver reads a DID document it fetches itself. */
export const DID_DOCUMENT_READ: BoundedJsonPolicy = {
  label: 'DID resolution',
  maxBytes: MAX_DID_DOCUMENT_BYTES,
  timeoutMs: DID_RESOLUTION_TIMEOUT_MS,
  json: DID_DOCUMENT_JSON,
};

/**
 * How the cheqd resolver reads a response that may be a DID Resolution Result: its own cap on
 * bytes, depth and members, since `didDocumentMetadata.linkedResourceMetadata` lists every resource
 * the DID has published. 4 MiB holds the metadata of about 7,000 resources, at about 600 bytes and
 * 12 members each, before the member cap binds; the document inside still meets every document
 * limit, one level deeper than the envelope's root.
 */
export const DID_RESOLUTION_ENVELOPE_READ: BoundedJsonPolicy = {
  label: 'DID resolution',
  maxBytes: 4 * MAX_DID_DOCUMENT_BYTES,
  timeoutMs: DID_RESOLUTION_TIMEOUT_MS,
  json: { maxDepth: MAX_JSON_DEPTH + 1, maxMembers: 16 * MAX_JSON_MEMBERS, maxMemberLength: MAX_JSON_MEMBER_LENGTH },
};

/** A nonempty string within the DID limit. */
export const boundedDid = (did: unknown): did is string =>
  typeof did === 'string' && did.length > 0 && did.length <= MAX_DID_LENGTH;

/** A string within the key identifier limit. */
export const boundedKeyId = (id: unknown): id is string =>
  typeof id === 'string' && id.length <= MAX_KEY_ID_LENGTH;

/** A DID, and a key id when one is given, each within its limit. */
export const boundedIdentifiers = (did: unknown, key?: unknown): boolean =>
  boundedDid(did) && (key === undefined || boundedKeyId(key));
