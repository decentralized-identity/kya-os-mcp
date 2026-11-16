/**
 * The did:web DID document a controller publishes for its Ed25519 keys, in the shape the library's
 * resolvers and verifiers read: each key as a verification method with both `publicKeyJwk` and
 * `publicKeyMultibase`, under `authentication` and `assertionMethod`.
 */

import type { Identity } from '../providers/base.js';
import type { DIDDocument, VerificationMethod } from './vc-verifier.js';
import { base58Encode } from '../utils/base58.js';
import { base64ToBytes } from '../utils/base64.js';
import { publicKeyToJwk } from './did-key-resolver.js';
import { isDidWeb } from './did-web-url.js';

/** Ed25519 multicodec prefix (0xed 0x01) used for `publicKeyMultibase`. */
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

/**
 * Default JSON-LD contexts for an Ed25519-keyed did:web Document.
 * `did/v1` is required by DID Core; `ed25519-2020/v1` defines the
 * `Ed25519VerificationKey2020` type emitted below.
 */
const DEFAULT_DID_WEB_CONTEXTS: readonly string[] = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/suites/ed25519-2020/v1',
];

/**
 * Options for {@link buildDidWebDocument}.
 */
export interface BuildDidWebDocumentOptions {
  /**
   * Additional JSON-LD contexts appended after the defaults
   * (`did/v1`, `ed25519-2020/v1`). Use to declare credential or
   * service contexts the controller publishes alongside its keys.
   */
  additionalContexts?: readonly string[];
  /**
   * Related DIDs intentionally associated with this `did:web` subject.
   * For `did:cheqd` linkage, publish the cheqd DID here and verify the
   * reciprocal reference on the cheqd DID Document.
   */
  alsoKnownAs?: readonly string[];
}

/**
 * Build the DID Document a did:web controller serves at its
 * resolution URL (see {@link didWebToUrl}).
 *
 * Accepts one identity, or an array of them, one per key the subject
 * controls (e.g. a key per device). Each becomes an Ed25519 verification
 * method derived from its `publicKey` (base64-encoded raw bytes, the
 * {@link Identity} convention), emitting both `publicKeyJwk` and
 * `publicKeyMultibase` for cross-format interop. All keys share the one
 * controller DID and each carries its own `kid` fragment, so a verifier can
 * select the signing key by `kid`, the basis for multi-device identity: a
 * new device adds a method, a lost one is dropped, and every other key is
 * untouched.
 *
 * Every method is published in both `authentication` and `assertionMethod`,
 * matching the {@link createDidKeyResolver} output and the most common
 * verifier expectations.
 *
 * The function is purely synchronous and performs no I/O. Hosts publish the
 * returned object verbatim (e.g. as the body of a `/.well-known/did.json`
 * route).
 *
 * @param identity - Subject identity, or an array of identities that all
 *   share one `did:web:` DID. Each `kid` must reference that DID
 *   (`<did>#<fragment>`) and be unique across the set.
 * @param options - Optional context extensions.
 * @returns DID Document satisfying the W3C DID Core data model.
 * @throws Error when the set is empty, when the DID is not a `did:web:` DID,
 *   when identities disagree on the DID, when a `kid` does not reference the
 *   DID or collides with another, or when a `publicKey` is not a valid base64
 *   string of the expected length.
 *
 * @example
 * ```typescript
 * const document = buildDidWebDocument({
 *   did: 'did:web:example.com:agents:bot1',
 *   kid: 'did:web:example.com:agents:bot1#keys-1',
 *   publicKey: agent.publicKey, // base64-encoded Ed25519
 *   createdAt: new Date().toISOString(),
 * });
 * // Serve `document` at https://example.com/agents/bot1/did.json
 * ```
 */
export function buildDidWebDocument(
  identity: Identity | Identity[],
  options?: BuildDidWebDocumentOptions
): DIDDocument {
  const identities = Array.isArray(identity) ? identity : [identity];

  const first = identities[0];
  if (!first) {
    throw new Error('buildDidWebDocument: at least one identity is required');
  }

  const did = first.did;
  if (!isDidWeb(did)) {
    throw new Error(
      `buildDidWebDocument: identity.did must be a did:web DID (got "${did}")`
    );
  }

  const verificationMethod = identities.map((id) =>
    toVerificationMethod(id, did)
  );

  // Every device key needs a distinct fragment; duplicate kids would produce
  // two verification methods with the same id, an ambiguous, malformed doc.
  const kids = verificationMethod.map((vm) => vm.id);
  if (new Set(kids).size !== kids.length) {
    throw new Error(
      'buildDidWebDocument: every key needs a unique verification-method id (kid); got a duplicate'
    );
  }

  const contexts = options?.additionalContexts?.length
    ? [...DEFAULT_DID_WEB_CONTEXTS, ...options.additionalContexts]
    : [...DEFAULT_DID_WEB_CONTEXTS];

  return {
    '@context': contexts,
    id: did,
    ...(options?.alsoKnownAs?.length ? { alsoKnownAs: [...options.alsoKnownAs] } : {}),
    verificationMethod,
    authentication: kids,
    assertionMethod: kids,
  };
}

/**
 * Build one Ed25519 verification method from a single device key, emitting
 * both `publicKeyJwk` and `publicKeyMultibase` for cross-format interop.
 *
 * Enforces the two invariants a multi-key document depends on: the key must
 * belong to `expectedDid` (a document must never mix keys from different DIDs),
 * and its `kid` must be a fragment of that one controller DID.
 */
function toVerificationMethod(
  identity: Identity,
  expectedDid: string
): VerificationMethod {
  if (identity.did !== expectedDid) {
    throw new Error(
      `buildDidWebDocument: all identities must share one DID; got "${identity.did}" alongside "${expectedDid}"`
    );
  }
  if (!identity.kid.startsWith(`${expectedDid}#`)) {
    throw new Error(
      `buildDidWebDocument: identity.kid "${identity.kid}" does not reference identity.did "${expectedDid}"`
    );
  }

  const publicKeyBytes = decodePublicKey(identity.publicKey);
  return {
    id: identity.kid,
    type: 'Ed25519VerificationKey2020',
    controller: expectedDid,
    publicKeyJwk: publicKeyToJwk(publicKeyBytes),
    publicKeyMultibase: encodeEd25519Multibase(publicKeyBytes),
  };
}

/**
 * Decode a base64-encoded Ed25519 public key to raw bytes.
 *
 * The {@link Identity} contract documents `publicKey` as base64 of the
 * 32-byte Ed25519 public key. We accept that length only: anything
 * else is a programming error and surfaces as a thrown construction
 * exception (per the repository error contract: construction throws,
 * verification/resolution returns).
 */
function decodePublicKey(publicKeyBase64: string): Uint8Array {
  const bytes = base64ToBytes(publicKeyBase64);
  if (bytes.length !== 32) {
    throw new Error(
      `buildDidWebDocument: expected 32-byte Ed25519 public key, got ${bytes.length} bytes after base64 decode`
    );
  }
  return bytes;
}

/**
 * Encode raw Ed25519 public key bytes as `publicKeyMultibase`
 * (multicodec-tagged, base58btc-encoded, `z`-prefixed). Matches the
 * encoding used by {@link createDidKeyResolver} for the equivalent
 * field on did:key documents.
 */
function encodeEd25519Multibase(publicKeyBytes: Uint8Array): string {
  const multicodec = new Uint8Array(
    ED25519_MULTICODEC_PREFIX.length + publicKeyBytes.length
  );
  multicodec.set(ED25519_MULTICODEC_PREFIX);
  multicodec.set(publicKeyBytes, ED25519_MULTICODEC_PREFIX.length);
  return `z${base58Encode(multicodec)}`;
}
