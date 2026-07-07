/**
 * DID:web Resolver
 *
 * Resolves did:web DIDs by fetching /.well-known/did.json from the domain.
 * Supports both root domain DIDs and path-based DIDs.
 *
 * Examples:
 *   did:web:example.com → https://example.com/.well-known/did.json
 *   did:web:example.com:agents:bot1 → https://example.com/agents/bot1/did.json
 *
 * @see https://w3c-ccg.github.io/did-method-web/
 */

import type { FetchProvider, Identity } from '../providers/base.js';
import type { DIDResolver, DIDDocument, VerificationMethod } from './vc-verifier.js';
import { logger } from '../logging/index.js';
import { base58Encode } from '../utils/base58.js';
import { base64ToBytes } from '../utils/base64.js';
import { publicKeyToJwk } from './did-key-resolver.js';

/**
 * Parsed components of a did:web DID
 */
interface ParsedDidWeb {
  domain: string;
  path: string[];
}

/**
 * Type guard for checking if value is a valid DID Document structure
 */
function isValidDIDDocument(value: unknown): value is DIDDocument {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const doc = value as Record<string, unknown>;

  // id is required and must be a string
  if (typeof doc['id'] !== 'string' || doc['id'].length === 0) {
    return false;
  }

  // verificationMethod is optional but if present must be an array
  if (doc['verificationMethod'] !== undefined) {
    if (!Array.isArray(doc['verificationMethod'])) {
      return false;
    }

    // Each verification method must have required fields
    for (const vm of doc['verificationMethod']) {
      if (!isValidVerificationMethod(vm)) {
        return false;
      }
    }
  }

  return true;
}

/**
 * Type guard for checking if value is a valid VerificationMethod
 */
function isValidVerificationMethod(value: unknown): value is VerificationMethod {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const vm = value as Record<string, unknown>;

  // id, type, and controller are required strings
  if (typeof vm['id'] !== 'string' || vm['id'].length === 0) {
    return false;
  }
  if (typeof vm['type'] !== 'string' || vm['type'].length === 0) {
    return false;
  }
  if (typeof vm['controller'] !== 'string' || vm['controller'].length === 0) {
    return false;
  }

  return true;
}

/**
 * Check if a DID is a did:web DID
 *
 * @param did - The DID to check
 * @returns true if it's a did:web DID
 */
export function isDidWeb(did: string): boolean {
  return did.startsWith('did:web:');
}

/**
 * Parse a did:web DID into its components
 *
 * @param did - The did:web DID to parse
 * @returns Parsed components or null if invalid
 */
export function parseDidWeb(did: string): ParsedDidWeb | null {
  if (!isDidWeb(did)) {
    return null;
  }

  // Remove the 'did:web:' prefix
  const remainder = did.slice(8);

  if (remainder.length === 0) {
    return null;
  }

  // Split by ':' to get domain and path components
  const parts = remainder.split(':');

  // First part is the domain (URL-decoded)
  const domain = decodeURIComponent(parts[0]!);

  if (domain.length === 0) {
    return null;
  }

  // Remaining parts form the path
  const path = parts.slice(1).map((p) => decodeURIComponent(p));

  return { domain, path };
}

/**
 * Convert a did:web DID to its resolution URL
 *
 * did:web:example.com → https://example.com/.well-known/did.json
 * did:web:example.com:path:to:doc → https://example.com/path/to/doc/did.json
 *
 * @param did - The did:web DID
 * @returns The resolution URL or null if invalid
 */
export function didWebToUrl(did: string): string | null {
  const parsed = parseDidWeb(did);

  if (!parsed) {
    return null;
  }

  const { domain, path } = parsed;

  // Build the URL
  // Note: did:web specification requires HTTPS
  let url = `https://${domain}`;

  if (path.length === 0) {
    // Root domain: use /.well-known/did.json
    url += '/.well-known/did.json';
  } else {
    // Path-based: use /path/to/resource/did.json
    url += '/' + path.join('/') + '/did.json';
  }

  return url;
}

/**
 * DID:web resolver implementation
 */
export class DidWebResolver implements DIDResolver {
  private fetchProvider: FetchProvider;
  private cache: Map<string, { document: DIDDocument; expiresAt: number }>;
  private cacheTtl: number;

  constructor(fetchProvider: FetchProvider, options?: { cacheTtl?: number }) {
    this.fetchProvider = fetchProvider;
    this.cache = new Map();
    this.cacheTtl = options?.cacheTtl ?? 300_000; // 5 minutes default
  }

  /**
   * Resolve a did:web DID to its DID Document
   *
   * @param did - The did:web DID to resolve
   * @returns The DID Document or null if resolution fails
   */
  async resolve(did: string): Promise<DIDDocument | null> {
    // Check if it's a did:web
    if (!isDidWeb(did)) {
      return null;
    }

    // Check cache
    const cached = this.cache.get(did);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.document;
    }

    // Convert to URL
    const url = didWebToUrl(did);
    if (!url) {
      logger.warn(`[DidWebResolver] Invalid did:web format: ${did}`);
      return null;
    }

    try {
      // Fetch the DID document
      const response = await this.fetchProvider.fetch(url);

      if (!response.ok) {
        logger.warn(`[DidWebResolver] HTTP ${response.status} fetching ${url}`);
        return null;
      }

      // Parse JSON
      let json: unknown;
      try {
        json = await response.json();
      } catch {
        logger.warn(`[DidWebResolver] Invalid JSON from ${url}`);
        return null;
      }

      // Validate structure
      if (!isValidDIDDocument(json)) {
        logger.warn(`[DidWebResolver] Invalid DID Document structure from ${url}`);
        return null;
      }

      // Verify the id matches the DID
      if (json.id !== did) {
        logger.warn(`[DidWebResolver] DID Document id mismatch: expected ${did}, got ${json.id}`);
        return null;
      }

      // Cache the result
      this.cache.set(did, {
        document: json,
        expiresAt: Date.now() + this.cacheTtl,
      });

      return json;
    } catch (error) {
      logger.warn(
        `[DidWebResolver] Error resolving ${did}: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      return null;
    }
  }

  /**
   * Clear the resolution cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Clear a specific entry from the cache
   */
  clearCacheEntry(did: string): void {
    this.cache.delete(did);
  }
}

/**
 * Create a did:web resolver with the given fetch provider
 *
 * @param fetchProvider - Provider for making HTTP requests
 * @param options - Optional configuration
 * @returns DIDResolver implementation for did:web
 */
export function createDidWebResolver(
  fetchProvider: FetchProvider,
  options?: { cacheTtl?: number }
): DIDResolver {
  return new DidWebResolver(fetchProvider, options);
}

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
 * Accepts one identity, or an array of them — one per key the subject
 * controls (e.g. a key per device). Each becomes an Ed25519 verification
 * method derived from its `publicKey` (base64-encoded raw bytes — the
 * {@link Identity} convention), emitting both `publicKeyJwk` and
 * `publicKeyMultibase` for cross-format interop. All keys share the one
 * controller DID and each carries its own `kid` fragment, so a verifier can
 * select the signing key by `kid` — the basis for multi-device identity: a
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
  // two verification methods with the same id — an ambiguous, malformed doc.
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
 * 32-byte Ed25519 public key. We accept that length only — anything
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
