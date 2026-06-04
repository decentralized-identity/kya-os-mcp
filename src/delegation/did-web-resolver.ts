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
 * Emits a single Ed25519 verification method derived from
 * `identity.publicKey` (base64-encoded raw bytes — the
 * {@link Identity} convention). Both `publicKeyJwk` and
 * `publicKeyMultibase` are included for cross-format interop with
 * verifiers that prefer one over the other.
 *
 * The verification method is published in both `authentication` and
 * `assertionMethod`, matching the {@link createDidKeyResolver} output
 * and the most common verifier expectations.
 *
 * The function is purely synchronous and performs no I/O. Hosts
 * publish the returned object verbatim (e.g. as the body of a
 * `/.well-known/did.json` route).
 *
 * @param identity - Subject identity. `did` must be a `did:web:` DID;
 *   `kid` must reference the same DID (`<did>#<fragment>`).
 * @param options - Optional context extensions.
 * @returns DID Document satisfying the W3C DID Core data model.
 * @throws Error when `identity.did` is not a `did:web:` DID, when
 *   `identity.kid` does not reference `identity.did`, or when
 *   `identity.publicKey` is not a valid base64 string of the
 *   expected length.
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
  identity: Identity,
  options?: BuildDidWebDocumentOptions
): DIDDocument {
  if (!isDidWeb(identity.did)) {
    throw new Error(
      `buildDidWebDocument: identity.did must be a did:web DID (got "${identity.did}")`
    );
  }

  if (!identity.kid.startsWith(`${identity.did}#`)) {
    throw new Error(
      `buildDidWebDocument: identity.kid "${identity.kid}" does not reference identity.did "${identity.did}"`
    );
  }

  const publicKeyBytes = decodePublicKey(identity.publicKey);
  const publicKeyJwk = publicKeyToJwk(publicKeyBytes);
  const publicKeyMultibase = encodeEd25519Multibase(publicKeyBytes);

  const verificationMethod: VerificationMethod = {
    id: identity.kid,
    type: 'Ed25519VerificationKey2020',
    controller: identity.did,
    publicKeyJwk,
    publicKeyMultibase,
  };

  const contexts = options?.additionalContexts?.length
    ? [...DEFAULT_DID_WEB_CONTEXTS, ...options.additionalContexts]
    : [...DEFAULT_DID_WEB_CONTEXTS];

  return {
    '@context': contexts,
    id: identity.did,
    ...(options?.alsoKnownAs?.length ? { alsoKnownAs: [...options.alsoKnownAs] } : {}),
    verificationMethod: [verificationMethod],
    authentication: [identity.kid],
    assertionMethod: [identity.kid],
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
