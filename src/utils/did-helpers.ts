/**
 * DID Validation and Helper Utilities
 *
 * Centralized utilities for DID validation, normalization, and handling.
 * Promotes DRY principle and consistency across the codebase.
 *
 * @package @kya-os/mcp/utils
 */

import { base58Encode } from "./base58.js";

/**
 * Check if a string is a valid DID format
 *
 * @param did - String to validate
 * @returns true if string starts with "did:"
 *
 * @example
 * ```typescript
 * isValidDid("did:key:z6Mk...") // true
 * isValidDid("not-a-did") // false
 * ```
 */
export function isValidDid(did: string): boolean {
  return typeof did === "string" && did.startsWith("did:");
}

/**
 * Get the DID method from a DID string
 *
 * @param did - DID string
 * @returns DID method (e.g., "key", "web") or null if invalid
 *
 * @example
 * ```typescript
 * getDidMethod("did:key:z6Mk...") // "key"
 * getDidMethod("did:web:example.com") // "web"
 * getDidMethod("invalid") // null
 * ```
 */
export function getDidMethod(did: string): string | null {
  if (!isValidDid(did)) {
    return null;
  }
  const match = did.match(/^did:([^:]+):/);
  return match?.[1] ?? null;
}

/**
 * Normalize a DID string (trim whitespace)
 *
 * @param did - DID string to normalize
 * @returns Normalized DID string
 *
 * @example
 * ```typescript
 * normalizeDid("  did:key:z6Mk...  ") // "did:key:z6Mk..."
 * ```
 */
export function normalizeDid(did: string): string {
  return did.trim();
}

/**
 * Compare two DIDs for equality (case-sensitive)
 *
 * @param did1 - First DID
 * @param did2 - Second DID
 * @returns true if DIDs are equal (after normalization)
 *
 * @example
 * ```typescript
 * compareDids("did:key:z6Mk...", "did:key:z6Mk...") // true
 * compareDids("did:key:z6Mk...", "did:web:example.com") // false
 * ```
 */
export function compareDids(did1: string, did2: string): boolean {
  return normalizeDid(did1) === normalizeDid(did2);
}

/**
 * Extract server DID from config (supports both old and new field names)
 *
 * Supports backward compatibility by reading both `serverDid` and deprecated `agentDid`.
 * Prefers `serverDid` if both are present.
 *
 * @param config - Config object with identity field
 * @returns Server DID string
 * @throws Error if neither serverDid nor agentDid is configured
 *
 * @example
 * ```typescript
 * // New config
 * getServerDid({ identity: { serverDid: "did:web:example.com" } }) // "did:web:example.com"
 *
 * // Old config (backward compatibility)
 * getServerDid({ identity: { agentDid: "did:web:example.com" } }) // "did:web:example.com"
 *
 * // Prefers serverDid over agentDid
 * getServerDid({ identity: { serverDid: "new", agentDid: "old" } }) // "new"
 * ```
 */
export function getServerDid(config: {
  identity: { serverDid?: string; agentDid?: string };
}): string {
  const serverDid = config.identity.serverDid || config.identity.agentDid;
  if (!serverDid) {
    throw new Error("Server DID not configured");
  }
  return serverDid;
}

/**
 * Extract agent ID from DID
 *
 * The agent ID is the last component of the DID.
 *
 * @param did - DID string
 * @returns Agent ID (last component of DID)
 *
 * @example
 * ```typescript
 * extractAgentId("did:web:example.com:agents:my-agent") // "my-agent"
 * extractAgentId("did:web:localhost:3000:agents:12912feb") // "12912feb"
 * extractAgentId("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK") // "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
 * ```
 */
export function extractAgentId(did: string): string {
  const parts = did.split(':');
  // split() always returns at least one element
  return parts[parts.length - 1] ?? did;
}

/**
 * Extract agent slug from DID
 *
 * Agent slug is the same as agent ID - the last component of the DID.
 * For DID format: did:web:example.com:agents:my-agent
 * Returns: my-agent
 *
 * @param did - DID string
 * @returns Agent slug (last component of DID)
 *
 * @example
 * ```typescript
 * extractAgentSlug("did:web:example.com:agents:my-agent") // "my-agent"
 * extractAgentSlug("did:web:localhost:3000:agents:12912feb") // "12912feb"
 * ```
 */
export function extractAgentSlug(did: string): string {
  return extractAgentId(did);
}

/**
 * Ed25519 multicodec prefix for did:key encoding
 * As per https://w3c-ccg.github.io/did-method-key/
 */
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

/**
 * Generate a did:key from Ed25519 public key bytes
 *
 * Following spec: https://w3c-ccg.github.io/did-method-key/
 * Format: did:key:z<multibase-base58btc(<multicodec-ed25519-pub><publicKey>)>
 *
 * @param publicKeyBytes - Ed25519 public key as Uint8Array (32 bytes)
 * @returns did:key string
 *
 * @example
 * ```typescript
 * const publicKey = new Uint8Array(32); // 32-byte Ed25519 public key
 * const did = generateDidKeyFromBytes(publicKey);
 * // did = "did:key:z6Mk..."
 * ```
 */
export function generateDidKeyFromBytes(publicKeyBytes: Uint8Array): string {
  // Combine multicodec prefix + public key
  const multicodecKey = new Uint8Array(
    ED25519_MULTICODEC_PREFIX.length + publicKeyBytes.length
  );
  multicodecKey.set(ED25519_MULTICODEC_PREFIX);
  multicodecKey.set(publicKeyBytes, ED25519_MULTICODEC_PREFIX.length);

  // Base58-btc encode and add multibase prefix 'z'
  const base58Encoded = base58Encode(multicodecKey);
  return `did:key:z${base58Encoded}`;
}

/**
 * Generate a did:key from base64-encoded Ed25519 public key
 *
 * Convenience wrapper around generateDidKeyFromBytes for base64-encoded keys.
 *
 * @param publicKeyBase64 - Ed25519 public key as base64 string
 * @returns did:key string
 *
 * @example
 * ```typescript
 * const publicKeyBase64 = "...base64 encoded key...";
 * const did = generateDidKeyFromBase64(publicKeyBase64);
 * // did = "did:key:z6Mk..."
 * ```
 */
export function generateDidKeyFromBase64(publicKeyBase64: string): string {
  // Decode base64 to bytes
  const publicKeyBytes = Uint8Array.from(atob(publicKeyBase64), (c) =>
    c.charCodeAt(0)
  );
  return generateDidKeyFromBytes(publicKeyBytes);
}

/**
 * Get the spec-compliant fragment identifier for a did:key DID.
 *
 * Per the did:key spec (W3C CCG), the fragment equals the multibase-encoded
 * public key value (the DID-specific-id). For example:
 *   did:key:z6MkABC... → z6MkABC...
 *
 * @see https://w3c-ccg.github.io/did-key-spec/#document-creation-algorithm
 * @param did - A did:key DID string
 * @returns The fragment identifier (multibase value), or 'keys-1' as fallback for non-did:key
 */
export function didKeyFragment(did: string): string {
  if (did.startsWith('did:key:')) {
    return did.slice('did:key:'.length);
  }
  // Fallback for non-did:key methods
  return 'keys-1';
}
