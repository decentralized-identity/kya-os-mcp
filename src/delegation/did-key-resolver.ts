/**
 * DID:key Resolver
 *
 * Resolves did:key DIDs to DID Documents with verification methods.
 * Supports Ed25519 keys (multicodec prefix 0xed01).
 *
 * did:key format: did:key:z<multibase-base58btc(<multicodec-prefix><public-key>)>
 *
 * For Ed25519:
 * - Multicodec prefix: 0xed 0x01
 * - Public key: 32 bytes
 * - Multibase prefix: 'z' (base58btc)
 *
 * @see https://w3c-ccg.github.io/did-method-key/
 */

import { base58Decode } from '../utils/base58.js';
import { didKeyFragment } from '../utils/did-helpers.js';
import { base64urlEncodeFromBytes } from '../utils/base64.js';
import type { DIDResolver, DIDDocument, VerificationMethod } from './vc-verifier.js';
import { logger } from '../logging/index.js';

/** Ed25519 multicodec prefix (0xed 0x01) */
export const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

/** Ed25519 public key length */
export const ED25519_PUBLIC_KEY_LENGTH = 32;

/**
 * Check if a DID is a valid did:key with Ed25519 key
 *
 * Ed25519 keys in did:key start with 'z6Mk' after the method prefix.
 * The 'z' is the multibase prefix for base58btc, and '6Mk' is the
 * base58-encoded prefix for Ed25519 (0xed 0x01).
 *
 * @param did - The DID to check
 * @returns true if it's a valid did:key with Ed25519 key
 */
export function isEd25519DidKey(did: string): boolean {
  return did.startsWith('did:key:z6Mk');
}

/**
 * Extract the public key bytes from a did:key DID
 *
 * @param did - The did:key DID
 * @returns Public key bytes or null if invalid
 */
export function extractPublicKeyFromDidKey(did: string): Uint8Array | null {
  if (!did.startsWith('did:key:z')) {
    return null;
  }

  try {
    // Extract the multibase-encoded part (after 'did:key:')
    const multibaseKey = did.replace('did:key:', '');

    // Remove the 'z' multibase prefix (base58btc)
    const base58Encoded = multibaseKey.slice(1);

    // Decode from base58
    const multicodecBytes = base58Decode(base58Encoded);

    // Check for Ed25519 multicodec prefix (0xed 0x01)
    if (
      multicodecBytes.length < ED25519_MULTICODEC_PREFIX.length + ED25519_PUBLIC_KEY_LENGTH ||
      multicodecBytes[0] !== ED25519_MULTICODEC_PREFIX[0] ||
      multicodecBytes[1] !== ED25519_MULTICODEC_PREFIX[1]
    ) {
      return null;
    }

    // Extract the public key (bytes after the prefix)
    return multicodecBytes.slice(ED25519_MULTICODEC_PREFIX.length);
  } catch (error) {
    logger.debug('Failed to extract public key from did:key', error);
    return null;
  }
}

/**
 * Convert Ed25519 public key bytes to JWK format
 *
 * @param publicKeyBytes - 32-byte Ed25519 public key
 * @returns JWK object
 */
export function publicKeyToJwk(publicKeyBytes: Uint8Array): {
  kty: string;
  crv: string;
  x: string;
} {
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: base64urlEncodeFromBytes(publicKeyBytes),
  };
}

/**
 * Create a DID:key resolver
 *
 * Returns a DIDResolver that can resolve did:key DIDs to DID Documents.
 * Currently supports only Ed25519 keys.
 *
 * @returns DIDResolver implementation for did:key
 */
export function createDidKeyResolver(): DIDResolver {
  return {
    resolve: async (did: string): Promise<DIDDocument | null> => {
      // Check if it's a did:key with Ed25519
      if (!isEd25519DidKey(did)) {
        return null;
      }

      // Extract the public key
      const publicKeyBytes = extractPublicKeyFromDidKey(did);
      if (!publicKeyBytes) {
        return null;
      }

      // Convert to JWK
      const publicKeyJwk = publicKeyToJwk(publicKeyBytes);

      // Get the multibase-encoded key for publicKeyMultibase
      const multibaseKey = did.replace('did:key:', '');

      // Construct the verification method
      const fragment = didKeyFragment(did);

      const verificationMethod: VerificationMethod = {
        id: `${did}#${fragment}`,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyJwk,
        publicKeyMultibase: multibaseKey,
      };

      // Construct and return the DID Document
      return {
        id: did,
        verificationMethod: [verificationMethod],
        authentication: [`${did}#${fragment}`],
        assertionMethod: [`${did}#${fragment}`],
      };
    },
  };
}

/**
 * Resolve a did:key DID synchronously
 *
 * Convenience function for cases where async is not needed.
 *
 * @param did - The did:key DID to resolve
 * @returns DID Document or null if invalid
 */
export function resolveDidKeySync(did: string): DIDDocument | null {
  if (!isEd25519DidKey(did)) {
    return null;
  }

  const publicKeyBytes = extractPublicKeyFromDidKey(did);
  if (!publicKeyBytes) {
    return null;
  }

  const publicKeyJwk = publicKeyToJwk(publicKeyBytes);
  const multibaseKey = did.replace('did:key:', '');

  const fragment = didKeyFragment(did);

  const verificationMethod: VerificationMethod = {
    id: `${did}#${fragment}`,
    type: 'Ed25519VerificationKey2020',
    controller: did,
    publicKeyJwk,
    publicKeyMultibase: multibaseKey,
  };

  return {
    id: did,
    verificationMethod: [verificationMethod],
    authentication: [`${did}#${fragment}`],
    assertionMethod: [`${did}#${fragment}`],
  };
}
