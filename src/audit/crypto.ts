import { CompactSign, compactVerify, importJWK, type JWK } from 'jose';
import type { CryptoProvider } from '../providers/base.js';
import { canonicalizeJsonBytes } from '../utils/canonical-json.js';
import { isSmallOrderEd25519CryptoKey } from '../utils/ed25519-public-key.js';
import { ownKeyResolver, publicJwkOf, type AuditSigningKey } from './own-key.js';
import type { Digest, SignerRef } from './types.js';

const encoder = new TextEncoder();
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;

export interface AuditHasher {
  sha256(data: Uint8Array): Promise<Digest>;
}

export class CryptoProviderAuditHasher implements AuditHasher {
  constructor(private readonly crypto: CryptoProvider) {}

  async sha256(data: Uint8Array): Promise<Digest> {
    const digest = await this.crypto.hash(data);
    if (!DIGEST_PATTERN.test(digest)) {
      throw new TypeError('Audit hasher must return sha256:<lowercase-hex>');
    }
    return digest as Digest;
  }
}

export interface AuditSigner {
  readonly ref: SignerRef;
  sign(payload: Uint8Array): Promise<string>;
  /**
   * A verifier of this signer's own signatures, or undefined when the key it
   * signs with does not yield its public key. The recorder and the checkpoint
   * builder use it to check the stored entries they build on when they are
   * given no `signatures`. A signer backed by a remote key service implements
   * it only if it can read the public key from that service.
   * @since 1.26.0
   */
  verifier?(): Promise<AuditSignatureVerifier | undefined>;
}

export interface AuditSignatureVerifier {
  verify(payload: Uint8Array, jws: string, signer: SignerRef): Promise<boolean>;
}

export type AuditVerificationKey = CryptoKey | JWK | Uint8Array;

/**
 * Resolves the key a signer verifies under. A JWK is imported and checked, so a small-order
 * Ed25519 key, under which one signature fits every payload, is refused. A `CryptoKey` imported
 * as non-extractable cannot be read back for that check, so a resolver that imports keys itself
 * should import them extractable, or return the JWK.
 */
export interface AuditVerificationKeyResolver {
  resolve(signer: SignerRef): Promise<AuditVerificationKey | null>;
}

/** Strict compact-JWS verifier with payload, algorithm, KID, and DID binding. */
export class CompactJwsAuditSignatureVerifier implements AuditSignatureVerifier {
  constructor(private readonly keys: AuditVerificationKeyResolver) {}

  async verify(payload: Uint8Array, jws: string, signer: SignerRef): Promise<boolean> {
    try {
      if (!signer.kid.startsWith(`${signer.did}#`)) return false;
      const resolved = await this.keys.resolve(signer);
      if (resolved === null) return false;
      // Imported here rather than inside compactVerify so the key can be checked:
      // under a small-order Ed25519 key one signature fits every payload. A JWK's
      // own "ext": false must not hide the key from that check, so it is imported
      // extractable whatever it says.
      const key = isJwk(resolved)
        ? await importJWK(resolved, signer.alg, { extractable: true })
        : resolved;
      if (await isSmallOrderEd25519CryptoKey(key)) return false;
      const result = await compactVerify(jws, key, { algorithms: [signer.alg] });
      if (result.protectedHeader.alg !== signer.alg ||
        result.protectedHeader.kid !== signer.kid ||
        result.payload.length !== payload.length) return false;
      return result.payload.every((byte, index) => byte === payload[index]);
    } catch {
      return false;
    }
  }
}

function isJwk(key: AuditVerificationKey): key is JWK {
  return !(key instanceof Uint8Array) && 'kty' in key;
}

/**
 * Reference JWS signer for a local private key: a WebCrypto/KMS-compatible
 * CryptoKey handle, a Node.js KeyObject or a private JWK.
 */
export class CompactJwsAuditSigner implements AuditSigner {
  private ownVerifier?: Promise<AuditSignatureVerifier | undefined>;

  constructor(
    readonly ref: SignerRef,
    private readonly privateKey: AuditSigningKey,
  ) {}

  async sign(payload: Uint8Array): Promise<string> {
    return new CompactSign(payload)
      .setProtectedHeader({ alg: this.ref.alg, kid: this.ref.kid })
      .sign(this.privateKey);
  }

  /**
   * A verifier of signatures under this signer's `ref` and key, derived from
   * the public half of its private key, or undefined when that key is a
   * CryptoKey created non-extractable, from which WebCrypto reads no public
   * key.
   * @since 1.26.0
   */
  verifier(): Promise<AuditSignatureVerifier | undefined> {
    this.ownVerifier ??= publicJwkOf(this.privateKey).then((publicKey) =>
      publicKey === undefined
        ? undefined
        : new CompactJwsAuditSignatureVerifier(ownKeyResolver(this.ref, publicKey)));
    return this.ownVerifier;
  }
}

export async function hashAuditValue(
  hasher: AuditHasher,
  domain: string,
  value: unknown,
): Promise<Digest> {
  if (domain.length === 0 || domain.includes('\0')) {
    throw new TypeError('Audit digest domain must be non-empty and cannot contain NUL');
  }
  const domainBytes = encoder.encode(`${domain}\0`);
  const valueBytes = canonicalizeJsonBytes(value);
  const input = new Uint8Array(domainBytes.length + valueBytes.length);
  input.set(domainBytes);
  input.set(valueBytes, domainBytes.length);
  return hasher.sha256(input);
}
