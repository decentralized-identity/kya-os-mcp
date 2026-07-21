import { CompactSign, compactVerify, type JWK } from 'jose';
import type { CryptoProvider } from '../providers/base.js';
import { canonicalizeJsonBytes } from '../utils/canonical-json.js';
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
}

export interface AuditSignatureVerifier {
  verify(payload: Uint8Array, jws: string, signer: SignerRef): Promise<boolean>;
}

export type AuditVerificationKey = CryptoKey | JWK | Uint8Array;

export interface AuditVerificationKeyResolver {
  resolve(signer: SignerRef): Promise<AuditVerificationKey | null>;
}

/** Strict compact-JWS verifier with payload, algorithm, KID, and DID binding. */
export class CompactJwsAuditSignatureVerifier implements AuditSignatureVerifier {
  constructor(private readonly keys: AuditVerificationKeyResolver) {}

  async verify(payload: Uint8Array, jws: string, signer: SignerRef): Promise<boolean> {
    try {
      if (!signer.kid.startsWith(`${signer.did}#`)) return false;
      const key = await this.keys.resolve(signer);
      if (key === null) return false;
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

/** Reference JWS signer for local WebCrypto/KMS-compatible CryptoKey handles. */
export class CompactJwsAuditSigner implements AuditSigner {
  constructor(
    readonly ref: SignerRef,
    private readonly privateKey: CryptoKey,
  ) {}

  async sign(payload: Uint8Array): Promise<string> {
    return new CompactSign(payload)
      .setProtectedHeader({ alg: this.ref.alg, kid: this.ref.kid })
      .sign(this.privateKey);
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
