/**
 * Crypto kit shared by the reference adapter and the vector generator.
 *
 * Centralizes the Ed25519 VC signing/verification convention
 * (`Ed25519Signature2020` over RFC 8785 canonicalized VC, minus `proof`) and the
 * gzip compression StatusList2021 uses, so the generator and the verifier cannot
 * drift. Pure Node built-ins + the package's public canonicalize/bitstring
 * primitives — no test-only helpers.
 */

import * as zlib from 'node:zlib';
import { canonicalizeJSON } from '../src/delegation/utils.js';
import type {
  CompressionFunction,
  DecompressionFunction,
} from '../src/delegation/bitstring.js';
import type { NodeCryptoProvider } from '../src/providers/node-crypto.js';
import type { DelegationCredential, Proof } from '../src/index.js';
import type { SignatureVerificationFunction } from '../src/delegation/vc-verifier.js';

/** gzip compressor matching StatusList2021's expected encoding. */
export const conformanceCompressor: CompressionFunction = {
  compress(data: Uint8Array): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      zlib.gzip(Buffer.from(data), (err, result) =>
        err ? reject(err) : resolve(new Uint8Array(result)),
      );
    });
  },
};

export const conformanceDecompressor: DecompressionFunction = {
  decompress(data: Uint8Array): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      zlib.gunzip(Buffer.from(data), (err, result) =>
        err ? reject(err) : resolve(new Uint8Array(result)),
      );
    });
  },
};

/**
 * Sign a VC-shaped object (`Ed25519Signature2020`). Strips any existing `proof`,
 * canonicalizes (RFC 8785), signs with `privateKeyBase64`, and returns the proof
 * block. This is the exact convention {@link ed25519SignatureVerifier} checks.
 */
export async function signVC(
  crypto: NodeCryptoProvider,
  vcWithoutProof: Record<string, unknown>,
  privateKeyBase64: string,
  verificationMethod: string,
): Promise<Proof> {
  const unsigned = { ...vcWithoutProof };
  delete unsigned['proof'];
  const canonical = canonicalizeJSON(unsigned);
  const signature = await crypto.sign(new TextEncoder().encode(canonical), privateKeyBase64);
  return {
    type: 'Ed25519Signature2020',
    created: '2026-01-01T00:00:00.000Z',
    verificationMethod,
    proofPurpose: 'assertionMethod',
    proofValue: Buffer.from(signature).toString('base64url'),
  };
}

/**
 * Verify the `Ed25519Signature2020` proof a {@link signVC}-produced credential
 * carries. Wired into {@link DelegationCredentialVerifier} as its
 * `signatureVerifier`.
 */
export function ed25519SignatureVerifier(
  crypto: NodeCryptoProvider,
): SignatureVerificationFunction {
  return async (vc: DelegationCredential, publicKeyJwk: unknown) => {
    try {
      const jwk = publicKeyJwk as { x?: string };
      if (!jwk.x) {
        return { valid: false, reason: 'missing public key x coordinate' };
      }
      const publicKeyBase64 = Buffer.from(jwk.x, 'base64url').toString('base64');
      const unsigned = { ...(vc as Record<string, unknown>) };
      delete unsigned['proof'];
      const canonical = canonicalizeJSON(unsigned);
      const proofValue = vc.proof?.proofValue;
      if (!proofValue) {
        return { valid: false, reason: 'missing proofValue' };
      }
      const signature = new Uint8Array(Buffer.from(proofValue as string, 'base64url'));
      const valid = await crypto.verify(
        new TextEncoder().encode(canonical),
        signature,
        publicKeyBase64,
      );
      return { valid, reason: valid ? undefined : 'signature verification failed' };
    } catch (error) {
      return {
        valid: false,
        reason: `verification error: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  };
}
