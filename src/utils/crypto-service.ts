/**
 * CryptoService
 *
 * Centralized cryptographic operations service providing consistent
 * signature verification across all platforms (Cloudflare, Node.js, etc.).
 */

import { CryptoProvider } from '../providers/base.js';
import { logger } from '../logging/index.js';
import {
  base64urlDecodeToString,
  base64urlDecodeToBytes,
  base64urlEncodeFromBytes,
  bytesToBase64,
} from './base64.js';

/**
 * Minimal Ed25519 JWK interface
 */
export interface Ed25519JWK {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  kid?: string;
  use?: string;
}

export interface ParsedJWS {
  header: Record<string, unknown>;
  payload?: Record<string, unknown>;
  signatureBytes: Uint8Array;
  signingInput: string;
}

export class CryptoService {
  constructor(private cryptoProvider: CryptoProvider) {}

  async verifyEd25519(
    data: Uint8Array,
    signature: Uint8Array,
    publicKey: string
  ): Promise<boolean> {
    try {
      const result = await this.cryptoProvider.verify(data, signature, publicKey);
      return result === true;
    } catch (error) {
      logger.error('[CryptoService] Ed25519 verification error:', error);
      return false;
    }
  }

  parseJWS(jws: string): ParsedJWS {
    const parts = jws.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWS format: expected header.payload.signature');
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    let header: Record<string, unknown>;
    try {
      header = JSON.parse(base64urlDecodeToString(headerB64!)) as Record<string, unknown>;
    } catch (error) {
      throw new Error(
        `Invalid header base64: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    let payload: Record<string, unknown> | undefined;
    if (payloadB64) {
      try {
        payload = JSON.parse(base64urlDecodeToString(payloadB64)) as Record<string, unknown>;
      } catch (error) {
        throw new Error(
          `Invalid payload base64: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    }

    let signatureBytes: Uint8Array;
    try {
      signatureBytes = base64urlDecodeToBytes(signatureB64!);
    } catch (error) {
      throw new Error(
        `Invalid signature base64: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    const signingInput = `${headerB64}.${payloadB64}`;

    return { header, payload, signatureBytes, signingInput };
  }

  async verifyJWS(
    jws: string,
    publicKeyJwk: Ed25519JWK,
    options?: {
      detachedPayload?: Uint8Array | string;
      expectedKid?: string;
      alg?: 'EdDSA';
    }
  ): Promise<boolean> {
    try {
      if (!this.isValidEd25519JWK(publicKeyJwk)) {
        logger.error('[CryptoService] Invalid Ed25519 JWK format');
        return false;
      }

      if (options?.expectedKid && publicKeyJwk.kid !== options.expectedKid) {
        logger.error('[CryptoService] Key ID mismatch');
        return false;
      }

      let parsed: ParsedJWS;
      try {
        parsed = this.parseJWS(jws);
      } catch (error) {
        if (options?.detachedPayload !== undefined) {
          const parts = jws.split('.');
          if (parts.length === 3 && parts[1] === '') {
            try {
              const headerB64 = parts[0]!;
              const signatureB64 = parts[2]!;
              const header = JSON.parse(
                base64urlDecodeToString(headerB64)
              ) as Record<string, unknown>;
              const signatureBytes = base64urlDecodeToBytes(signatureB64);
              parsed = { header, payload: undefined, signatureBytes, signingInput: '' };
            } catch {
              logger.error('[CryptoService] Invalid detached JWS format');
              return false;
            }
          } else {
            logger.error('[CryptoService] Invalid JWS format:', error);
            return false;
          }
        } else {
          logger.error('[CryptoService] Invalid JWS format:', error);
          return false;
        }
      }

      const expectedAlg = options?.alg || 'EdDSA';
      if (parsed.header['alg'] !== expectedAlg) {
        logger.error(
          `[CryptoService] Unsupported algorithm: ${parsed.header['alg']}, expected ${expectedAlg}`
        );
        return false;
      }
      if (
        options?.expectedKid !== undefined &&
        parsed.header['kid'] !== options.expectedKid
      ) {
        logger.error('[CryptoService] Protected JWS key ID mismatch');
        return false;
      }

      let signingInputBytes: Uint8Array;

      if (options?.detachedPayload !== undefined) {
        const headerB64 = jws.split('.')[0]!;
        let payloadB64: string;

        if (options.detachedPayload instanceof Uint8Array) {
          payloadB64 = base64urlEncodeFromBytes(options.detachedPayload);
        } else {
          payloadB64 = base64urlEncodeFromBytes(
            new TextEncoder().encode(options.detachedPayload)
          );
        }

        signingInputBytes = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
      } else {
        if (!parsed.signingInput) {
          logger.error('[CryptoService] Missing signing input for compact JWS');
          return false;
        }
        signingInputBytes = new TextEncoder().encode(parsed.signingInput);
      }

      let publicKeyBase64: string;
      try {
        publicKeyBase64 = this.jwkToBase64PublicKey(publicKeyJwk);
      } catch (error) {
        logger.error('[CryptoService] Failed to extract public key:', error);
        return false;
      }

      return await this.verifyEd25519(signingInputBytes, parsed.signatureBytes, publicKeyBase64);
    } catch (error) {
      logger.error('[CryptoService] JWS verification error:', error);
      return false;
    }
  }

  private isValidEd25519JWK(jwk: unknown): jwk is Ed25519JWK {
    return (
      typeof jwk === 'object' &&
      jwk !== null &&
      'kty' in jwk &&
      (jwk as Record<string, unknown>)['kty'] === 'OKP' &&
      'crv' in jwk &&
      (jwk as Record<string, unknown>)['crv'] === 'Ed25519' &&
      'x' in jwk &&
      typeof (jwk as Record<string, unknown>)['x'] === 'string' &&
      ((jwk as Record<string, unknown>)['x'] as string).length > 0
    );
  }

  private jwkToBase64PublicKey(jwk: Ed25519JWK): string {
    const publicKeyBytes = base64urlDecodeToBytes(jwk.x);
    if (publicKeyBytes.length !== 32) {
      throw new Error(`Invalid Ed25519 public key length: ${publicKeyBytes.length}`);
    }
    return bytesToBase64(publicKeyBytes);
  }
}
