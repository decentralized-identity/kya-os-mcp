/**
 * CryptoService
 *
 * Centralized cryptographic operations service providing consistent
 * signature verification across all platforms (Cloudflare, Node.js, etc.).
 */

import { CryptoProvider } from '../providers/base.js';
import { logger } from '../logging/index.js';
import { base64urlEncodeFromBytes, bytesToBase64 } from './base64.js';
import { describeValue } from './describe-value.js';
import { strictBase64urlBytes, strictBase64urlText } from './base64-reading.js';
import { ed25519KeyBytes } from './ed25519-public-key.js';

/**
 * A JWS segment's bytes, read as RFC 7515 §2 writes base64url (SPEC.md §7.4):
 * the URL-safe alphabet alone, with no white space and no `=`. So every
 * verifier of a proof reads one string for it, and the same bytes, or
 * refuses it.
 */
function segmentBytes(segment: string): Uint8Array {
  const bytes = strictBase64urlBytes(segment);
  if (bytes === undefined) throw new Error('not base64url as RFC 7515 §2 writes it');
  return bytes;
}

/**
 * A JWS segment's JSON, its bytes read as UTF-8 that is well formed (see {@link segmentBytes}). It
 * refuses in its own words: the engine's parse error quotes the text around the fault, which whoever
 * wrote the JWS chose, control characters included, and a caller logs what it throws.
 */
function segmentJson(segment: string): Record<string, unknown> {
  const text = strictBase64urlText(segment);
  if (text === undefined) throw new Error('not base64url of UTF-8 text as RFC 7515 §2 writes it');
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new Error('the text it encodes is not JSON');
  }
}

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
      header = segmentJson(headerB64!);
    } catch (error) {
      throw new Error(
        `Invalid header base64: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    let payload: Record<string, unknown> | undefined;
    if (payloadB64) {
      try {
        payload = segmentJson(payloadB64);
      } catch (error) {
        throw new Error(
          `Invalid payload base64: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    }

    let signatureBytes: Uint8Array;
    try {
      signatureBytes = segmentBytes(signatureB64!);
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
              const header = segmentJson(parts[0]!);
              const signatureBytes = segmentBytes(parts[2]!);
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
        logger.error(`[CryptoService] Unsupported algorithm ${describeValue(parsed.header['alg'])}, expected ${expectedAlg}`);
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
      // A payload segment the JWS embeds next to a different detached payload.
      let embeddedSigningInput: string | undefined;

      if (options?.detachedPayload !== undefined) {
        const [headerB64, embeddedPayloadB64] = jws.split('.') as [string, string];
        let payloadB64: string;

        if (options.detachedPayload instanceof Uint8Array) {
          payloadB64 = base64urlEncodeFromBytes(options.detachedPayload);
        } else {
          payloadB64 = base64urlEncodeFromBytes(
            new TextEncoder().encode(options.detachedPayload)
          );
        }

        signingInputBytes = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
        if (embeddedPayloadB64 !== '' && embeddedPayloadB64 !== payloadB64) {
          embeddedSigningInput = `${headerB64}.${embeddedPayloadB64}`;
        }
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

      if (!(await this.verifyEd25519(signingInputBytes, parsed.signatureBytes, publicKeyBase64))) {
        return false;
      }
      // The signature was checked over the detached payload. A different
      // payload the JWS also embeds must verify under the same signature, or
      // anything reading the JWS alone (JWT tooling, an audit store) sees
      // claims the verified signature never covered. One signature verifies
      // two different payloads only under a forged or degenerate key, so in
      // practice this accepts an embedded payload exactly when it is the
      // detached one.
      if (
        embeddedSigningInput !== undefined &&
        !(await this.verifyEd25519(
          new TextEncoder().encode(embeddedSigningInput),
          parsed.signatureBytes,
          publicKeyBase64,
        ))
      ) {
        logger.error('[CryptoService] Embedded JWS payload is not the signed payload');
        return false;
      }
      return true;
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

  // `x` is read as the proof's segments are (SPEC.md §7.4), and as every
  // Ed25519 JWK is: the key a proof is checked with reads one way.
  private jwkToBase64PublicKey(jwk: Ed25519JWK): string {
    return bytesToBase64(ed25519KeyBytes(jwk));
  }
}
