/**
 * Delegation Utilities
 *
 * Shared utility functions for delegation credential operations.
 */

import { base64urlEncodeFromString } from '../utils/base64.js';
import { canonicalizeJson } from '../utils/canonical-json.js';
import { jwsSegmentsJson } from './jws-segment.js';

/**
 * Canonicalize a JSON value using RFC 8785 (JSON Canonicalization Scheme).
 *
 * Delegates to the strict canonicalizer, which rejects values that are not
 * representable in JSON (Infinity, NaN, undefined, functions, symbols,
 * bigints) instead of coercing them to `"null"` or `"undefined"` as JSON
 * serialization does. That matters for cryptographic canonicalization, where
 * distinct inputs must produce distinct outputs.
 *
 * @throws {TypeError} If `obj` is not a valid JSON value
 */
export function canonicalizeJSON(obj: unknown): string {
  return canonicalizeJson(obj);
}

export interface VCJWTHeader {
  alg: 'EdDSA';
  typ: 'JWT' | 'vc+jwt';
  kid?: string;
}

export interface VCJWTPayload {
  iss: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  vc: Record<string, unknown>;
}

export interface EncodeVCAsJWTOptions {
  keyId?: string;
}

export function createUnsignedVCJWT(
  vc: Record<string, unknown>,
  options: EncodeVCAsJWTOptions = {}
): {
  header: VCJWTHeader;
  payload: VCJWTPayload;
  encodedHeader: string;
  encodedPayload: string;
  signingInput: string;
} {
  const header: VCJWTHeader = {
    alg: 'EdDSA',
    typ: 'JWT',
  };
  if (options.keyId) {
    header.kid = options.keyId;
  }

  const issuer =
    typeof vc['issuer'] === 'string'
      ? vc['issuer']
      : ((vc['issuer'] as Record<string, unknown>)?.['id'] as string);
  const subject = (vc['credentialSubject'] as Record<string, unknown>)?.['id'] as
    | string
    | undefined;

  let exp: number | undefined;
  let iat: number | undefined;

  if (vc['expirationDate'] && typeof vc['expirationDate'] === 'string') {
    exp = Math.floor(new Date(vc['expirationDate']).getTime() / 1000);
  }
  if (vc['issuanceDate'] && typeof vc['issuanceDate'] === 'string') {
    iat = Math.floor(new Date(vc['issuanceDate']).getTime() / 1000);
  }

  const vcWithoutProof = { ...vc };
  delete vcWithoutProof['proof'];

  const payload: VCJWTPayload = {
    iss: issuer,
    vc: vcWithoutProof,
  };

  if (subject) payload.sub = subject;
  if (exp) payload.exp = exp;
  if (iat) payload.iat = iat;
  if (vc['id'] && typeof vc['id'] === 'string') payload.jti = vc['id'];

  const encodedHeader = base64urlEncodeFromString(JSON.stringify(header));
  const encodedPayload = base64urlEncodeFromString(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  return {
    header,
    payload,
    encodedHeader,
    encodedPayload,
    signingInput,
  };
}

export function completeVCJWT(signingInput: string, signature: string): string {
  return `${signingInput}.${signature}`;
}

/**
 * The header and the payload of a compact VC-JWT, read as JSON as
 * `jwsSegmentsJson` reads them `lenient`: by the runtime's base64 decoder.
 *
 * Null for a string that is not three segments of which the first two are
 * JSON, and for one whose header or payload nests its arrays and objects
 * more than `MAX_CREDENTIAL_NESTING_DEPTH` levels deep (SPEC §7.8). Such a
 * text is not handed to a parser: it is counted first, in one pass, so
 * whether a JWT is read never turns on how deep a text the parser underneath
 * can read.
 */
export function parseVCJWT(jwt: string): {
  header: VCJWTHeader;
  payload: VCJWTPayload;
  signature: string;
  signingInput: string;
} | null {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    return null;
  }

  try {
    const [header, payload] = jwsSegmentsJson([parts[0]!, parts[1]!], 'lenient') as [VCJWTHeader, VCJWTPayload];

    return {
      header,
      payload,
      signature: parts[2]!,
      signingInput: `${parts[0]}.${parts[1]}`,
    };
  } catch {
    return null;
  }
}
