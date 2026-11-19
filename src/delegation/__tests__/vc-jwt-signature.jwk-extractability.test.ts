/**
 * A VC-JWT issuer's key published as a JWK, whatever its `ext` member says. Under a small-order
 * Ed25519 key one signature verifies every payload, so the envelope check reads the imported key
 * back to refuse one. A JWK may carry `"ext": false`, which an import honours by making the key
 * non-extractable, and such a key cannot be read back: the check must run on it all the same.
 */
import { describe, expect, it } from 'vitest';
import { verifyVcJwtSignature } from '../vc-jwt-verify.js';
import type { DIDResolver } from '../vc-verifier.types.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import { keyOf, signedJwt } from '../../__tests__/utils/delegation-credentials.js';
import { base64urlEncodeFromBytes } from '../../utils/base64.js';
import { generateDidKeyFromBytes } from '../../utils/did-helpers.js';
import type { VerificationMethod } from '../../types/protocol.js';

const encoder = new TextEncoder();
const b64url = (value: string | Uint8Array): string =>
  base64urlEncodeFromBytes(typeof value === 'string' ? encoder.encode(value) : value);

/** The identity point: a public key of order one. */
const IDENTITY = Uint8Array.from({ length: 32 }, (_, index) => (index === 0 ? 1 : 0));
/** R = identity, S = 0: fits every payload under such a key. */
const ANY_SIGNATURE = Uint8Array.from({ length: 64 }, (_, index) => (index === 0 ? 1 : 0));

/** A resolver whose document publishes `method` with its JWK's `ext` member as `extractability` says. */
function publishing(method: VerificationMethod, extractability: { ext?: boolean }): DIDResolver {
  const published = { ...method, publicKeyJwk: { ...method.publicKeyJwk, ...extractability } };
  return { resolve: async () => issuerDidDocument(published as VerificationMethod) };
}

describe.each([
  ['says nothing of extractability', {}],
  ['says it is extractable', { ext: true }],
  ['says it is not extractable', { ext: false }],
])('a VC-JWT issuer key whose JWK %s', (_case, extractability) => {
  it('is refused when it is a small-order point', async () => {
    const did = generateDidKeyFromBytes(IDENTITY);
    const kid = `${did}#key-1`;
    const resolver = publishing(methodOf({ did, kid, publicKey: Buffer.from(IDENTITY).toString('base64') }), extractability);
    const payload = JSON.stringify({ iss: did, vc: { credentialSubject: { scopes: ['admin:*'] } } });
    const forged = `${b64url(JSON.stringify({ alg: 'EdDSA', kid }))}.${b64url(payload)}.${b64url(ANY_SIGNATURE)}`;

    const result = await verifyVcJwtSignature(forged, did, kid, resolver);

    expect(result).toMatchObject({ valid: false, reason: 'Verification method key is a small-order Ed25519 point' });
  });

  it('verifies what the issuer signed when it is a sound key', async () => {
    const issuer = await keyOf('did:web:issuer.example', 'key-1');
    const jwt = await signedJwt(issuer, { kid: issuer.kid });

    const result = await verifyVcJwtSignature(jwt, issuer.did, issuer.kid, publishing(methodOf(issuer), extractability));

    expect(result.valid).toBe(true);
  });
});
