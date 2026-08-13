import { describe, it, expect } from 'vitest';
import { verificationMethodJwk } from '../verification-method-key.js';
import { base58Encode } from '../../utils/base58.js';
import type { VerificationMethod } from '../vc-verifier.types.js';

const RAW = new Uint8Array(32).map((_, i) => i + 1);
const WITH_CODEC = new Uint8Array([0xed, 0x01, ...RAW]);
const vm = (extra: Partial<VerificationMethod>): VerificationMethod => ({
  id: 'did:example:issuer#key-1',
  type: 'Ed25519VerificationKey2020',
  controller: 'did:example:issuer',
  ...extra,
});

describe('verificationMethodJwk', () => {
  it('passes an existing publicKeyJwk through untouched', () => {
    const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'abc' };
    expect(verificationMethodJwk(vm({ publicKeyJwk: jwk }))).toBe(jwk);
  });

  it('synthesizes from publicKeyMultibase with the 0xed01 multicodec prefix', () => {
    const result = verificationMethodJwk(
      vm({ publicKeyMultibase: `z${base58Encode(WITH_CODEC)}` }),
    );
    expect(result).toMatchObject({ kty: 'OKP', crv: 'Ed25519' });
    expect(typeof result?.x).toBe('string');
  });

  it('synthesizes from a bare 32-byte publicKeyMultibase (no codec prefix)', () => {
    const result = verificationMethodJwk(
      vm({ publicKeyMultibase: `z${base58Encode(RAW)}` }),
    );
    expect(result).toMatchObject({ kty: 'OKP', crv: 'Ed25519' });
  });

  it('synthesizes from legacy publicKeyBase58', () => {
    const result = verificationMethodJwk(vm({ publicKeyBase58: base58Encode(RAW) }));
    expect(result).toMatchObject({ kty: 'OKP', crv: 'Ed25519' });
  });

  it('prefers publicKeyJwk when several encodings are present', () => {
    const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'explicit' };
    const result = verificationMethodJwk(
      vm({ publicKeyJwk: jwk, publicKeyMultibase: `z${base58Encode(WITH_CODEC)}` }),
    );
    expect(result).toBe(jwk);
  });

  it('rejects a non-Ed25519 multicodec prefix (fail-closed)', () => {
    const wrongCodec = new Uint8Array([0xec, 0x01, ...RAW]); // x25519, 34 bytes
    expect(
      verificationMethodJwk(vm({ publicKeyMultibase: `z${base58Encode(wrongCodec)}` })),
    ).toBeUndefined();
  });

  it('rejects wrong key lengths (fail-closed)', () => {
    expect(
      verificationMethodJwk(vm({ publicKeyMultibase: `z${base58Encode(RAW.slice(0, 31))}` })),
    ).toBeUndefined();
    expect(
      verificationMethodJwk(vm({ publicKeyBase58: base58Encode(new Uint8Array(33)) })),
    ).toBeUndefined();
  });

  it('rejects a non-z multibase prefix (fail-closed)', () => {
    expect(
      verificationMethodJwk(vm({ publicKeyMultibase: `f${base58Encode(RAW)}` })),
    ).toBeUndefined();
  });

  it('rejects malformed base58 and absent key material (fail-closed)', () => {
    expect(verificationMethodJwk(vm({ publicKeyMultibase: 'z0OIl' }))).toBeUndefined();
    expect(verificationMethodJwk(vm({}))).toBeUndefined();
  });
});
