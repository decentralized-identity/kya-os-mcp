/**
 * The check of a delegation credential's embedded Ed25519 signature, over
 * its signed form (SPEC.md §7.8). The middleware checks every embedded proof
 * with it, and so does the conformance kit, so the vectors are held to the
 * one reading the spec gives a signature string and a credential's members.
 */
import { describe, expect, it } from 'vitest';
import { keyOf, resignedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { methodOf } from '../../__tests__/utils/did-documents.js';
import { nodeCrypto } from '../../__tests__/utils/node-crypto-provider.js';
import { arrays } from '../../__tests__/utils/nesting.js';
import type { DelegationCredential } from '../../types/protocol.js';
import { embeddedSignatureVerifier } from '../embedded-signature.js';

const verify = embeddedSignatureVerifier(nodeCrypto);

const UNSIGNED = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  id: 'urn:uuid:embedded-signature',
  type: ['VerifiableCredential', 'DelegationCredential'],
  issuer: 'did:web:user.example.com',
  credentialSubject: { id: 'did:web:agent.example.com' },
};

/** A credential its issuer signed over the RFC 8785 form of all but its proof. */
async function signed() {
  const key = await keyOf(UNSIGNED.issuer, 'key-1');
  const credential = await resignedCredential(UNSIGNED as never, {}, key);
  const proofValue = credential.proof!.proofValue!;
  const jwk = methodOf(key).publicKeyJwk as { kty: string; crv: string; x: string };
  const withProofValue = (written: string): DelegationCredential =>
    ({ ...credential, proof: { ...credential.proof!, proofValue: written } });
  return { credential, proofValue, jwk, withProofValue };
}

describe('embeddedSignatureVerifier', () => {
  it('verifies what the issuer signed, and not a credential changed since', async () => {
    const { credential, jwk } = await signed();

    expect(await verify(credential, jwk)).toEqual({ valid: true, reason: undefined });
    const changed = { ...credential, issuer: 'did:web:someone.else' } as DelegationCredential;
    expect(await verify(changed, jwk)).toEqual({ valid: false, reason: 'Signature verification failed' });
  });

  it('reads a signature however §7.8 lets it be written', async () => {
    const { proofValue, jwk, withProofValue } = await signed();
    const standard = proofValue.replace(/-/g, '+').replace(/_/g, '/');

    for (const written of [`${proofValue}==`, `${proofValue.slice(0, 40)}\n${proofValue.slice(40)}`, standard]) {
      expect((await verify(withProofValue(written), jwk)).valid).toBe(true);
    }
  });

  it.each([
    ['a character of neither alphabet', (value: string) => `${value.slice(0, 40)}*${value.slice(40)}`],
    ['`=` ahead of a base64 character', (value: string) => `${value.slice(0, 40)}=${value.slice(40)}`],
  ])('refuses a signature string that holds %s, which is no signature', async (_name, write) => {
    const { proofValue, jwk, withProofValue } = await signed();

    // A lenient decoder passes over the first and reads the signature all the same.
    expect(await verify(withProofValue(write(proofValue)), jwk)).toEqual({
      valid: false,
      reason: 'Unreadable proofValue: A credential signature is base64url',
    });
  });

  it('checks the signature over every member but proof, one named __proto__ included', async () => {
    const { credential, jwk } = await signed();
    // Parsed, as a credential arrives: `__proto__` is then an own member, which
    // a copy made by assignment would drop from what is checked.
    const smuggled = JSON.parse(
      JSON.stringify(credential).replace('{', '{"__proto__":{"scope":"all"},'),
    ) as DelegationCredential;

    expect(Object.keys(smuggled)).toContain('__proto__');
    expect((await verify(smuggled, jwk)).valid).toBe(false);
  });

  // An array is no credential object, whatever members it carries by name:
  // it has no signed form, as it has no digest (SPEC §7.8), so no signature
  // over one is checked.
  it('refuses an array that carries a signed credential\'s members by name', async () => {
    const { credential, jwk } = await signed();
    const array = Object.assign([], credential) as unknown as DelegationCredential;

    expect(await verify(array, jwk)).toEqual({
      valid: false,
      reason: 'Unreadable proofValue: A credential object carries its signature in proof.proofValue',
    });
  });

  it.each([
    ['an integer past 2^53 - 1', 2 ** 53],
    ['a Date', new Date(0)],
    ['undefined', undefined],
  ])('refuses a credential whose signed content holds %s, which has no canonical form, for its content', async (_name, value) => {
    const { credential, jwk } = await signed();
    const unreadable = { ...credential, issuedAt: value } as DelegationCredential;

    const result = await verify(unreadable, jwk);

    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(
      /^Unreadable credential content: What a credential's signature covers has no canonical JSON form: Cannot canonicalize .* at \$\.issuedAt/,
    );
  });

  it('refuses a credential nested deeper than a credential may be, for its content', async () => {
    const { credential, jwk } = await signed();
    const deep = { ...credential, nested: arrays(64) } as DelegationCredential;

    expect(await verify(deep, jwk)).toEqual({
      valid: false,
      reason: 'Unreadable credential content: A credential object nests at most 64 levels deep',
    });
  });

  it('says what reading the credential threw, though it is no Error', async () => {
    const { credential, jwk } = await signed();
    // A credential held behind a proxy whose members cannot be listed.
    const unlisted = new Proxy(credential, {
      ownKeys: () => {
        throw 'its members cannot be listed';
      },
    });

    expect(await verify(unlisted, jwk)).toEqual({
      valid: false,
      reason: 'Unreadable credential content: its members cannot be listed',
    });
  });

  it("reads the key's x as a proof's key is read: base64url as RFC 7515 §2 writes it, of 32 bytes", async () => {
    for (;;) {
      const { credential, jwk } = await signed();
      // A key whose base64url has a character that base64 writes another way.
      if (!/[-_]/.test(jwk.x)) continue;
      const key = Buffer.from(jwk.x, 'base64url');
      const standard = key.toString('base64');

      expect(await verify(credential, jwk)).toEqual({ valid: true, reason: undefined });
      for (const x of [
        standard,
        standard.replace(/=+$/, ''),
        `${jwk.x}=`,
        `${jwk.x.slice(0, 5)} ${jwk.x.slice(5)}`,
        `${jwk.x}\n`,
      ]) {
        expect(await verify(credential, { ...jwk, x }), x).toEqual({
          valid: false,
          reason: 'Unreadable x in publicKeyJwk: An Ed25519 JWK carries its key in x, base64url as RFC 7515 §2 writes it',
        });
      }
      expect(await verify(credential, { ...jwk, x: key.subarray(0, 31).toString('base64url') })).toEqual({
        valid: false,
        reason: 'Unreadable x in publicKeyJwk: An Ed25519 key is 32 bytes, not 31',
      });
      return;
    }
  });

  it('says what is missing: the proof, its proofValue, or the key', async () => {
    const { credential, jwk, withProofValue } = await signed();
    const { proof: _proof, ...unproved } = credential;

    expect(await verify(unproved as DelegationCredential, jwk)).toEqual({ valid: false, reason: 'Missing proof' });
    expect(await verify(withProofValue(''), jwk)).toEqual({ valid: false, reason: 'Missing proofValue in proof' });
    expect(await verify(credential, { kty: 'OKP' })).toEqual({ valid: false, reason: 'No x field in publicKeyJwk' });
  });
});
