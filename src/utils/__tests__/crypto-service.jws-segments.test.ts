/**
 * A response proof's JWS is read as RFC 7515 §2 writes base64url (SPEC.md
 * §7.4): the URL-safe alphabet alone, with no white space and no `=`, the
 * reading `conformance/verify.py` gives a proof too, so the two verifiers
 * reach one verdict on every string. A signature is checked over the segments
 * as received, so a segment that a lenient decoder reads to the same bytes as
 * another string is still refused.
 */
import { describe, expect, it } from 'vitest';
import { ed25519Signer } from '../../__tests__/utils/ed25519-signer.js';
import { base64url } from '../../__tests__/utils/encodings.js';
import { nodeCrypto } from '../../__tests__/utils/node-crypto-provider.js';
import { CryptoService, type Ed25519JWK } from '../crypto-service.js';

const service = new CryptoService(nodeCrypto);
const KID = 'did:key:z6MkSigner#key-1';

const base64 = (encoded: string): string => Buffer.from(encoded, 'base64url').toString('base64');

/** A signer, and a JWS it signs over `header` and `payload` as written. */
async function signer(): Promise<{ jwk: Ed25519JWK; sign: (header: string, payload: string) => Promise<string> }> {
  const key = await ed25519Signer();
  const sign = async (header: string, payload: string): Promise<string> =>
    `${header}.${payload}.${base64url(await key.sign(`${header}.${payload}`))}`;
  return { jwk: { ...key.jwk, kid: KID }, sign };
}

const HEADER = base64url(JSON.stringify({ alg: 'EdDSA', kid: KID }));

/** A JWS of `payload` whose signature segment holds a character base64 writes another way. */
async function signedWithUrlCharacters(sign: (header: string, payload: string) => Promise<string>): Promise<string> {
  for (let attempt = 0; ; attempt++) {
    const jws = await sign(HEADER, base64url(JSON.stringify({ attempt })));
    if (/[-_]/.test(jws.split('.')[2]!)) return jws;
  }
}

const withSignature = (jws: string, signature: string): string =>
  `${jws.slice(0, jws.lastIndexOf('.'))}.${signature}`;

describe('CryptoService.verifyJWS reads each segment as a JWS segment', () => {
  it('verifies a signature segment as signed, and refuses it padded or holding white space', async () => {
    const { jwk, sign } = await signer();
    const jws = await signedWithUrlCharacters(sign);
    const signature = jws.split('.')[2]!;

    expect(await service.verifyJWS(jws, jwk, { expectedKid: KID })).toBe(true);
    for (const written of [
      `${signature}==`,
      `${signature.slice(0, 43)}\n${signature.slice(43)}`,
      `${signature.slice(0, 10)}  ${signature.slice(10)}`,
      `${signature} `,
    ]) {
      expect(await service.verifyJWS(withSignature(jws, written), jwk, { expectedKid: KID })).toBe(false);
    }
  });

  it('refuses a header or payload segment padded or holding white space, though it was signed so', async () => {
    const { jwk, sign } = await signer();
    // A header and a payload of lengths base64url writes with spare characters, so `=` completes each.
    const header = base64url(JSON.stringify({ alg: 'EdDSA', kid: KID, n: 12 }));
    const payload = base64url('{"a":1}');
    expect(header.length % 4).not.toBe(0);
    expect(payload.length % 4).not.toBe(0);
    const padded = (segment: string): string => segment.padEnd(Math.ceil(segment.length / 4) * 4, '=');

    expect(await service.verifyJWS(await sign(header, payload), jwk, { expectedKid: KID })).toBe(true);
    for (const [writtenHeader, writtenPayload] of [
      [padded(header), payload],
      [header, padded(payload)],
      [`${header.slice(0, 8)} ${header.slice(8)}`, payload],
      [header, `${payload}\n`],
    ] as const) {
      expect(await service.verifyJWS(await sign(writtenHeader, writtenPayload), jwk, { expectedKid: KID })).toBe(false);
    }
  });

  it('refuses a signature segment written in the base64 alphabet, though it reads to the same bytes', async () => {
    const { jwk, sign } = await signer();
    const jws = await signedWithUrlCharacters(sign);
    const signature = jws.split('.')[2]!;

    expect(await service.verifyJWS(withSignature(jws, base64(signature)), jwk, { expectedKid: KID })).toBe(false);
    expect(await service.verifyJWS(withSignature(jws, base64(signature).replaceAll('=', '')), jwk)).toBe(false);
  });

  it('refuses padding that does not complete the last group, and a last group of one character', async () => {
    const { jwk, sign } = await signer();
    const jws = await signedWithUrlCharacters(sign);
    const signature = jws.split('.')[2]!;

    const inside = `${signature.slice(0, 40)}=${signature.slice(40)}`;
    for (const written of [`${signature}=`, `${signature}===`, `${signature}A`, inside]) {
      expect(await service.verifyJWS(withSignature(jws, written), jwk, { expectedKid: KID })).toBe(false);
    }
  });

  it('refuses a signed header that is base64, or not UTF-8, or not JSON once read', async () => {
    const { jwk, sign } = await signer();
    // A header whose base64url has a `-` or `_`, signed as written in base64.
    const header = { alg: 'EdDSA', kid: KID, note: '>>>???' };
    const urlHeader = base64url(JSON.stringify(header));
    expect(urlHeader).toMatch(/[-_]/);
    const opening = Buffer.from(`{"alg":"EdDSA","kid":"${KID}","note":"`);
    const notUtf8 = base64url(Buffer.concat([opening, Buffer.from([0xff, 0x22, 0x7d])]));
    const marked = base64url(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(header))]));
    const payload = base64url('{}');

    expect(await service.verifyJWS(await sign(urlHeader, payload), jwk, { expectedKid: KID })).toBe(true);
    for (const written of [base64(urlHeader), notUtf8, marked]) {
      expect(await service.verifyJWS(await sign(written, payload), jwk, { expectedKid: KID })).toBe(false);
    }
  });

  it("reads the key's x as strictly: not padded, not holding white space, and not in the base64 alphabet", async () => {
    for (;;) {
      const { jwk, sign } = await signer();
      if (!/[-_]/.test(jwk.x)) continue;
      const jws = await sign(HEADER, base64url('{}'));
      const keyed = (x: string): Promise<boolean> => service.verifyJWS(jws, { ...jwk, x }, { expectedKid: KID });

      expect(await keyed(jwk.x)).toBe(true);
      expect(await keyed(`${jwk.x}=`)).toBe(false);
      expect(await keyed(`${jwk.x.slice(0, 5)} ${jwk.x.slice(5)}`)).toBe(false);
      expect(await keyed(base64(jwk.x))).toBe(false);
      expect(await keyed(base64(jwk.x).replaceAll('=', ''))).toBe(false);
      expect(await keyed(`${jwk.x}*`)).toBe(false);
      return;
    }
  });

  it('says which segment it could not read, and how it reads one', () => {
    const [payload, signature] = [base64url('{}'), base64url(new Uint8Array(64))];

    // A `*`, which base64url does not write, for the header and then after the signature.
    expect(() => service.parseJWS(`*.${payload}.${signature}`)).toThrow(
      new Error('Invalid header base64: not base64url of UTF-8 text as RFC 7515 §2 writes it'),
    );
    expect(() => service.parseJWS(`${HEADER}.${payload}.${signature}*`)).toThrow(
      new Error('Invalid signature base64: not base64url as RFC 7515 §2 writes it'),
    );
  });

  it('reads a detached JWS the same way', async () => {
    const { jwk, sign } = await signer();
    const payload = new TextEncoder().encode('{"detached":true}');
    for (let attempt = 0; ; attempt++) {
      const header = base64url(JSON.stringify({ alg: 'EdDSA', kid: KID, attempt }));
      const [, , signature] = (await sign(header, base64url(payload))).split('.') as [string, string, string];
      if (!/[-_]/.test(signature)) continue;
      const detached = (written: string): Promise<boolean> =>
        service.verifyJWS(`${header}..${written}`, jwk, { detachedPayload: payload, expectedKid: KID });
      expect(await detached(signature)).toBe(true);
      expect(await detached(`${signature}==`)).toBe(false);
      expect(await detached(`${signature}\n`)).toBe(false);
      expect(await detached(base64(signature))).toBe(false);
      return;
    }
  });
});
