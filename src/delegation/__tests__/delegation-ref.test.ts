/**
 * The reference a delegation credential goes by (SPEC.md §7.8).
 *
 * `delegationRef` has one definition, and a proof, an audit event and a
 * verifier holding the credential are compared by it. The cases here are the
 * ones conformance/verify.py holds its own derivation to, so the two
 * implementations answer each of them alike.
 */
import { describe, expect, it, vi } from 'vitest';
import { sha256Of } from '../../__tests__/utils/digests.js';
import { base64url, compactJwt, unit } from '../../__tests__/utils/encodings.js';
import { arrays } from '../../__tests__/utils/nesting.js';
import { nodeHash as hash } from '../../__tests__/utils/node-crypto-provider.js';
import { delegationCredentialId, delegationReference, delegationRefOf } from '../delegation-ref.js';

const utf8 = (text: string) => new TextEncoder().encode(text);
const base64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');

/** A compact VC-JWT with `payload` as its claims. Its header and signature are never read for an id. */
const vcJwt = (payload: string | Uint8Array, encode: (bytes: Uint8Array) => string = base64url) =>
  compactJwt(encode(typeof payload === 'string' ? utf8(payload) : payload), 'c2lnbmF0dXJl');

const nested = { credentialSubject: { delegation: { id: 'del-1' } } };

describe('delegationCredentialId', () => {
  describe('of a credential object', () => {
    it.each([
      ['its id', { id: 'urn:a', ...nested }, 'urn:a'],
      ['the id of its delegation when it has none of its own', nested, 'del-1'],
      ['the id of its delegation when its own is not a string', { id: 7, ...nested }, 'del-1'],
      ['the id of its delegation when its own is empty', { id: '', ...nested }, 'del-1'],
      ['nothing when the only id is empty', { id: '' }, undefined],
      ['nothing when the id of its delegation is empty', { credentialSubject: { delegation: { id: '' } } }, undefined],
      ['nothing when its subject is not an object', { credentialSubject: 'del-1' }, undefined],
      ['nothing when its delegation is an array', { credentialSubject: { delegation: [{ id: 'del-1' }] } }, undefined],
      // SPEC §7.8: of the members of one object that share a name, the last is read.
      ['the last of two ids, read from JSON text', JSON.parse('{"id":"urn:a","id":"urn:b"}') as object, 'urn:b'],
    ])('is %s', (_name, credential, shown) => {
      expect(delegationCredentialId(credential)).toBe(shown);
    });

    it.each([
      ['an array', [{ id: 'urn:a' }]],
      ['a number', 7],
      ['null', null],
      ['nothing', undefined],
      ['a function', Object.assign(() => undefined, { id: 'urn:a' })],
    ])('is nothing for %s', (_name, value) => {
      expect(delegationCredentialId(value)).toBeUndefined();
    });

    it('is read from own data members only: an accessor is not called, and nothing inherited is an id', () => {
      const called = { getter: false };
      const withAccessor = Object.defineProperty({ ...nested }, 'id', {
        enumerable: true,
        get() {
          called.getter = true;
          return 'urn:from-a-getter';
        },
      });
      expect(delegationCredentialId(withAccessor)).toBe('del-1');
      expect(called.getter).toBe(false);
      expect(delegationCredentialId(Object.create({ id: 'urn:inherited' }))).toBeUndefined();
      expect(delegationCredentialId(Object.create(nested))).toBeUndefined();
    });

    it('is read as the JSON form of the object has it: a member that is not enumerable is not there', () => {
      const hidden = <T extends object>(object: T, key: string, value: unknown): T =>
        Object.defineProperty(object, key, { value, enumerable: false });
      expect(delegationCredentialId(hidden({ ...nested }, 'id', 'urn:hidden'))).toBe('del-1');
      expect(delegationCredentialId(hidden({}, 'credentialSubject', nested.credentialSubject))).toBeUndefined();
      expect(delegationCredentialId({ credentialSubject: hidden({}, 'delegation', { id: 'del-1' }) })).toBeUndefined();
      expect(delegationCredentialId({ credentialSubject: { delegation: hidden({}, 'id', 'del-1') } })).toBeUndefined();
    });

    it('never throws, whatever the value does when it is read', () => {
      const hostile = new Proxy({}, {
        getOwnPropertyDescriptor() {
          throw new Error('not readable');
        },
      });
      expect(delegationCredentialId(hostile)).toBeUndefined();
    });

    // An id is two members down at most, so it is read however deep the rest
    // nests: a credential object that has no signed form is still named.
    it('is shown by an object nested deeper than a credential may be', () => {
      const proof = { proofValue: 'c2lnbmF0dXJl' };
      expect(delegationCredentialId({ id: 'urn:a', n: arrays(64), proof })).toBe('urn:a');
      expect(delegationCredentialId({ ...nested, n: arrays(200_000), proof })).toBe('del-1');
    });
  });

  describe('of a VC-JWT', () => {
    const tilde = '{"vc":{"id":"urn:~~~"}}';
    const claims = '{"vc":{"id":"urn:a"}}';

    it.each([
      ['vc.id first', vcJwt('{"vc":{"id":"urn:a"},"jti":"urn:b"}'), 'urn:a'],
      ['jti when the credential has no id', vcJwt('{"vc":{},"jti":"urn:b"}'), 'urn:b'],
      ['jti when vc.id is empty', vcJwt('{"vc":{"id":""},"jti":"urn:b"}'), 'urn:b'],
      ['the id of its delegation last', vcJwt('{"vc":{"credentialSubject":{"delegation":{"id":"del-1"}}}}'), 'del-1'],
      ['the id of its delegation when jti is empty', vcJwt('{"jti":"","vc":{"credentialSubject":{"delegation":{"id":"del-1"}}}}'), 'del-1'],
      ['read past white space after the claims', vcJwt(`${claims} `), 'urn:a'],
      ['read from a payload with the characters only base64url has', vcJwt(tilde), 'urn:~~~'],
      ['read from a payload with a line break in it, and the padding of a whole group',
        vcJwt(claims, (bytes) => `${base64(bytes).slice(0, 8)}\n${base64(bytes).slice(8)}`), 'urn:a'],
      ['read past an integer of 400 digits beside the credential',
        vcJwt(`{"vc":{"id":"urn:a"},"n":${'1'.repeat(400)}}`), 'urn:a'],
      ['read past a negative integer of 641 digits inside it',
        vcJwt(`{"vc":{"id":"urn:a","n":-${'9'.repeat(641)}}}`), 'urn:a'],
      ['read past an integer of 4301 digits beside it',
        vcJwt(`{"vc":{"id":"urn:a"},"n":${'1'.repeat(4301)}}`), 'urn:a'],
      // SPEC §7.8: of the members of one object that share a name, the last is read.
      ['the last of two ids the credential holds', vcJwt('{"vc":{"id":"urn:a","id":"urn:b"}}'), 'urn:b'],
      ['the last of two jti', vcJwt('{"vc":{},"jti":"urn:a","jti":"urn:b"}'), 'urn:b'],
      ['the id of the last of two credentials', vcJwt('{"vc":{"id":"urn:a"},"vc":{"id":"urn:b"}}'), 'urn:b'],
    ])('is %s', (_name, jwt, shown) => {
      expect(delegationCredentialId(jwt)).toBe(shown);
    });

    it.each([
      ['claims with no vc: they are not a credential', vcJwt('{"jti":"urn:b"}')],
      ['a vc that is an array', vcJwt('{"vc":[],"jti":"urn:b"}')],
      ['a last vc that is an array, whatever one before it holds', vcJwt('{"vc":{"id":"urn:a"},"vc":[]}')],
      ['claims that are not an object', vcJwt('"urn:a"')],
      ['a payload that starts with a byte order mark, which is not JSON',
        vcJwt(new Uint8Array([0xef, 0xbb, 0xbf, ...utf8(claims)]))],
      ['a payload that is not UTF-8', vcJwt(new Uint8Array([...utf8('{"vc":{"id":"urn:'), 0xff, ...utf8('"}}')]))],
      ['a payload that is not JSON', vcJwt('{"vc":{"id":"urn:a"},"n":NaN}')],
      ['a payload in base64, not base64url', vcJwt(tilde, (bytes) => base64(bytes).replace(/=+$/, ''))],
      ['two segments', `eyJhbGciOiJFZERTQSJ9.${base64url(utf8(claims))}`],
      ['four segments', `${vcJwt(claims)}.c2lnbmF0dXJl`],
      ['an empty string', ''],
    ])('is nothing for %s', (_name, jwt) => {
      expect(delegationCredentialId(jwt)).toBeUndefined();
    });

    it('holds the base64 case to what it is meant to be: a payload base64url writes differently', () => {
      expect(base64(utf8(tilde))).toContain('+');
    });

    // SPEC §7.8: a payload whose arrays and objects nest more than 64 deep is
    // not read as JSON. The payload is level 1 and `vc` level 2.
    describe('whose payload nests', () => {
      const inVc = (open: string, close: string, levels: number, leaf = ''): string =>
        `{"vc":{"id":"urn:a","n":${open.repeat(levels - 2)}${leaf}${close.repeat(levels - 2)}}}`;

      it.each([
        ['arrays', '[', ']', ''],
        ['objects', '{"a":', '}', '1'],
      ])('%s 64 levels deep shows its id, and 65 levels deep shows none', (_name, open, close, leaf) => {
        expect(delegationCredentialId(vcJwt(inVc(open, close, 64, leaf)))).toBe('urn:a');
        expect(delegationCredentialId(vcJwt(inVc(open, close, 65, leaf)))).toBeUndefined();
      });

      it('65 levels deep beside the credential shows none: all of the payload is counted', () => {
        const beside = (levels: number): string =>
          `{"vc":{"id":"urn:a"},"n":${'['.repeat(levels - 1)}${']'.repeat(levels - 1)}}`;
        expect(delegationCredentialId(vcJwt(beside(64)))).toBe('urn:a');
        expect(delegationCredentialId(vcJwt(beside(65)))).toBeUndefined();
      });

      it('deeper than that is handed to no parser, so the answer is not how deep a text one reads', () => {
        const parse = vi.spyOn(JSON, 'parse');
        let shown: unknown;
        let parsed: number;
        try {
          shown = delegationCredentialId(vcJwt(inVc('[', ']', 200_000)));
          parsed = parse.mock.calls.length;
        } finally {
          parse.mockRestore();
        }
        expect(shown).toBeUndefined();
        expect(parsed).toBe(0);
      });

      it.each([
        ['a bracket in a string nests nothing', `{"vc":{"id":"urn:${'['.repeat(100)}"}}`, `urn:${'['.repeat(100)}`],
        ['nor does one after a quote the string escapes', `{"vc":{"id":"urn:a","s":"\\"${'['.repeat(100)}"}}`, 'urn:a'],
        ['a string that ends in a backslash it escapes is over, and 64 levels after it are read',
          `{"vc":{"id":"urn:a","s":"\\\\","n":${'['.repeat(62)}${']'.repeat(62)}}}`, 'urn:a'],
        ['and 65 levels after it are not',
          `{"vc":{"id":"urn:a","s":"\\\\","n":${'['.repeat(63)}${']'.repeat(63)}}}`, undefined],
      ])('counts what is nested and not what is written: %s', (_name, payload, shown) => {
        // Each payload is JSON, so what is shown is the count's doing.
        expect(() => JSON.parse(payload)).not.toThrow();
        expect(delegationCredentialId(vcJwt(payload))).toBe(shown);
      });

      it('is read whatever the header nests: an id is in the payload', () => {
        const header = base64url(utf8(`{"alg":"EdDSA","n":${'['.repeat(64)}${']'.repeat(64)}}`));
        expect(delegationCredentialId(`${header}.${base64url(utf8(claims))}.c2lnbmF0dXJl`)).toBe('urn:a');
      });
    });
  });
});

describe('delegationReference', () => {
  const longId = 'x'.repeat(257);
  const astral = String.fromCodePoint(0x1f600).repeat(128);
  const digestLike = `sha256:${'a'.repeat(64)}`;

  it.each([
    ['a plain id', 'del-1'],
    ['an id of 256 code units', 'x'.repeat(256)],
    ['an id of 128 characters that is 256 code units', astral],
    ['an id with a no-break space, the first character past C1', `del${unit(0xa0)}1`],
    ['an id with a tilde, the last character before DEL', 'del~1'],
    ['an id that is a space alone, the first character past C0', unit(0x20)],
    ['an id that reads as a digest in upper case', `sha256:${'A'.repeat(64)}`],
    ['an id that reads as a digest one digit short', `sha256:${'a'.repeat(63)}`],
    ['an id that reads as a digest one digit long', `sha256:${'a'.repeat(65)}`],
    ['an id with a digest inside it', `urn:${digestLike}`],
    ['an id that holds the word unknown', 'unknown-1'],
    ['an id that is unknown in upper case', 'Unknown'],
    ['an id with a narrow no-break space, the first character past the overrides', `del${unit(0x202f)}1`],
    ['an id with a surrogate pair', `del${String.fromCodePoint(0x1f600)}1`],
  ])('is the id itself for %s', async (_name, id) => {
    expect(await delegationReference(id, hash)).toBe(id);
  });

  it.each([
    ['an id of 257 code units', longId],
    ['an id of 129 characters that is 257 code units', `${astral}x`],
    ['an id with a line feed', `del${unit(0x0a)}1`],
    ['an id with NUL, the first of C0', `del${unit(0x00)}1`],
    ['an id with US, the last of C0', `del${unit(0x1f)}1`],
    ['an id that is US alone', unit(0x1f)],
    ['an id with DEL', `del${unit(0x7f)}1`],
    ['an id with the first of C1', `del${unit(0x80)}1`],
    ['an id with the last of C1', `del${unit(0x9f)}1`],
    ['an id that already reads as a digest', digestLike],
    ['an id that is the word an audit record names a credential with no id by', 'unknown'],
    ['an id with a right-to-left override', `del${unit(0x202e)}1`],
    ['an id with a zero-width space', `del${unit(0x200b)}1`],
    ['an id with a byte order mark', `${unit(0xfeff)}del-1`],
    ['an id with a line separator', `del${unit(0x2028)}1`],
    ['an id with a paragraph separator', `del${unit(0x2029)}1`],
    ['an id with a tag character outside the basic plane', `del${String.fromCodePoint(0xe0041)}1`],
  ])('is the digest of the id for %s', async (_name, id) => {
    const reference = await delegationReference(id, hash);
    expect(reference).toBe(sha256Of(id));
    expect(reference).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('is the digest every implementation gets for the same id', async () => {
    expect(await delegationReference(longId, hash))
      .toBe('sha256:15eb95a462ee20bd91a415ae2d4aed341288186ddaa2b37908f7d592f0c3f85f');
  });

  // A surrogate without its pair is written as the three bytes of its code
  // point (WTF-8): U+D800 as ED A0 80, U+DC00 as ED B0 80, U+DFFF as ED BF BF.
  it.each([
    ['a high surrogate without its pair', unit(0xd800), [0xed, 0xa0, 0x80]],
    ['a low surrogate without its pair', `a${unit(0xdc00)}b`, [0x61, 0xed, 0xb0, 0x80, 0x62]],
    ['a pair the wrong way round', `${unit(0xdfff)}${unit(0xd800)}`, [0xed, 0xbf, 0xbf, 0xed, 0xa0, 0x80]],
    ['a lone surrogate beside a pair', `${unit(0xd83d)}${unit(0xd83d)}${unit(0xde00)}`,
      [0xed, 0xa0, 0xbd, 0xf0, 0x9f, 0x98, 0x80]],
  ])('is the digest of the id for %s, its WTF-8 bytes hashed', async (_name, id, bytes) => {
    expect(await delegationReference(id, hash)).toBe(sha256Of(Uint8Array.from(bytes)));
  });

  it('is the digest of a long id that holds a surrogate without its pair', async () => {
    expect(await delegationReference(`${longId}${unit(0xd800)}`, hash))
      .toBe(sha256Of(Uint8Array.from([...utf8(longId), 0xed, 0xa0, 0x80])));
  });

  it.each([
    ['an empty id', ''],
    ['a value that is not a string', 7 as unknown as string],
  ])('is nothing for %s, and takes no digest', async (_name, id) => {
    let hashed = 0;
    const counting = (bytes: Uint8Array) => {
      hashed += 1;
      return hash(bytes);
    };
    expect(await delegationReference(id, counting)).toBeUndefined();
    expect(hashed).toBe(0);
  });

  it('takes no digest for an id it keeps', async () => {
    const refusing = async (): Promise<string> => {
      throw new Error('no digest was needed');
    };
    expect(await delegationReference('del-1', refusing)).toBe('del-1');
  });
});

describe('delegationRefOf', () => {
  it('is the reference for the id a credential shows, in either form', async () => {
    const longId = `urn:uuid:${'f'.repeat(300)}`;
    expect(await delegationRefOf({ id: 'urn:a', ...nested }, hash)).toBe('urn:a');
    expect(await delegationRefOf({ id: longId }, hash)).toBe(sha256Of(longId));
    expect(await delegationRefOf(vcJwt('{"vc":{},"jti":"urn:b"}'), hash)).toBe('urn:b');
    expect(await delegationRefOf(vcJwt(JSON.stringify({ vc: { id: longId } })), hash)).toBe(sha256Of(longId));
  });

  it('is nothing for a VC-JWT whose payload nests deeper than a credential may be, and its id for one that does not', async () => {
    const payload = (levels: number): string =>
      `{"vc":{"id":"urn:a","n":${'['.repeat(levels - 2)}${']'.repeat(levels - 2)}}}`;
    expect(await delegationRefOf(vcJwt(payload(64)), hash)).toBe('urn:a');
    expect(await delegationRefOf(vcJwt(payload(65)), hash)).toBeUndefined();
  });

  it('is nothing for a credential that shows no id', async () => {
    expect(await delegationRefOf({ id: '' }, hash)).toBeUndefined();
    expect(await delegationRefOf({}, hash)).toBeUndefined();
    expect(await delegationRefOf('not a jwt', hash)).toBeUndefined();
  });

  it('is a digest for a credential whose id is not well-formed Unicode, or is unknown', async () => {
    expect(await delegationRefOf({ id: `urn:${unit(0xd800)}` }, hash))
      .toBe(sha256Of(Uint8Array.from([...utf8('urn:'), 0xed, 0xa0, 0x80])));
    expect(await delegationRefOf(vcJwt('{"vc":{"id":"unknown"}}'), hash)).toBe(sha256Of('unknown'));
  });
});
