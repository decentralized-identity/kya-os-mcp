/**
 * The signed form of a credential (SPEC.md §7.8): the one reading of what an
 * issuer signed that both signature verification and the chain digest use.
 * These tests hold the two things that reading must get right: a signature is
 * one value however its string was written, and a member is never dropped or
 * re-read on the way to being checked.
 */
import { describe, it, expect } from 'vitest';
import {
  CredentialContentError,
  MAX_CREDENTIAL_NESTING_DEPTH,
  NoSignedFormError,
  canonicalVcJwt,
  credentialWithoutProof,
  decodeJwsSegment,
  decodeSignature,
  digestInput,
  signedForm,
  signedFormJson,
  signingInput,
} from '../signed-form.js';
import { arrays, objects } from '../../__tests__/utils/nesting.js';
import { canonicalizeJson } from '../../utils/canonical-json.js';

const bytes = (...values: number[]) => Uint8Array.from(values);
const text = (value: string) => new TextEncoder().encode(value);
const read = (value: Uint8Array) => new TextDecoder().decode(value);

describe('decodeSignature', () => {
  it('reads base64url, the bytes RFC 4648 §5 says', () => {
    expect(decodeSignature('c2lnbmF0dXJl')).toEqual(text('signature'));
    expect(decodeSignature('-_-_')).toEqual(bytes(0xfb, 0xff, 0xbf));
    expect(decodeSignature('')).toEqual(bytes());
  });

  it.each([
    ['padding', 'c2ln', 'c2ln=', 'c2ln==', 'c2ln===='],
    ['whitespace around its padding', 'c2lnbg', 'c2lnbg ==', 'c2lnbg=\n=', 'c2lnbg==\r\n'],
    ['the base64 alphabet', '-_-_', '+/+/', '-/+_'],
    ['whitespace inside it', 'c2lnbmF0dXJl', 'c2ln bmF0\ndXJl', '\tc2lnbmF0\fdXJl\r\n'],
    ['the spare bits of a last character', 'c2lnbg', 'c2lnbh', 'c2lnbv'],
    ['a trailing character short of a byte', 'c2ln', 'c2lnQ', 'c2ln_'],
  ])('gives one signature whatever %s', (_name, ...variants) => {
    const [first, ...rest] = variants.map((variant) => decodeSignature(variant));
    expect(first!.length).toBeGreaterThan(0);
    for (const other of rest) expect(other).toEqual(first);
  });

  it.each([
    ['punctuation', 'c2ln!bmF0dXJl'],
    ['a dot', 'c2ln.bmF0dXJl'],
    ['a letter outside ASCII', 'c2lnébmF0dXJl'],
    ['a character outside the BMP', 'c2ln\u{1F512}bmF0'],
    ['a control character', 'c2ln\u0000bmF0'],
    ['a vertical tab, which is not whitespace', 'c2ln\vbmF0'],
  ])('refuses a string with %s in it: that is not a signature', (_name, encoded) => {
    expect(() => decodeSignature(encoded)).toThrow(NoSignedFormError);
  });

  // Padding ends a signature. Decoders in use disagree about a `=` anywhere
  // else: some pass over it, some stop at it. A string they read to different
  // bytes is not one signature, so it is none.
  it.each([
    ['inside it', 'c2ln=bmF0dXJl'],
    ['before it', '=c2lnbmF0dXJl'],
    ['before its last character', 'c2lnbmF0dXJ=l'],
    ['between two halves that each decode', 'c2ln==bmF0'],
    ['and whitespace before more of it', 'c2ln= bmF0dXJl'],
  ])('refuses a string with padding %s', (_name, encoded) => {
    expect(() => decodeSignature(encoded)).toThrow(NoSignedFormError);
    // Without the padding it is a signature, so it was the padding.
    expect(decodeSignature(encoded.replaceAll('=', '')).length).toBeGreaterThan(0);
  });

  it('gives different bytes for different signatures', () => {
    expect(decodeSignature('c2lnbmF0dXJl')).not.toEqual(decodeSignature('c2lnbmF0dXJm'));
    expect(decodeSignature('c2ln')).not.toEqual(decodeSignature('c2lnbg'));
  });
});

describe('decodeJwsSegment', () => {
  it('reads base64url, the bytes RFC 7515 §2 says', () => {
    expect(decodeJwsSegment('c2lnbmF0dXJl')).toEqual(text('signature'));
    expect(decodeJwsSegment('-_-_')).toEqual(bytes(0xfb, 0xff, 0xbf));
    expect(decodeJwsSegment('')).toEqual(bytes());
  });

  it.each([
    ['two `=` after a last group of two', 'c2lnbg', 'c2lnbg==', 'c2lnbg= =\n'],
    ['one `=` after a last group of three', 'c2lnbmE', 'c2lnbmE='],
    ['whitespace inside it', 'c2lnbmF0dXJl', 'c2ln bmF0\ndXJl', '\tc2lnbmF0\fdXJl\r\n'],
    ['the spare bits of a last character', 'c2lnbg', 'c2lnbh', 'c2lnbv'],
  ])('gives one value whatever %s', (_name, ...variants) => {
    const [first, ...rest] = variants.map((variant) => decodeJwsSegment(variant));
    expect(first!.length).toBeGreaterThan(0);
    for (const other of rest) expect(other).toEqual(first);
  });

  it.each([
    ['`+`, which base64 writes for `-`', 'c2ln+mF0'],
    ['`/`, which base64 writes for `_`', 'c2ln/mF0'],
    ['one `=` after a last group of two', 'c2lnbg='],
    ['two `=` after a last group of three', 'c2lnbmE=='],
    ['`=` after whole groups of four', 'c2ln='],
    ['a whole group of `=`', 'c2ln===='],
    ['a last group of one character', 'c2lnb'],
    ['a last group of one character, padded', 'c2lnb==='],
    ['a vertical tab, which is not whitespace', 'c2ln\vbmF0'],
    ['`=` ahead of more of it', 'c2lnbg==bmF0'],
    ['`=` alone', '=='],
    ['a character outside the alphabet', 'c2ln!mF0'],
    ['a letter outside ASCII', 'c2lnébmF0'],
  ])('refuses %s', (_name, encoded) => {
    expect(() => decodeJwsSegment(encoded)).toThrow(new NoSignedFormError('A JWS segment is base64url (RFC 7515 §2)'));
  });
});

describe('credentialWithoutProof', () => {
  it('leaves out proof and nothing else', () => {
    const credential = { id: 'urn:uuid:1', issuer: 'did:web:a', proof: { proofValue: 'c2ln' } };
    expect(credentialWithoutProof(credential)).toEqual({ id: 'urn:uuid:1', issuer: 'did:web:a' });
    expect(credential).toHaveProperty('proof');
  });

  it('keeps a member named __proto__ as a member', () => {
    // As JSON.parse gives it: an own property, which assignment would turn
    // into a prototype and so drop from what gets canonicalized.
    const credential = JSON.parse('{"id":"urn:uuid:1","__proto__":{"scope":"all"},"proof":{}}') as object;
    const unsigned = credentialWithoutProof(credential);
    expect(Object.keys(unsigned)).toEqual(['id', '__proto__']);
    expect(Object.getPrototypeOf(unsigned)).toBe(Object.prototype);
    expect(canonicalizeJson(unsigned)).toBe('{"__proto__":{"scope":"all"},"id":"urn:uuid:1"}');
  });

  it('keeps an accessor an accessor, which has no canonical form', () => {
    let reads = 0;
    const credential = { id: 'urn:uuid:1' };
    Object.defineProperty(credential, 'issuer', {
      enumerable: true,
      get: () => (reads++ === 0 ? 'did:web:honest' : 'did:web:other'),
    });
    const unsigned = credentialWithoutProof(credential);
    expect(reads).toBe(0);
    expect(() => canonicalizeJson(unsigned)).toThrow(/accessor/);
  });

  it('keeps a member keyed by a symbol, which has no canonical form, enumerable or not', () => {
    const tag = Symbol('tag');
    const hiddenTag = Symbol('hidden tag');
    const credential = { id: 'urn:uuid:1', [tag]: 1, proof: { proofValue: 'c2ln' } };
    Object.defineProperty(credential, hiddenTag, { value: 2, enumerable: false });
    const unsigned = credentialWithoutProof(credential);
    expect(Reflect.ownKeys(unsigned)).toEqual(['id', tag, hiddenTag]);
    expect(() => canonicalizeJson(unsigned)).toThrow(/symbol-keyed property at \$/);
  });

  it('keeps a member that is not enumerable as one, which is not JSON', () => {
    const credential = Object.defineProperty({ id: 'urn:uuid:1', proof: {} }, 'note', { value: 'x', enumerable: false });
    const unsigned = credentialWithoutProof(credential);
    expect(Object.getOwnPropertyDescriptor(unsigned, 'note')).toMatchObject({ value: 'x', enumerable: false });
    expect(canonicalizeJson(unsigned)).toBe('{"id":"urn:uuid:1"}');
  });
});

describe('signedForm', () => {
  const credential = {
    id: 'urn:uuid:1',
    issuer: 'did:web:a',
    proof: { type: 'Ed25519Signature2020', created: '2026-01-01T00:00:00Z', proofValue: 'c2lnbmF0dXJl' },
  };

  it('of an object is the credential without its proof, and the signature bytes', () => {
    expect(signedForm(credential)).toEqual({
      credential: { id: 'urn:uuid:1', issuer: 'did:web:a' },
      signature: text('signature'),
    });
    expect(signedFormJson(signedForm(credential))).toEqual({
      credential: { id: 'urn:uuid:1', issuer: 'did:web:a' },
      signature: 'c2lnbmF0dXJl',
    });
  });

  it('of a VC-JWT is its first two segments as received, and the signature bytes', () => {
    expect(signedForm('aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl')).toEqual({
      jwt: 'aGVhZGVy.cGF5bG9hZA',
      signature: text('signature'),
    });
    expect(signedFormJson(signedForm('aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl'))).toEqual({
      jwt: 'aGVhZGVy.cGF5bG9hZA',
      signature: 'c2lnbmF0dXJl',
    });
  });

  it('writes the signature one way however it arrived', () => {
    const padded = { ...credential, proof: { ...credential.proof, proofValue: 'c2ln bmF0dXJl==' } };
    expect(signedForm(padded)).toEqual(signedForm(credential));
    // Eight bytes: eleven characters, the last with two spare bits, and one `=`.
    expect(signedForm('aGVhZGVy.cGF5bG9hZA.c2lnbmF0\ndXJ=')).toEqual(signedForm('aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXI'));
  });

  it('reads the signature of a VC-JWT as a JWS segment, and a proofValue more loosely', () => {
    // The same characters, in the base64 alphabet and with padding past a
    // group of four: a signature in a proof, and none in a JWS.
    for (const written of ['+/+/', '-_-_====', 'c2lnbmF0dXJl=', 'c2lnbmF0d']) {
      expect(signedForm({ id: 'urn:uuid:1', proof: { proofValue: written } }).signature.length).toBeGreaterThan(0);
      expect(() => signedForm(`aGVhZGVy.cGF5bG9hZA.${written}`)).toThrow(NoSignedFormError);
    }
  });

  // Only ASCII white space is passed over (SPEC §7.8). A no-break space, a
  // byte order mark or a line separator at either end of a signature string
  // is a character of no alphabet, however a runtime's `trim` treats it.
  describe.each([
    ['a no-break space', '\u00a0'],
    ['a byte order mark', '\ufeff'],
    ['a line separator', '\u2028'],
  ])('with %s at either end of its signature string', (_name, space) => {
    it.each([
      ['at its start', (signature: string) => `${space}${signature}`],
      ['at its end', (signature: string) => `${signature}${space}`],
    ])('has none, %s, as a proofValue or as a VC-JWT signature', (_where, write) => {
      const proofValue = (written: string) => ({ id: 'urn:uuid:1', proof: { proofValue: written } });
      expect(signedForm(proofValue('c2lnbmF0dXJl')).signature).toEqual(text('signature'));
      expect(signedForm('aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl').signature).toEqual(text('signature'));

      expect(() => signedForm(proofValue(write('c2lnbmF0dXJl')))).toThrow(NoSignedFormError);
      expect(() => signedForm(`aGVhZGVy.cGF5bG9hZA.${write('c2lnbmF0dXJl')}`)).toThrow(NoSignedFormError);
    });
  });

  it('does not read a proof or a proofValue through an accessor', () => {
    const hostile = { id: 'urn:uuid:1' };
    Object.defineProperty(hostile, 'proof', { enumerable: true, get: () => ({ proofValue: 'c2ln' }) });
    expect(() => signedForm(hostile)).toThrow(NoSignedFormError);
  });

  it('reads a proof and a proofValue as JSON has them: one that is not enumerable is not there', () => {
    const hiddenProof = Object.defineProperty({ id: 'urn:uuid:1' }, 'proof', {
      value: { proofValue: 'c2ln' },
      enumerable: false,
    });
    expect(() => signedForm(hiddenProof)).toThrow('A credential object carries its signature in proof.proofValue');
    const hiddenValue = {
      id: 'urn:uuid:1',
      proof: Object.defineProperty({}, 'proofValue', { value: 'c2ln', enumerable: false }),
    };
    expect(() => signedForm(hiddenValue)).toThrow('A credential signature is base64url of at least one byte');
    expect(signedForm({ id: 'urn:uuid:1', proof: { proofValue: 'c2ln' } }).signature).toEqual(text('sig'));
  });

  it.each([
    ['a signature with a character that is not base64', { id: 'x', proof: { proofValue: 'c2ln!' } }],
    ['a signature with padding inside it', { id: 'x', proof: { proofValue: 'c2ln=bmF0' } }],
    ['a signature of padding alone', { id: 'x', proof: { proofValue: '==' } }],
    ['a signature of one character, short of a byte', { id: 'x', proof: { proofValue: 'c' } }],
    ['a signature that is not a string', { id: 'x', proof: { proofValue: 7 } }],
    ['no proof', { id: 'x' }],
    ['a string with two segments', 'aGVhZGVy.cGF5bG9hZA'],
    ['a string with four segments', 'aGVhZGVy.cGF5bG9hZA.c2ln.c2ln'],
    ['a JWS with an empty header', '.cGF5bG9hZA.c2lnbmF0dXJl'],
    ['a JWS with an empty payload', 'aGVhZGVy..c2lnbmF0dXJl'],
    ['a JWS with an empty signature', 'aGVhZGVy.cGF5bG9hZA.'],
    ['a JWS whose signature has padding inside it', 'aGVhZGVy.cGF5bG9hZA.c2ln=bmF0'],
    ['a number', 42],
    ['null', null],
    ['an array', [{ id: 'x', proof: { proofValue: 'c2ln' } }]],
  ])('has none for %s', (_name, value) => {
    expect(() => signedForm(value as never)).toThrow(NoSignedFormError);
  });

  // A value that is neither a string nor an object is no credential, and is
  // told so before anything reads a member of it, as a caller in plain
  // JavaScript can pass one whatever the types say.
  it.each([
    ['undefined', undefined],
    ['null', null],
    ['a number', 42],
    ['an array', [{ id: 'x', proof: { proofValue: 'c2ln' } }]],
  ])('has none for %s, which is no credential', (_name, value) => {
    expect(() => signedForm(value as never)).toThrow(NoSignedFormError);
    expect(() => signedForm(value as never)).toThrow(
      'A delegation credential is a compact VC-JWT string or a credential object',
    );
  });

  it('has none for a string that is not a compact JWS, which is read as one', () => {
    expect(() => signedForm('urn:uuid:1')).toThrow(NoSignedFormError);
    expect(() => signedForm('urn:uuid:1')).toThrow('A VC-JWT is a compact JWS: header.payload.signature');
  });

  // SPEC §7.8: the arrays and objects of a credential object nest at most 64
  // deep. The object is level 1, so a member of it is level 2, and a member
  // of its `proof` level 3.
  describe('of an object nested as deep as a credential may be', () => {
    const proof = { proofValue: 'c2lnbmF0dXJl' };
    const TOO_DEEP = 'A credential object nests at most 64 levels deep';

    it('is bounded at 64 levels', () => {
      expect(MAX_CREDENTIAL_NESTING_DEPTH).toBe(64);
    });

    it.each<[string, (levels: number) => object]>([
      ['arrays in what the issuer signed', (levels) => ({ id: 'urn:uuid:1', n: arrays(levels - 1), proof })],
      ['objects in what the issuer signed', (levels) => ({ id: 'urn:uuid:1', n: objects(levels - 1), proof })],
      ['arrays in its proof, which no signature covers', (levels) => ({ id: 'urn:uuid:1', proof: { ...proof, note: arrays(levels - 2) } })],
      ['objects in its proof', (levels) => ({ id: 'urn:uuid:1', proof: { ...proof, note: objects(levels - 2) } })],
    ])('is there for %s 64 levels deep, and not for 65', (_name, nestedTo) => {
      const form = signedForm(nestedTo(64));
      expect(form.signature).toEqual(text('signature'));
      // What is as deep as the bound is read all the way down, by both readings.
      expect(read(signingInput(form))).toContain('"urn:uuid:1"');
      expect(read(digestInput(form))).toContain('"signature":"c2lnbmF0dXJl"');
      expect(() => signedForm(nestedTo(65))).toThrow(NoSignedFormError);
      expect(() => signedForm(nestedTo(65))).toThrow(TOO_DEEP);
    });

    it('is not there for one nested deeper than any call stack, which takes none to find out', () => {
      expect(() => signedForm({ id: 'urn:uuid:1', n: arrays(200_000), proof })).toThrow(TOO_DEEP);
      expect(() => signedForm({ id: 'urn:uuid:1', proof: { ...proof, note: objects(200_000) } })).toThrow(TOO_DEEP);
    });

    // JSON has every element of an array, and the canonicalizer reads one
    // whether or not it is enumerable, so the bound counts it too.
    describe('counting an element that is not enumerable', () => {
      const hiddenElement = (value: unknown): unknown[] =>
        Object.defineProperty([0], 0, { value, enumerable: false, writable: true, configurable: true });
      const holding = (levels: number) => ({ id: 'urn:uuid:1', n: hiddenElement(arrays(levels - 2)), proof });

      it('is there 64 levels deep, read all the way down, and not for 65', () => {
        const form = signedForm(holding(64));
        expect(read(signingInput(form))).toContain('"leaf"');
        expect(read(signingInput(form))).toBe(read(signingInput(signedForm({ id: 'urn:uuid:1', n: [arrays(62)], proof }))));
        expect(() => signedForm(holding(65))).toThrow(TOO_DEEP);
      });

      it.each([70, 200_000])('is not there %i levels deep: the bound refuses it, not the call stack', (levels) => {
        let thrown: unknown;
        try {
          signingInput(signedForm(holding(levels)));
        } catch (error) {
          thrown = error;
        }
        expect(thrown).toBeInstanceOf(NoSignedFormError);
        expect(thrown).not.toBeInstanceOf(RangeError);
        expect((thrown as Error).message).toBe(TOO_DEEP);
      });
    });

    it('is not there for one that holds itself, which is deeper than any bound', () => {
      const inSigned: Record<string, unknown> = { id: 'urn:uuid:1', proof };
      inSigned['self'] = inSigned;
      expect(() => signedForm(inSigned)).toThrow(TOO_DEEP);
      const looping: Record<string, unknown> = { ...proof };
      looping['self'] = looping;
      expect(() => signedForm({ id: 'urn:uuid:1', proof: looping })).toThrow(TOO_DEEP);
    });

    it('counts a value that is in two places at the deeper of them, whichever is read first', () => {
      const shared = arrays(62);
      // Beside the credential it reaches level 63; one array further in, 64; two, 65.
      expect(() => signedForm({ id: 'urn:uuid:1', near: shared, far: [shared], proof })).not.toThrow();
      expect(() => signedForm({ id: 'urn:uuid:1', near: shared, far: [[shared]], proof })).toThrow(TOO_DEEP);
      expect(() => signedForm({ id: 'urn:uuid:1', far: [[shared]], near: shared, proof })).toThrow(TOO_DEEP);
    });

    it('asks for a signature first: a value with no proof is refused as that, however deep it is', () => {
      expect(() => signedForm({ id: 'urn:uuid:1', n: arrays(200_000) }))
        .toThrow('A credential object carries its signature in proof.proofValue');
    });
  });
});

describe('signingInput', () => {
  it('of a VC-JWT is the JWS signing input: its two segments as received', () => {
    expect(read(signingInput(signedForm('aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl')))).toBe('aGVhZGVy.cGF5bG9hZA');
  });

  it('of a credential object is the RFC 8785 form of the object without its proof', () => {
    const credential = {
      issuer: 'did:web:a',
      id: 'urn:uuid:1',
      proof: { type: 'Ed25519Signature2020', proofValue: 'c2lnbmF0dXJl', note: 'unsigned' },
    };
    expect(read(signingInput(signedForm(credential)))).toBe('{"id":"urn:uuid:1","issuer":"did:web:a"}');
  });

  it('is what digestInput hashes, with the signature beside it', () => {
    const credential = { id: 'urn:uuid:1', issuer: 'did:web:a', proof: { proofValue: 'c2ln bmF0dXJl==' } };
    const form = signedForm(credential);
    expect(read(digestInput(form))).toBe(`{"credential":${read(signingInput(form))},"signature":"c2lnbmF0dXJl"}`);
    const jwt = signedForm('aGVhZGVy.cGF5bG9hZA.c2lnbmF0\ndXJ=');
    expect(read(digestInput(jwt))).toBe(`{"jwt":"${read(signingInput(jwt))}","signature":"c2lnbmF0dXI"}`);
  });

  // RFC 8785 gives these no form, so a signature cannot cover them and a
  // digest cannot be taken over them. The value is the cause, not a fault.
  it.each([
    ['a number that is not finite', { n: Number.POSITIVE_INFINITY }],
    ['a number that is not a number', { n: Number.NaN }],
    ['an integer a double does not hold exactly', { n: 2 ** 53 }],
    ['a string that is not well-formed Unicode', { s: '\ud800' }],
    ['a member with no JSON form', { u: undefined }],
    ['a value that is not plain data', { at: new Date(0) }],
    ['a member keyed by a symbol', { [Symbol('tag')]: 1 }],
  ])('has none for a credential with %s, and neither has the digest', (_name, members) => {
    const form = signedForm({ id: 'urn:uuid:1', ...members, proof: { proofValue: 'c2ln' } });
    for (const input of [signingInput, digestInput]) {
      let thrown: unknown;
      try {
        input(form);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(NoSignedFormError);
      // It is the content that has none, not the signature string.
      expect(thrown).toBeInstanceOf(CredentialContentError);
      expect((thrown as Error).message).toContain('no canonical JSON form');
      // The canonicalizer's own error is kept, as the cause.
      expect((thrown as Error).cause).toBeInstanceOf(Error);
    }
  });
});

describe('a failure that is not the value’s', () => {
  // `signedForm` lets no object deeper than the bound through, so these forms
  // are made by hand: the serializer recurses, and runs out of stack on them.
  it('is thrown as it is: a call stack that ran out is not a credential with no signed form', () => {
    const form = { credential: { id: 'urn:uuid:1', n: arrays(200_000) }, signature: text('signature') };
    for (const input of [signingInput, digestInput]) {
      let thrown: unknown;
      try {
        input(form);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(RangeError);
      expect(thrown).not.toBeInstanceOf(NoSignedFormError);
    }
  });
});

describe('NoSignedFormError', () => {
  it('is a TypeError that names itself, so it is told apart from any other failure', () => {
    const error = new NoSignedFormError('no signed form', { cause: 'why' });
    expect(error).toBeInstanceOf(TypeError);
    expect(error.name).toBe('NoSignedFormError');
    expect(error.message).toBe('no signed form');
    expect(error.cause).toBe('why');
    expect(new TypeError('other')).not.toBeInstanceOf(NoSignedFormError);
  });

  it('is a CredentialContentError for what a credential holds, and not for its signature string', () => {
    const content = new CredentialContentError('nests too deep');
    expect(content).toBeInstanceOf(NoSignedFormError);
    expect(content.name).toBe('CredentialContentError');

    const deep = { id: 'urn:uuid:1', n: arrays(MAX_CREDENTIAL_NESTING_DEPTH), proof: { proofValue: 'c2ln' } };
    expect(() => signedForm(deep)).toThrow(CredentialContentError);
    for (const unread of [{ id: 'urn:uuid:1', proof: { proofValue: 'c2ln!' } }, { id: 'urn:uuid:1' }, 'a.b.c2ln!']) {
      expect(() => signedForm(unread)).toThrow(NoSignedFormError);
      expect(() => signedForm(unread)).not.toThrow(CredentialContentError);
    }
  });
});

describe('canonicalVcJwt', () => {
  it('rewrites only the signature segment, to the same bytes', () => {
    expect(canonicalVcJwt('aGVhZGVy.cGF5bG9hZA.c2lnbmF0\ndXJ =')).toBe('aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXI');
    expect(canonicalVcJwt('aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl')).toBe('aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl');
  });

  it('refuses what is not a compact JWS with a signature', () => {
    expect(() => canonicalVcJwt('not-a-jwt')).toThrow(NoSignedFormError);
    expect(() => canonicalVcJwt('a.b.')).toThrow(NoSignedFormError);
    expect(() => canonicalVcJwt('a.b.c2ln=bmF0')).toThrow(NoSignedFormError);
    expect(() => canonicalVcJwt('a.b.c2ln+mF0')).toThrow(NoSignedFormError);
  });
});
