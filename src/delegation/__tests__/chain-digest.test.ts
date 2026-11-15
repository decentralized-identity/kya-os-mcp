/**
 * Delegation chain digests (SPEC.md §7.8, Appendix C.4).
 *
 * The digest is what lets a holder of a chain prove, from a response proof's
 * signature, that it is the chain the server evaluated. These tests pin the
 * value (the SPEC's own vector, so another implementation can check itself
 * against the same numbers) and the two properties it has to have. It moves
 * when anything a credential's issuer signed moves, or the order does. It
 * does not move with anything the issuer did not sign, so the party holding
 * a credential cannot make a server sign a digest that the issuer's own copy
 * fails to reproduce.
 */
import { createHash } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import {
  DELEGATION_CHAIN_DIGEST_DOMAIN,
  DELEGATION_CREDENTIAL_DIGEST_DOMAIN,
  delegationChainDigest,
  delegationCredentialDigest,
  digestDelegationChain,
} from '../chain-digest.js';
import { NoSignedFormError } from '../signed-form.js';
import { arrays, objects } from '../../__tests__/utils/nesting.js';
import { nodeHash as hash } from '../../__tests__/utils/node-crypto-provider.js';

/** SPEC.md Appendix C.4: a root credential object and a leaf presented as a VC-JWT. */
const ROOT = {
  id: 'urn:uuid:1111-aaaa',
  type: ['VerifiableCredential', 'DelegationCredential'],
  issuer: 'did:web:user.example.com',
  credentialSubject: { id: 'did:web:agent-a.example.com' },
  proof: {
    type: 'Ed25519Signature2020',
    created: '2024-03-01T12:00:00Z',
    verificationMethod: 'did:web:user.example.com#key-1',
    proofPurpose: 'assertionMethod',
    proofValue: 'c2lnbmF0dXJlLW9mLXJvb3Q',
  },
};
const LEAF_JWT = 'eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319.c2lnbmF0dXJlLW9mLWxlYWY';
const ROOT_SIGNED_FORM =
  '{"credential":{"credentialSubject":{"id":"did:web:agent-a.example.com"},"id":"urn:uuid:1111-aaaa",' +
  '"issuer":"did:web:user.example.com","type":["VerifiableCredential","DelegationCredential"]},' +
  '"signature":"c2lnbmF0dXJlLW9mLXJvb3Q"}';
const LEAF_SIGNED_FORM =
  '{"jwt":"eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319","signature":"c2lnbmF0dXJlLW9mLWxlYWY"}';
const ROOT_DIGEST = 'sha256:6fbe4c0f04413cb40ec3b3069bf7c73dc1b6a681765e95ac451672136328712e';
const LEAF_DIGEST = 'sha256:d29d65862fce70137390bea2859696c7ad80ce88cede778fea1cab24d513eed1';
const CHAIN_DIGEST = 'sha256:2df99ab7f9b80436dba945e0dfb7a37bd7b35400c82bbc72a5c2744f516eb788';

/** The construction spelled out, with nothing from the module under test. */
const byHand = (domain: string, canonical: string): string =>
  `sha256:${createHash('sha256').update(`${domain}\0${canonical}`, 'utf8').digest('hex')}`;

describe('delegation chain digests', () => {
  it('reproduces the SPEC Appendix C.4 vector', async () => {
    expect(await delegationCredentialDigest(ROOT, hash)).toBe(ROOT_DIGEST);
    expect(await delegationCredentialDigest(LEAF_JWT, hash)).toBe(LEAF_DIGEST);
    expect(await delegationChainDigest([ROOT_DIGEST, LEAF_DIGEST], hash)).toBe(CHAIN_DIGEST);
    expect(await digestDelegationChain([ROOT, LEAF_JWT], hash)).toEqual({
      credentials: [ROOT_DIGEST, LEAF_DIGEST],
      chain: CHAIN_DIGEST,
    });
  });

  it('is SHA-256 over the domain, a zero byte and the canonical signed form', () => {
    expect(DELEGATION_CREDENTIAL_DIGEST_DOMAIN).toBe('org.kya-os.delegation.credential.v1');
    expect(DELEGATION_CHAIN_DIGEST_DOMAIN).toBe('org.kya-os.delegation.chain.v1');
    expect(byHand(DELEGATION_CREDENTIAL_DIGEST_DOMAIN, ROOT_SIGNED_FORM)).toBe(ROOT_DIGEST);
    expect(byHand(DELEGATION_CREDENTIAL_DIGEST_DOMAIN, LEAF_SIGNED_FORM)).toBe(LEAF_DIGEST);
    expect(byHand(DELEGATION_CHAIN_DIGEST_DOMAIN, JSON.stringify([ROOT_DIGEST, LEAF_DIGEST])))
      .toBe(CHAIN_DIGEST);
  });

  describe('of a credential object', () => {
    it('does not depend on member order (RFC 8785)', async () => {
      const reordered = {
        proof: ROOT.proof,
        credentialSubject: { id: 'did:web:agent-a.example.com' },
        issuer: 'did:web:user.example.com',
        type: ['VerifiableCredential', 'DelegationCredential'],
        id: 'urn:uuid:1111-aaaa',
      };
      expect(await delegationCredentialDigest(reordered, hash)).toBe(ROOT_DIGEST);
    });

    it('moves with any claim the issuer signed', async () => {
      const widened = { ...ROOT, credentialSubject: { id: 'did:web:agent-b.example.com' } };
      expect(await delegationCredentialDigest(widened, hash)).not.toBe(ROOT_DIGEST);
      const extra = { ...ROOT, note: 'added' };
      expect(await delegationCredentialDigest(extra, hash)).not.toBe(ROOT_DIGEST);
    });

    it('moves with the signature, so the same claims signed again are another credential', async () => {
      const resigned = { ...ROOT, proof: { ...ROOT.proof, proofValue: 'YW5vdGhlci1zaWduYXR1cmU' } };
      expect(await delegationCredentialDigest(resigned, hash)).not.toBe(ROOT_DIGEST);
    });

    it('does not move with proof members the signature does not cover', async () => {
      // SPEC §6.2: type, created, verificationMethod and proofPurpose are
      // outside the signature, as is anything else a holder adds to `proof`.
      const redressed = {
        ...ROOT,
        proof: {
          type: 'DataIntegrityProof',
          created: '2031-01-01T00:00:00Z',
          verificationMethod: 'did:web:user.example.com#another-key',
          proofPurpose: 'authentication',
          proofValue: ROOT.proof.proofValue,
          note: 'added by whoever held this copy',
          cache: undefined,
          fetchedAt: new Date(0),
        },
      };
      expect(await delegationCredentialDigest(redressed, hash)).toBe(ROOT_DIGEST);
    });

    it('does not move with how the signature is written', async () => {
      // 17 bytes leave two spare bits in the last character; "Q" and "R"
      // carry the same signature. So do padding and whitespace, which
      // decoders in use pass over.
      const written = [
        'c2lnbmF0dXJlLW9mLXJvb3R',
        'c2lnbmF0dXJlLW9mLXJvb3Q=',
        'c2lnbmF0dXJl LW9mLXJvb3Q',
        'c2lnbmF0dXJl\nLW9mLXJvb3Q==',
      ];
      for (const proofValue of written) {
        const recoded = { ...ROOT, proof: { ...ROOT.proof, proofValue } };
        expect(await delegationCredentialDigest(recoded, hash)).toBe(ROOT_DIGEST);
      }
      const urlSafe = { ...ROOT, proof: { ...ROOT.proof, proofValue: '-_-_' } };
      const standard = { ...ROOT, proof: { ...ROOT.proof, proofValue: '+/+/' } };
      expect(await delegationCredentialDigest(urlSafe, hash))
        .toBe(await delegationCredentialDigest(standard, hash));
    });

    it('counts a member named __proto__ as the member it is', async () => {
      const smuggled = JSON.parse(JSON.stringify(ROOT).replace('{', '{"__proto__":{"scope":"all"},')) as object;
      expect(Object.keys(smuggled)).toContain('__proto__');
      expect(await delegationCredentialDigest(smuggled, hash)).not.toBe(ROOT_DIGEST);
    });

    it.each([
      ['no proof', { id: 'urn:uuid:x' }],
      ['a proof with no proofValue', { id: 'urn:uuid:x', proof: { type: 'Ed25519Signature2020' } }],
      ['an empty proofValue', { id: 'urn:uuid:x', proof: { proofValue: '' } }],
      ['a proofValue with no base64 character in it', { id: 'urn:uuid:x', proof: { proofValue: '!?!' } }],
      ['a proofValue that is not a string', { id: 'urn:uuid:x', proof: { proofValue: 7 } }],
      ['a list of proofs', { id: 'urn:uuid:x', proof: [{ proofValue: 'c2ln' }] }],
      ['a JWT marker in place of a signature', { id: 'urn:uuid:x', proof: { type: 'JwtProof2020', jwt: LEAF_JWT } }],
      ['padding inside its proofValue', { id: 'urn:uuid:x', proof: { proofValue: 'c2ln=bmF0' } }],
    ])('refuses an object with %s: it has no signed form', async (_name, value) => {
      await expect(delegationCredentialDigest(value, hash)).rejects.toThrow(NoSignedFormError);
    });

    it('refuses signed content with no canonical JSON form: it has no signed form either', async () => {
      const cyclic: Record<string, unknown> = { id: 'urn:uuid:loop', proof: ROOT.proof };
      cyclic.self = cyclic;
      const unsignable = [
        cyclic,
        { id: 'x', extra: undefined, proof: ROOT.proof },
        { id: 'x', issued: Number.NaN, proof: ROOT.proof },
        { id: 'x', issued: Number.POSITIVE_INFINITY, proof: ROOT.proof },
        // One past the integers a double holds exactly: another parser may
        // read another number from the same text.
        { id: 'x', issued: 2 ** 53, proof: ROOT.proof },
      ];
      for (const credential of unsignable) {
        await expect(delegationCredentialDigest(credential, hash)).rejects.toThrow(NoSignedFormError);
      }
      // The largest such integer is signed content like any other.
      await expect(delegationCredentialDigest({ id: 'x', issued: 2 ** 53 - 1, proof: ROOT.proof }, hash))
        .resolves.toMatch(/^sha256:[0-9a-f]{64}$/);
    });

    describe('holding an element that is not enumerable, which JSON has', () => {
      const hiddenElement = (value: unknown): unknown[] =>
        Object.defineProperty([0], 0, { value, enumerable: false, writable: true, configurable: true });

      it('digests it as the element it is', async () => {
        const hidden = { ...ROOT, n: hiddenElement(arrays(10)) };
        const shown = { ...ROOT, n: [arrays(10)] };
        expect(await delegationCredentialDigest(hidden, hash)).toBe(await delegationCredentialDigest(shown, hash));
      });

      it.each([70, 200_000])('has no digest %i levels deep: the nesting bound refuses it, not the call stack', async (levels) => {
        const credential = { ...ROOT, n: hiddenElement(arrays(levels)) };
        const thrown = await delegationCredentialDigest(credential, hash).catch((error: unknown) => error);
        expect(thrown).toBeInstanceOf(NoSignedFormError);
        expect(thrown).not.toBeInstanceOf(RangeError);
        expect((thrown as Error).message).toBe('A credential object nests at most 64 levels deep');
        await expect(digestDelegationChain([credential], hash)).rejects.toThrow(NoSignedFormError);
      });
    });

    it('refuses a member keyed by a symbol: it has no canonical JSON form, at the top as below it', async () => {
      for (const credential of [
        { ...ROOT, [Symbol('tag')]: 1 },
        { ...ROOT, credentialSubject: { ...ROOT.credentialSubject, [Symbol('tag')]: 1 } },
      ]) {
        await expect(delegationCredentialDigest(credential, hash)).rejects.toThrow(NoSignedFormError);
        await expect(delegationCredentialDigest(credential, hash)).rejects.toThrow(/symbol-keyed property/);
      }
    });

    it('reports a failing hash provider as that, not as a credential with no signed form', async () => {
      const failing = async () => {
        throw new Error('hsm unreachable');
      };
      const thrown = await delegationCredentialDigest(ROOT, failing).catch((error: unknown) => error);
      expect(thrown).toBeInstanceOf(Error);
      expect(thrown).not.toBeInstanceOf(NoSignedFormError);
      expect((thrown as Error).message).toBe('hsm unreachable');
      await expect(digestDelegationChain([ROOT, LEAF_JWT], failing)).rejects.toThrow('hsm unreachable');
    });
  });

  describe('of a VC-JWT', () => {
    it('moves with the header, the payload or the signature', async () => {
      const [header, payload, signature] = LEAF_JWT.split('.') as [string, string, string];
      // The vector's VC-JWT with one segment changed each time.
      const variants = await Promise.all([
        delegationCredentialDigest(`${header}x.${payload}.${signature}`, hash),
        delegationCredentialDigest(`${header}.${payload}x.${signature}`, hash),
        delegationCredentialDigest(`${header}.${payload}.YW5vdGhlci1zaWduYXR1cmU`, hash),
      ]);
      expect(new Set([LEAF_DIGEST, ...variants]).size).toBe(4);
    });

    it('does not move with how the signature segment is written, as far as a JWS segment may be', async () => {
      const [header, payload, signature] = LEAF_JWT.split('.') as [string, string, string];
      // "Y" and "Z" differ only in the spare bits of the last character. One
      // `=` completes its last group of three, and whitespace is passed over.
      for (const written of ['c2lnbmF0dXJlLW9mLWxlYWZ', `${signature}=`, 'c2lnbmF0dXJl\nLW9mLWxlYWY =']) {
        expect(await delegationCredentialDigest(`${header}.${payload}.${written}`, hash)).toBe(LEAF_DIGEST);
      }
      // Written any further from base64url it is no JWS, and has no digest.
      for (const written of [`${signature}==`, `${signature.slice(0, -1)}+`]) {
        await expect(delegationCredentialDigest(`${header}.${payload}.${written}`, hash))
          .rejects.toThrow(NoSignedFormError);
      }
    });

    it('is not the digest of an object with the same claims', async () => {
      const [header, payload, signature] = LEAF_JWT.split('.') as [string, string, string];
      // The JWT's signing input and signature as members of an object, which is another credential.
      const lookalike = { jwt: `${header}.${payload}`, proof: { proofValue: signature } };
      expect(await delegationCredentialDigest(lookalike, hash)).not.toBe(LEAF_DIGEST);
    });

    it.each([
      ['two segments', 'eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319'],
      ['four segments', `${LEAF_JWT}.extra`],
      ['an empty header', '.eyJ2YyI6e319.c2ln'],
      ['an empty payload', 'eyJhbGciOiJFZERTQSJ9..c2ln'],
      ['an empty signature', 'eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319.'],
      ['padding inside its signature', 'eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319.c2ln=bmF0'],
      ['no dots at all', 'not-a-jwt'],
    ])('refuses a string with %s: it is not a compact JWS', async (_name, value) => {
      await expect(delegationCredentialDigest(value, hash)).rejects.toThrow(NoSignedFormError);
    });
  });

  it.each([
    ['undefined', undefined],
    ['a number', 42],
    ['null', null],
    ['an array', [ROOT]],
    ['a boolean', true],
  ])('refuses %s: it is no credential', async (_name, value) => {
    await expect(delegationCredentialDigest(value as never, hash)).rejects.toThrow(NoSignedFormError);
    await expect(delegationCredentialDigest(value as never, hash)).rejects.toThrow(
      'A delegation credential is a compact VC-JWT string or a credential object',
    );
  });

  it('refuses a string that is not a compact JWS: it is read as one, and is none', async () => {
    await expect(delegationCredentialDigest('urn:uuid:1111-aaaa', hash)).rejects.toThrow(NoSignedFormError);
  });

  describe('of a chain', () => {
    it('depends on order: the same credentials leaf first are another chain', async () => {
      expect(await delegationChainDigest([LEAF_DIGEST, ROOT_DIGEST], hash)).not.toBe(CHAIN_DIGEST);
    });

    it('moves when a hop is added, dropped or replaced', async () => {
      const other = await delegationCredentialDigest({ id: 'urn:uuid:3333-cccc', proof: ROOT.proof }, hash);
      const variants = await Promise.all([
        delegationChainDigest([ROOT_DIGEST], hash),
        delegationChainDigest([ROOT_DIGEST, LEAF_DIGEST, other], hash),
        delegationChainDigest([ROOT_DIGEST, other], hash),
        delegationChainDigest([other, LEAF_DIGEST], hash),
      ]);
      expect(new Set([CHAIN_DIGEST, ...variants]).size).toBe(5);
    });

    it('is domain-separated from a credential digest', async () => {
      // A chain of one is never its credential's digest, and the bytes of a
      // chain could not be passed off as a credential's signed form.
      expect(await delegationChainDigest([ROOT_DIGEST], hash)).not.toBe(ROOT_DIGEST);
      expect(byHand(DELEGATION_CREDENTIAL_DIGEST_DOMAIN, JSON.stringify([ROOT_DIGEST, LEAF_DIGEST])))
        .not.toBe(CHAIN_DIGEST);
    });

    it('can be recomputed from the per-credential digests alone', async () => {
      const { credentials, chain } = await digestDelegationChain([ROOT, LEAF_JWT], hash);
      expect(await delegationChainDigest(credentials, hash)).toBe(chain);
    });

    it('refuses an empty chain', async () => {
      await expect(delegationChainDigest([], hash)).rejects.toThrow('at least one credential');
      await expect(digestDelegationChain([], hash)).rejects.toThrow('at least one credential');
      // An empty list is a caller's mistake, not a credential without a signed form.
      await expect(digestDelegationChain([], hash)).rejects.not.toBeInstanceOf(NoSignedFormError);
    });

    it('has no digest when one credential of it has no signed form', async () => {
      await expect(digestDelegationChain([ROOT, 42 as never, LEAF_JWT], hash)).rejects.toThrow(NoSignedFormError);
      await expect(digestDelegationChain([{ id: 'urn:uuid:x' }, LEAF_JWT], hash)).rejects.toThrow(NoSignedFormError);
    });

    it.each([
      ['uppercase hex', ROOT_DIGEST.toUpperCase().replace('SHA256', 'sha256')],
      ['a short digest', ROOT_DIGEST.slice(0, -1)],
      ['another algorithm', ROOT_DIGEST.replace('sha256', 'sha512')],
      ['a bare hex string', ROOT_DIGEST.slice('sha256:'.length)],
      ['a non-string', 7 as unknown as string],
    ])('refuses %s as a credential digest', async (_name, digest) => {
      await expect(delegationChainDigest([ROOT_DIGEST, digest], hash)).rejects.toThrow(TypeError);
    });

    it('does not change the list it is given', async () => {
      const digests = Object.freeze([ROOT_DIGEST, LEAF_DIGEST]);
      expect(await delegationChainDigest(digests, hash)).toBe(CHAIN_DIGEST);
    });
  });

  // `conformance/verify.py` holds its own reading to these same cases, so the
  // two implementations refuse alike and, where they do not refuse, agree.
  describe('the cases the Python verifier is held to', () => {
    const JWT = 'eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319.';
    const SIGNED = { id: 'urn:uuid:1111-aaaa', proof: { proofValue: 'c2lnbmF0dXJl' } };
    const signedAs = (proofValue: unknown) => ({ id: 'urn:uuid:1111-aaaa', proof: { proofValue } });
    // A credential object is level 1, so a member nested 63 deep makes it 64 deep, the bound.
    const holdsItself: Record<string, unknown> = { ...SIGNED };
    holdsItself['self'] = holdsItself;
    // A number as JSON.parse reads its text: as the double nearest it, which
    // for an integer past the largest double is infinite.
    const withNumber = (digits: string): unknown =>
      JSON.parse(`{"id":"urn:uuid:1111-aaaa","proof":{"proofValue":"c2lnbmF0dXJl"},"n":${digits}}`);

    it.each([
      ['`=` ahead of a base64 character', `${JWT}c2lnbmF0=dXJl`],
      ['`=` at the start', `${JWT}=c2lnbmF0dXJl`],
      ['a character of neither alphabet', `${JWT}c2lnbmF0dXJl*`],
      ['a vertical tab, which is not whitespace', `${JWT}c2lnbmF0\vdXJl`],
      ['a JWS signature written with `+`, which is base64 and not base64url', `${JWT}c2ln+mF0dXJl`],
      ['a JWS signature written with `/`', `${JWT}c2ln/mF0dXJl`],
      ['a JWS signature with `=` after whole groups of four', `${JWT}c2lnbmF0dXJl=`],
      ['a JWS signature with two `=` after a last group of three', `${JWT}c2lnbmF0dXI==`],
      ['a JWS signature with one `=` after a last group of two, which takes two', `${JWT}c2lnbmF0dQ=`],
      ['a JWS signature with a whole group of `=`', `${JWT}c2lnbmF0dXJl====`],
      ['a JWS signature whose last character gives no byte', `${JWT}c2lnbmF0d`],
      ['a signature of no whole byte', `${JWT}c`],
      ['no signature', JWT],
      ['an empty header', '.eyJ2YyI6e319.c2lnbmF0dXJl'],
      ['an empty payload', 'eyJhbGciOiJFZERTQSJ9..c2lnbmF0dXJl'],
      ['two segments', 'eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319'],
      ['four segments', 'eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319.c2lnbmF0dXJl.c2ln'],
      ['an object with no proof', { id: 'urn:uuid:1111-aaaa' }],
      ['a proofValue that is not a string', signedAs(7)],
      ['a proofValue with a vertical tab in it', signedAs('c2lnbmF0\vdXJl')],
      ['a proofValue with `=` ahead of a base64 character', signedAs('c2lnbmF0=dXJl')],
      ['an integer a receiver need not read exactly', { ...SIGNED, n: 2 ** 53 }],
      ['such an integer written with an exponent', { ...SIGNED, n: 1e16 }],
      ['a number that is not finite', { ...SIGNED, n: Infinity }],
      ['an integer of 400 digits, read from JSON text', withNumber('1'.repeat(400))],
      ['an integer of 4301 digits, read from JSON text', withNumber('1'.repeat(4301))],
      // A number is read as a double before it is held to that, whatever its text.
      ['a number that is no integer as written and reads as 9007199254740994', withNumber('9007199254740993.5')],
      ['a number below 2^53 as written that reads as 2^53, a tie gone to even', withNumber('9007199254740991.5')],
      ['a string that is not well-formed Unicode', { ...SIGNED, s: '\ud800' }],
      ['an object nested 65 levels deep in arrays, one past the bound', { ...SIGNED, n: arrays(64) }],
      ['an object nested 65 levels deep in objects', { ...SIGNED, n: objects(64) }],
      ['an object nested 65 levels deep in its proof', { ...SIGNED, proof: { ...SIGNED.proof, note: arrays(63) } }],
      ['an object nested deeper than any stack', { ...SIGNED, n: arrays(100_000) }],
      ['an object that holds itself', holdsItself],
      ['an array', ['eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319.c2lnbmF0dXJl']],
      ['null', null],
    ])('gives no digest to %s', async (_name, value) => {
      await expect(delegationCredentialDigest(value as never, hash)).rejects.toThrow(NoSignedFormError);
    });

    it.each([
      [
        'a JWS signature',
        `${JWT}c2lnbmF0dXI`,
        'sha256:54100f570455d7b0f955febea7bfb03961fae7ac4ec04091312d668eac5884e3',
      ],
      [
        'that signature broken across lines, padded, and with a spare bit set',
        `${JWT}c2lnbmF0\ndXJ =`,
        'sha256:54100f570455d7b0f955febea7bfb03961fae7ac4ec04091312d668eac5884e3',
      ],
      [
        'a JWS signature with a form feed in it, which is whitespace where a vertical tab is not',
        `${JWT}c2lnbmF0\fdXJl`,
        'sha256:d612091f803bc695ce2977ea0a08d547d493048f1ee02895ac40af882256f0ce',
      ],
      [
        'a proofValue with a form feed in it',
        signedAs('c2lnbmF0\fdXJl'),
        'sha256:1e44f47096f50bb8d2f0a32ee74a182c41aaec5704fc3eeb3704a3dfc7ab18cf',
      ],
      [
        'a proofValue',
        signedAs('-_-_'),
        'sha256:0f494896114a7e198939ef17be1459def88e5d7d5349f16259b08ce383deae22',
      ],
      [
        'that proofValue in the base64 alphabet, with a line break and more padding than a group holds',
        signedAs('+/+/\n==='),
        'sha256:0f494896114a7e198939ef17be1459def88e5d7d5349f16259b08ce383deae22',
      ],
      [
        'the largest integer read exactly',
        { ...SIGNED, n: 2 ** 53 - 1 },
        'sha256:0471052646eafa107e3ff1b8d079896cdc668b67da5443a718f2bcd306f4f49e',
      ],
      [
        'that integer written with a fraction, which reads as it',
        withNumber('9007199254740991.0') as object,
        'sha256:0471052646eafa107e3ff1b8d079896cdc668b67da5443a718f2bcd306f4f49e',
      ],
      [
        'a small fraction and a character outside the BMP',
        { ...SIGNED, n: 1e-7, s: '\u{1F600}' },
        'sha256:dc7620f2c6a54d6d6c6940109e30228ec007f698723e16d94e9c950b4d8d6da0',
      ],
      [
        'an object nested 64 levels deep in arrays, the bound',
        { ...SIGNED, n: arrays(63) },
        'sha256:8cf2933e9f7d627c74f01097d951d53845dbfdbcf19d929ffb35fe3f19ec5068',
      ],
      [
        'an object nested 64 levels deep in objects',
        { ...SIGNED, n: objects(63) },
        'sha256:f742418cf6b9b17356ca5127de22aea0fa61c3df3fd3185eabbfe38462d2584b',
      ],
      [
        'an object nested 64 levels deep in its proof, which is counted and is no part of the digest',
        { ...SIGNED, proof: { ...SIGNED.proof, note: arrays(62) } },
        'sha256:1e44f47096f50bb8d2f0a32ee74a182c41aaec5704fc3eeb3704a3dfc7ab18cf',
      ],
      [
        'an object read from a text that holds `id` and `proof` twice, as the last of each',
        JSON.parse(
          '{"id":"urn:uuid:2222-bbbb","proof":{"proofValue":"*"},"id":"urn:uuid:1111-aaaa","proof":{"proofValue":"c2lnbmF0dXJl"}}',
        ) as object,
        'sha256:1e44f47096f50bb8d2f0a32ee74a182c41aaec5704fc3eeb3704a3dfc7ab18cf',
      ],
      [
        'a VC-JWT whose payload nests deeper than any stack: its segments are digested, and not read',
        `eyJhbGciOiJFZERTQSJ9.${Buffer.from(`{"vc":${'['.repeat(100_000)}${']'.repeat(100_000)}}`).toString('base64url')}.c2lnbmF0dXJl`,
        'sha256:b4667a591db72dba8eb1eba941bec5bc79c817e9d92ab4c649aad03e81fe6967',
      ],
      [
        'a VC-JWT whose payload holds an integer of 4301 digits',
        `eyJhbGciOiJFZERTQSJ9.${Buffer.from(`{"vc":{"id":"urn:a"},"n":${'1'.repeat(4301)}}`).toString('base64url')}.c2lnbmF0dXJl`,
        'sha256:1b5bda68bf124649ffe0c3dd123f5baf1985f9d57124c31f87881db987c2e046',
      ],
    ])('gives %s the digest Python gives it', async (_name, value, digest) => {
      expect(await delegationCredentialDigest(value, hash)).toBe(digest);
    });
  });
});
