/**
 * The retrieval of a verification method by verification relationship (W3C Controlled Identifiers
 * v1.0 §3.3) that the verifiers of a delegation credential, a status list and a delegation hop go
 * through, and the check of a proof's stated purpose. Those verifiers are tested end to end beside
 * them; these are the document shapes the retrieval reads and the purposes the check reads. How a
 * lookup's work grows is tested in ./verification-relationship-scaling.test.ts, and the lookup is
 * compared with an independent reference in ./verification-relationship-reference.test.ts.
 */

import { describe, it, expect } from 'vitest';
import type { DIDDocument } from '../vc-verifier.types.js';
import {
  assertionMethodRefusal,
  proofPurposeMismatch,
  retrieveVerificationMethod,
  selectAssertionMethod,
  type VerificationRelationship,
} from '../verification-relationship.js';
import { ACME, OTHER, documentOf, keylessMethod as method } from '../../__tests__/utils/did-documents.js';

/** Another DID exactly as long as Acme's, so that only its characters tell the two apart. */
const SAME_LENGTH = 'did:web:evil.example';


/** The id of the method `name` retrieves from `document` for Acme, if any. */
const retrieve = (document: DIDDocument, name: string, relationship: VerificationRelationship = 'assertionMethod') =>
  retrieveVerificationMethod(document, ACME, name, relationship)?.id;

/** What `selectAssertionMethod` selects from `document` for Acme by `named`: the method's id, or why it selects none. */
const select = (document: DIDDocument, named?: unknown) => {
  const selection = selectAssertionMethod(document, ACME, named);
  return 'method' in selection ? selection.method.id : selection;
};

/** The id of the method `document` lists first for Acme under assertionMethod, if it selects one. */
const first = (document: DIDDocument) => {
  const selection = select(document);
  return typeof selection === 'string' ? selection : undefined;
};

describe('retrieveVerificationMethod', () => {
  const document = documentOf({
    verificationMethod: [method(`${ACME}#a`), method('#b'), method(`${ACME}#login`)],
    assertionMethod: [`${ACME}#a`, '#b'],
    authentication: ['#login'],
  });

  it('retrieves a method the relationship references, named absolute or relative, its id written either way', () => {
    for (const name of [`${ACME}#a`, '#a']) expect(retrieve(document, name)).toBe(`${ACME}#a`);
    for (const name of [`${ACME}#b`, '#b']) expect(retrieve(document, name)).toBe('#b');
  });

  it('retrieves a method the relationship embeds, named absolute or relative, its id written either way', () => {
    const embedding = documentOf({ assertionMethod: [method('#a'), method(`${ACME}#b`)] });
    for (const name of [`${ACME}#a`, '#a']) expect(retrieve(embedding, name)).toBe('#a');
    for (const name of [`${ACME}#b`, '#b']) expect(retrieve(embedding, name)).toBe(`${ACME}#b`);
  });

  it('retrieves nothing for a method listed only under another relationship, or under none', () => {
    expect(retrieve(document, '#login')).toBeUndefined();
    expect(retrieve(document, '#login', 'authentication')).toBe(`${ACME}#login`);
    expect(retrieve(documentOf({ verificationMethod: [method('#a')] }), '#a')).toBeUndefined();
    expect(retrieve(document, '#c')).toBeUndefined();
  });

  it('retrieves only a method whose id is under the DID, whatever the document lists and defines', () => {
    // One method to a document, so that no two of them share a fragment and make it ambiguous.
    const outside = [`${OTHER}#k`, `${SAME_LENGTH}#k`, `${ACME}:sub#k`, `${ACME}.evil#k`, `${ACME}/path#k`, `${ACME}?query#k`, 'k'];
    for (const id of outside) {
      const referencing = documentOf({ verificationMethod: [method(id)], assertionMethod: [id, '#k'] });
      const embedding = documentOf({ assertionMethod: [method(id), '#k'] });
      for (const document of [referencing, embedding]) {
        for (const name of [id, '#k', `${ACME}#k`]) expect(retrieve(document, name), `${id}, named ${name}`).toBeUndefined();
        expect(first(document), id).toBeUndefined();
      }
    }
    // Under a DID as long as Acme's, a reference lists none of Acme's methods and a request names none.
    expect(SAME_LENGTH).toHaveLength(ACME.length);
    const referencingForeign = documentOf({ verificationMethod: [method('#k')], assertionMethod: [`${SAME_LENGTH}#k`] });
    for (const name of [`${SAME_LENGTH}#k`, '#k', `${ACME}#k`]) expect(retrieve(referencingForeign, name), name).toBeUndefined();
    expect(first(referencingForeign)).toBeUndefined();
    const listing = documentOf({ verificationMethod: [method('#k')], assertionMethod: ['#k'] });
    expect(retrieve(listing, '#k')).toBe('#k');
    expect(retrieve(listing, `${SAME_LENGTH}#k`)).toBeUndefined();
  });

  it('retrieves a method whose id is the DID itself, with no fragment', () => {
    const bare = documentOf({ verificationMethod: [method(ACME)], assertionMethod: [ACME] });
    expect(retrieve(bare, ACME)).toBe(ACME);
  });

  it("retrieves nothing from a document that is not the DID's own, or names no DID", () => {
    const members = { verificationMethod: [method('#a')], assertionMethod: ['#a'] };
    for (const id of [OTHER, `${ACME}:users:alice`]) expect(retrieve(documentOf(members, id), '#a')).toBeUndefined();
    expect(retrieve(members as unknown as DIDDocument, '#a')).toBeUndefined();
  });

  it('retrieves nothing for a DID URL with a fragment, even from a document that names it as its id', () => {
    const withFragment = `${ACME}#a`;
    const document = documentOf({ verificationMethod: [method('#b', withFragment)], assertionMethod: ['#b'] }, withFragment);
    for (const name of ['#b', `${withFragment}#b`]) {
      expect(retrieveVerificationMethod(document, withFragment, name, 'assertionMethod')).toBeUndefined();
    }
    expect(selectAssertionMethod(document, withFragment, undefined)).toEqual({ refused: 'no usable first entry' });
  });

  it('retrieves nothing for an id the document defines twice, among verificationMethod and the methods the relationship embeds', () => {
    const twice = [
      { verificationMethod: [method('#a'), method(`${ACME}#a`)], assertionMethod: ['#a'] },
      { verificationMethod: [method('#a')], assertionMethod: [method(`${ACME}#a`)] },
      { assertionMethod: [method('#a'), '#a', method('#a')] },
    ];
    for (const members of twice) {
      expect(retrieve(documentOf(members), '#a')).toBeUndefined();
      expect(first(documentOf(members))).toBeUndefined();
    }
  });

  it('retrieves a method, referenced or embedded, only when it has an id, a type and a controller', () => {
    const { type: _type, ...untyped } = method('#a');
    const { controller: _controller, ...uncontrolled } = method('#b');
    const malformed = [untyped, uncontrolled, { ...method('#c'), type: '' }, { ...method('#d'), controller: 7 }];
    const names = ['#a', '#b', '#c', '#d'];
    const referencing = documentOf({ verificationMethod: [...malformed, method('#e')], assertionMethod: [...names, '#e'] });
    const embedding = documentOf({ assertionMethod: [...malformed, method('#e')] });
    for (const document of [referencing, embedding]) {
      for (const name of names) expect(retrieve(document, name)).toBeUndefined();
      expect(retrieve(document, '#e')).toBe('#e');
      expect(first(document)).toBeUndefined();
    }
  });

  it('retrieves a method, referenced or embedded, only when its controller is the DID', () => {
    const controllers = [OTHER, `${ACME}#a`, `${ACME}:sub`, `${ACME}/`, `${ACME} `, 'did:web:ACME.example', ACME.slice(0, -1)];
    for (const controller of controllers) {
      const referencing = documentOf({ verificationMethod: [method('#a', controller), method('#b')], assertionMethod: ['#a', '#b'] });
      const embedding = documentOf({ assertionMethod: [method('#a', controller), method('#b')] });
      for (const document of [referencing, embedding]) {
        expect(retrieve(document, '#a')).toBeUndefined();
        expect(retrieve(document, `${ACME}#a`)).toBeUndefined();
        expect(first(document)).toBeUndefined();
      }
    }
  });

  it('reads an id that a method it cannot use defines as defined, so a second definition of it names no method', () => {
    const { type: _type, ...untyped } = method('#a');
    for (const unusable of [method('#a', OTHER), untyped]) {
      for (const verificationMethod of [[unusable, method('#a')], [method('#a'), unusable]]) {
        const document = documentOf({ verificationMethod, assertionMethod: ['#a'] });
        expect(retrieve(document, '#a')).toBeUndefined();
        expect(first(document)).toBeUndefined();
      }
    }
  });

  it('reads references against verificationMethod and the methods the same relationship embeds, not another relationship', () => {
    const embedding = documentOf({ authentication: [method('#login')], assertionMethod: ['#login', '#a', method('#a')] });
    expect(retrieve(embedding, '#login')).toBeUndefined();
    expect(first(embedding)).toBeUndefined();
  });

  it('reads the relationship and verificationMethod only as arrays', () => {
    const published = { verificationMethod: [method(`${ACME}#a`)] };
    for (const assertionMethod of [`${ACME}#a`, { [`${ACME}#a`]: true }, null]) {
      expect(retrieve(documentOf({ ...published, assertionMethod }), '#a')).toBeUndefined();
    }
    expect(retrieve(documentOf({ verificationMethod: { '#a': method('#a') }, assertionMethod: ['#a'] }), '#a')).toBeUndefined();
  });

  it('resolves a reference past entries of verificationMethod that are not methods', () => {
    const document = documentOf({ verificationMethod: [42, null, { type: 'JsonWebKey' }, method('#a')], assertionMethod: ['#a'] });
    expect(retrieve(document, '#a')).toBe('#a');
  });
});

describe('selectAssertionMethod', () => {
  const NO_FIRST_ENTRY = { refused: 'no usable first entry' };

  it('selects the method a name names, absolute or relative, and with no name the first assertionMethod entry', () => {
    const document = documentOf({ verificationMethod: [method('#a'), method(`${ACME}#b`)], assertionMethod: ['#a', '#b'] });
    for (const named of ['#b', `${ACME}#b`]) expect(select(document, named)).toBe(`${ACME}#b`);
    expect(select(document, undefined)).toBe('#a');
  });

  it('refuses a name that is present and is not a non-empty string, whatever the first entry lists', () => {
    const document = documentOf({ verificationMethod: [method('#a')], assertionMethod: ['#a'] });
    for (const named of ['', 7, 0, null, false, {}, ['#a'], JSON.parse('{"toString":"#a"}')]) {
      expect(select(document, named), JSON.stringify(named)).toEqual({ refused: 'not a name' });
    }
    expect(select(document)).toBe('#a');
  });

  it('refuses a name assertionMethod does not list as not listed', () => {
    const document = documentOf({ verificationMethod: [method('#a'), method('#login')], assertionMethod: ['#a'], authentication: ['#login'] });
    for (const named of ['#login', '#gone', `${OTHER}#a`, 'a']) expect(select(document, named), named).toEqual({ refused: 'not listed' });
  });

  it("refuses a dangling first entry without falling through to a later usable method", () => {
    const usable = { verificationMethod: [method('#a'), method('#b'), method(`${OTHER}#c`, OTHER), method('#twice'), method('#twice')] };
    for (const entry of ['#gone', 42, null, { id: 7 }, `${OTHER}#c`, '#twice', '']) {
      expect(select(documentOf({ ...usable, assertionMethod: [entry, '#b', '#a'] })), String(entry)).toEqual(NO_FIRST_ENTRY);
    }
    expect(select(documentOf({ ...usable, assertionMethod: ['#a', '#gone'] }))).toBe('#a');
  });

  it('says so when the method it would select names another DID as its controller, named or listed first', () => {
    const reason = (name: string) => `Verification method "${name}" under assertionMethod of "${ACME}" has another DID as its controller: "${OTHER}"`;
    const referencing = documentOf({ verificationMethod: [method('#a', OTHER)], assertionMethod: ['#a'] });
    const embedding = documentOf({ assertionMethod: [method('#a', OTHER)] });
    for (const document of [referencing, embedding]) {
      for (const named of ['#a', `${ACME}#a`]) expect(select(document, named)).toEqual({ refused: 'another DID', reason: reason(named) });
      expect(select(document)).toEqual({ refused: 'another DID', reason: reason('#a') });
    }
  });

  it("says so when the method it would select is listed in the document of another DID", () => {
    const reason = (name: string) => `Verification method "${name}" under assertionMethod of "${ACME}" has another DID as its document's id: "${OTHER}"`;
    for (const controller of [ACME, OTHER]) {
      const document = documentOf({ verificationMethod: [method('#a', controller)], assertionMethod: ['#a'] }, OTHER);
      for (const named of ['#a', `${ACME}#a`]) expect(select(document, named)).toEqual({ refused: 'another DID', reason: reason(named) });
      expect(select(document)).toEqual({ refused: 'another DID', reason: reason('#a') });
    }
  });

  it('refuses as not listed a method under another controller that does not conform, or whose id is defined twice', () => {
    const { type: _type, ...untyped } = method('#a', OTHER);
    for (const verificationMethod of [[untyped], [method('#a', OTHER), method('#a', OTHER)]]) {
      const document = documentOf({ verificationMethod, assertionMethod: ['#a'] });
      expect(select(document, '#a')).toEqual({ refused: 'not listed' });
      expect(select(document)).toEqual(NO_FIRST_ENTRY);
    }
    // A document with no id names no DID, so it is not another DID's either.
    const anonymous = { verificationMethod: [method('#a')], assertionMethod: ['#a'] } as unknown as DIDDocument;
    expect(select(anonymous, '#a')).toEqual({ refused: 'not listed' });
  });

  it('takes nothing when no entry names a usable method', () => {
    const published = { verificationMethod: [method('#a')] };
    expect(first(documentOf({ ...published, assertionMethod: ['#gone'] }))).toBeUndefined();
    expect(first(documentOf(published))).toBeUndefined();
    expect(first(documentOf({ ...published, assertionMethod: ['#a'] }, OTHER))).toBeUndefined();
  });

  it('reads an entry that names no method as none, even when the DID itself names one the relationship does not list', () => {
    const bare = documentOf({ verificationMethod: [method(ACME)], assertionMethod: [42, `${OTHER}#k`, { type: 'JsonWebKey' }] });
    expect(first(bare)).toBeUndefined();
    expect(retrieve(bare, ACME)).toBeUndefined();
  });
});

describe('assertionMethodRefusal', () => {
  /** How each verifier calls the name its proof gives its key. */
  const NAMINGS = ['JWT kid', 'Proof verificationMethod', 'Status list proof verificationMethod'];

  it('says why no key was selected, in the words of the verifier that names it, quoting the issuer DID every time', () => {
    for (const naming of NAMINGS) {
      expect(assertionMethodRefusal({ refused: 'not a name' }, naming, '', ACME)).toBe(`${naming} "" is not a DID URL`);
      expect(assertionMethodRefusal({ refused: 'not a name' }, naming, ['#a'], ACME)).toBe(`${naming} of type array is not a DID URL`);
      expect(assertionMethodRefusal({ refused: 'not listed' }, naming, '#login', ACME))
        .toBe(`Verification method "#login" not found under assertionMethod of "${ACME}"`);
      expect(assertionMethodRefusal({ refused: 'no usable first entry' }, naming, undefined, ACME))
        .toBe(`${naming} is absent, and assertionMethod of "${ACME}" has no usable first entry`);
      expect(assertionMethodRefusal({ refused: 'another DID', reason: 'the reason it gives' }, naming, '#a', ACME)).toBe('the reason it gives');
    }
  });

  it('quotes the name and the issuer DID as describeValue does, cut after 64 characters and escaped', () => {
    const long = `${ACME}:${'a'.repeat(100)}`;
    const quotedLong = `"${long.slice(0, 64)}"...`;
    const hidden = 'did:web:acme\u202e.example';
    expect(assertionMethodRefusal({ refused: 'not listed' }, 'JWT kid', `${long}#k`, hidden))
      .toBe(`Verification method ${quotedLong} not found under assertionMethod of "did:web:acme\\u202e.example"`);
    expect(assertionMethodRefusal({ refused: 'no usable first entry' }, 'JWT kid', undefined, long))
      .toBe(`JWT kid is absent, and assertionMethod of ${quotedLong} has no usable first entry`);
  });

  it('writes the reason for each selection selectAssertionMethod refuses', () => {
    const document = documentOf({ verificationMethod: [method('#a'), method('#b', OTHER)], assertionMethod: ['#gone', '#a', '#b'] });
    const refusals: [unknown, string][] = [
      [7, 'Proof verificationMethod of type number is not a DID URL'],
      ['#login', `Verification method "#login" not found under assertionMethod of "${ACME}"`],
      [undefined, `Proof verificationMethod is absent, and assertionMethod of "${ACME}" has no usable first entry`],
      ['#b', `Verification method "#b" under assertionMethod of "${ACME}" has another DID as its controller: "${OTHER}"`],
    ];
    for (const [named, reason] of refusals) {
      const selection = selectAssertionMethod(document, ACME, named);
      if ('method' in selection) throw new Error(`selected ${selection.method.id}`);
      expect(assertionMethodRefusal(selection, 'Proof verificationMethod', named, ACME)).toBe(reason);
    }
  });
});

describe('proofPurposeMismatch', () => {
  const mismatch = (proofPurpose: unknown) => proofPurposeMismatch({ proofPurpose }, 'assertionMethod');

  it('accepts a proof that states the relationship, or states no purpose', () => {
    for (const proof of [{ proofPurpose: 'assertionMethod' }, {}, { proofPurpose: undefined }, undefined, 'proof']) {
      expect(proofPurposeMismatch(proof, 'assertionMethod')).toBeUndefined();
    }
  });

  it('refuses a proof that states another purpose, naming both', () => {
    expect(mismatch('authentication')).toBe('Proof purpose "authentication" is not assertionMethod');
    expect(mismatch('AssertionMethod')).toBe('Proof purpose "AssertionMethod" is not assertionMethod');
    expect(mismatch('')).toBe('Proof purpose "" is not assertionMethod');
  });

  it('refuses a stated purpose that is not a string, even one that holds the relationship, naming its type', () => {
    const stated: [unknown, string][] = [
      [['assertionMethod'], 'array'],
      [{ purpose: 'assertionMethod' }, 'object'],
      [JSON.parse('{"toString":"assertionMethod"}'), 'object'],
      [null, 'null'],
      [7, 'number'],
      [true, 'boolean'],
    ];
    for (const [proofPurpose, type] of stated) {
      expect(mismatch(proofPurpose)).toBe(`Proof purpose of type ${type} is not assertionMethod`);
    }
  });

  it('quotes a stated purpose as describeValue does, cut after its first 64 characters', () => {
    expect(mismatch('z'.repeat(100_000))).toBe(`Proof purpose "${'z'.repeat(64)}"... is not assertionMethod`);
  });
});
