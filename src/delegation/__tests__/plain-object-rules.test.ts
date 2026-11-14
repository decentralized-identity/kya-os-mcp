/**
 * The package's two plain-object rules, side by side. The `statusListIssuers` map is held to this
 * realm (`isPlainObjectOfThisRealm`, `utils/statuslist-acceptance.ts`); a DID document may come
 * from any realm (`isPlainObjectOfAnyRealm`, `../did-document-walk.ts`).
 */

import vm from 'node:vm';
import { describe, expect, it } from 'vitest';
import { measureDidDocument } from '../did-document-walk.js';
import { assertStatusListIssuers } from '../../utils/statuslist-acceptance.js';

const ISSUER = 'did:web:issuer.example';
const LIST = 'https://status.example/lists/1';
const NOT_A_MAP =
  'statusListIssuers must be a plain object mapping each status-list issuer DID to the status-list URLs or https origins it keeps';

/** `source`, an expression, evaluated in a realm of its own. */
const elsewhere = (source: string): unknown => vm.runInNewContext(`(${source})`);

describe('a plain object of this realm', () => {
  it('is admitted by both rules, written as a literal, frozen, or made with no prototype', () => {
    const noPrototype = Object.assign(Object.create(null) as Record<string, unknown>, { id: ISSUER });
    for (const value of [{ id: ISSUER }, Object.freeze({ id: ISSUER }), noPrototype]) {
      expect(measureDidDocument(value).ok).toBe(true);
    }
    const map = Object.assign(Object.create(null) as Record<string, unknown>, { [ISSUER]: [LIST] });
    for (const value of [{ [ISSUER]: [LIST] }, Object.freeze({ [ISSUER]: [LIST] }), map]) {
      expect(() => assertStatusListIssuers(value)).not.toThrow();
    }
  });
});

describe('a plain object of another realm', () => {
  it('is admitted as a DID document', () => {
    expect(measureDidDocument(elsewhere(`{ id: '${ISSUER}', service: [{ nested: {} }] }`)).ok).toBe(true);
  });

  it('is refused as a statusListIssuers map, though one that realm made with no prototype is admitted', () => {
    expect(() => assertStatusListIssuers(elsewhere(`{ '${ISSUER}': ['${LIST}'] }`))).toThrow(new TypeError(NOT_A_MAP));
    expect(() => assertStatusListIssuers(elsewhere('Object.create(null)'))).not.toThrow();
  });
});

describe('an object that is not plain', () => {
  it('is refused by both rules, whichever realm made it', () => {
    class Document { id = ISSUER; }
    const inherited: unknown = Object.create({ [ISSUER]: [LIST] });
    for (const value of [new Document(), inherited, elsewhere(`new (class Document { id = '${ISSUER}' })()`)]) {
      expect(() => assertStatusListIssuers(value)).toThrow(new TypeError(NOT_A_MAP));
    }
    expect(measureDidDocument(new Document()).ok).toBe(false);
    expect(measureDidDocument({ id: ISSUER, value: new Map() }).ok).toBe(false);
    expect(measureDidDocument(elsewhere(`new (class Document { id = '${ISSUER}' })()`)).ok).toBe(false);
  });
});
