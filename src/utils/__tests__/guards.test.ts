/**
 * `isPlainObjectOfThisRealm`, the one test of a plain object that the status-list acceptance rule
 * and the RFC 8785 serializer share, and `issuerOf`, the one reading of the issuer a credential or status list names (VC Data Model 2.0
 * §4.7: a URL, or an object whose `id` is one) that the delegation verifiers, the Entity Card's
 * verifier and the cheqd status list resolver share.
 */

import { runInNewContext } from 'node:vm';
import { describe, it, expect } from 'vitest';
import { isPlainObjectOfThisRealm, issuerOf } from '../guards.js';

const ACME = 'did:web:acme.example';

describe('issuerOf', () => {
  it('reads an issuer named by a string, or by the id of an object', () => {
    expect(issuerOf(ACME)).toBe(ACME);
    expect(issuerOf({ id: ACME, name: 'Acme' })).toBe(ACME);
    expect(issuerOf('acme')).toBe('acme');
    expect(issuerOf({ id: '' })).toBe('');
  });

  it('reads none from anything else, never converting it', () => {
    const throwing = {
      toString(): string {
        throw new Error('converted');
      },
    };
    const values: unknown[] = [
      { id: 5 },
      {},
      { id: null },
      { id: [ACME] },
      { id: { id: ACME } },
      { id: throwing },
      JSON.parse('{"id":{"toString":"x"}}'),
      [ACME],
      Object.assign([ACME], { id: ACME }),
      throwing,
      5,
      null,
      undefined,
      true,
    ];
    for (const value of values) expect(issuerOf(value)).toBeUndefined();
  });
});

describe('isPlainObjectOfThisRealm', () => {
  it('holds for an object whose prototype is Object.prototype or null', () => {
    const plain: unknown[] = [
      {},
      { id: ACME },
      Object.create(null),
      Object.assign(Object.create(null), { id: ACME }),
      Object.freeze({ id: ACME }),
      JSON.parse('{"__proto__":{"id":"x"}}'),
      new Object(),
    ];
    for (const value of plain) expect(isPlainObjectOfThisRealm(value)).toBe(true);
  });

  it('fails for an array, a class instance, an object of another prototype, and anything that is not an object', () => {
    class Named {}
    const others: unknown[] = [
      [],
      [{}],
      Object.setPrototypeOf([], null),
      Object.setPrototypeOf([], Object.prototype),
      new Named(),
      new (class Object {})(),
      new Date(0),
      new Map(),
      /x/,
      Object.create({}),
      Object.create(Object.create(null)),
      runInNewContext('({})'),
      () => undefined,
      'text',
      5,
      true,
      null,
      undefined,
    ];
    for (const value of others) expect(isPlainObjectOfThisRealm(value)).toBe(false);
  });
});
