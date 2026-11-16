/**
 * `issuerOf`, the one reading of the issuer a credential or status list names (VC Data Model 2.0
 * §4.7: a URL, or an object whose `id` is one) that the delegation verifiers, the Entity Card's
 * verifier and the cheqd status list resolver share.
 */

import { describe, it, expect } from 'vitest';
import { issuerOf } from '../guards.js';

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
