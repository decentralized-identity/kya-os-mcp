/**
 * The status-list validity rule (`../statuslist-validity.ts`): a list is read only inside the window
 * it states, its VC 2.0 `validFrom` and `validUntil`, or with neither its VC 1.1 `issuanceDate` and
 * `expirationDate`. A list that states no bound is read, a bound that is not a date leaves the window
 * unknown, and a refusal says which bound it went by, quoting the time the list states.
 */

import { describe, expect, it } from 'vitest';
import { RefusalError } from '../refusal.js';
import { acceptStatusListValidity, assertStatusListValidity } from '../statuslist-validity.js';

const NOW = Date.parse('2026-06-30T00:00:00Z');
const PAST = '2026-06-29T00:00:00Z';
const FUTURE = '2026-07-01T00:00:00Z';

describe('acceptStatusListValidity', () => {
  it.each<[string, Record<string, unknown>]>([
    ['states no bound', {}],
    ['is inside its validFrom and validUntil', { validFrom: PAST, validUntil: FUTURE }],
    ['is inside its issuanceDate and expirationDate', { issuanceDate: PAST, expirationDate: FUTURE }],
    ['is at its validUntil exactly', { validUntil: '2026-06-30T00:00:00Z' }],
    ['is at its validFrom exactly', { validFrom: '2026-06-30T00:00:00Z' }],
    ['states a validUntil ahead, which decides over a past expirationDate', { validUntil: FUTURE, expirationDate: PAST }],
    ['states a validFrom behind, which decides over a future issuanceDate', { validFrom: PAST, issuanceDate: FUTURE }],
  ])('reads a list that %s', (_label, list) => {
    expect(acceptStatusListValidity(list, NOW)).toEqual({ valid: true });
  });

  it.each<[string, Record<string, unknown>, string]>([
    ['past its validUntil', { validFrom: PAST, validUntil: PAST }, `status list expired at "${PAST}" (its validUntil)`],
    ['past its expirationDate', { expirationDate: PAST }, `status list expired at "${PAST}" (its expirationDate)`],
    ['before its validFrom', { validFrom: FUTURE }, `status list is not valid until "${FUTURE}" (its validFrom)`],
    ['before its issuanceDate', { issuanceDate: FUTURE }, `status list is not valid until "${FUTURE}" (its issuanceDate)`],
    ['with a validUntil that is not a date', { validUntil: 'never' }, 'status list states a validUntil ("never") that is not a date'],
    ['with a validFrom that is a number', { validFrom: 1_900_000_000 }, 'status list states a validFrom (of type number) that is not a date'],
    ['with a null validUntil, which hides its expirationDate', { validUntil: null, expirationDate: FUTURE }, 'status list states a validUntil (of type null) that is not a date'],
    ['with an expirationDate that is not a date', { expirationDate: 'soon' }, 'status list states an expirationDate ("soon") that is not a date'],
  ])('refuses a list %s, saying so', (_label, list, reason) => {
    expect(acceptStatusListValidity(list, NOW)).toEqual({ valid: false, reason });
  });

  it('reads a value that is not an object as a list that states no bound', () => {
    expect(acceptStatusListValidity(null, NOW)).toEqual({ valid: true });
  });
});

describe('assertStatusListValidity', () => {
  it('throws status_unavailable, which is transient, with the reason, for a list outside its window', () => {
    let thrown: unknown;
    try {
      assertStatusListValidity({ validUntil: PAST }, NOW);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(RefusalError);
    expect((thrown as RefusalError).code).toBe('status_unavailable');
    expect((thrown as RefusalError).message).toBe(`status list expired at "${PAST}" (its validUntil)`);
  });

  it('returns for a list inside its window', () => {
    expect(() => assertStatusListValidity({ validUntil: FUTURE }, NOW)).not.toThrow();
  });
});
