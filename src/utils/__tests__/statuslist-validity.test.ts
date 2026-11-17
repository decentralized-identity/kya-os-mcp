/**
 * The status-list validity rule (`../statuslist-validity.ts`): a list is read only inside the window
 * it states, its VC 2.0 `validFrom` and `validUntil`, or with neither its VC 1.1 `issuanceDate` and
 * `expirationDate`. A list that states no bound is read, a bound that is not an RFC 3339 date-time
 * with its zone leaves the window unknown, and a refusal says which bound it went by, quoting the
 * time the list states. Each bound is held with the clock tolerance, `maxClockSkewMs`, 120 seconds
 * unless set.
 */

import { describe, expect, it } from 'vitest';
import { RefusalError } from '../refusal.js';
import { acceptStatusListValidity, assertStatusListValidity } from '../statuslist-validity.js';

/** The reason a list is refused for stating `member` as `stated`, quoted as the reason quotes it. */
const notADate = (member: string, stated: string): string =>
  `status list states ${member} (${stated}) that is not an RFC 3339 date-time with a time zone`;

const NOW = Date.parse('2026-06-30T00:00:00Z');
const PAST = '2026-06-29T00:00:00Z';
const FUTURE = '2026-07-01T00:00:00Z';
const SECOND = 1000;
const at = (offsetMs: number): string => new Date(NOW + offsetMs).toISOString();

describe('acceptStatusListValidity', () => {
  it.each<[string, Record<string, unknown>]>([
    ['states no bound', {}],
    ['is inside its validFrom and validUntil', { validFrom: PAST, validUntil: FUTURE }],
    ['is inside its issuanceDate and expirationDate', { issuanceDate: PAST, expirationDate: FUTURE }],
    ['is at its validUntil exactly', { validUntil: '2026-06-30T00:00:00Z' }],
    ['is at its validFrom exactly', { validFrom: '2026-06-30T00:00:00Z' }],
    ['states a validUntil ahead, which decides over a past expirationDate', { validUntil: FUTURE, expirationDate: PAST }],
    ['states a validFrom behind, which decides over a future issuanceDate', { validFrom: PAST, issuanceDate: FUTURE }],
    ['starts 2 seconds ahead, as a list just issued by a server whose clock runs ahead does', { validFrom: at(2 * SECOND) }],
    ['starts 120 seconds ahead, the clock tolerance exactly', { validFrom: at(120 * SECOND) }],
    ['ended 2 seconds ago, within the clock tolerance', { validUntil: at(-2 * SECOND) }],
    ['ended 120 seconds ago, the clock tolerance exactly', { validUntil: at(-120 * SECOND) }],
    ['states its bounds at offsets from UTC', { validFrom: '2026-06-29T18:00:00-06:00', validUntil: '2026-07-01T05:30:00+05:30' }],
  ])('reads a list that %s', (_label, list) => {
    expect(acceptStatusListValidity(list, NOW)).toEqual({ valid: true });
  });

  it.each<[string, Record<string, unknown>, string]>([
    ['past its validUntil', { validFrom: PAST, validUntil: PAST }, `status list expired at "${PAST}" (its validUntil)`],
    ['past its expirationDate', { expirationDate: PAST }, `status list expired at "${PAST}" (its expirationDate)`],
    ['before its validFrom', { validFrom: FUTURE }, `status list is not valid until "${FUTURE}" (its validFrom)`],
    ['before its issuanceDate', { issuanceDate: FUTURE }, `status list is not valid until "${FUTURE}" (its issuanceDate)`],
    ['ended more than 120 seconds ago', { validUntil: at(-121 * SECOND) }, `status list expired at "${at(-121 * SECOND)}" (its validUntil)`],
    ['starting more than 120 seconds ahead', { validFrom: at(121 * SECOND) }, `status list is not valid until "${at(121 * SECOND)}" (its validFrom)`],
    ['with a validUntil that is not a date', { validUntil: 'never' }, notADate('a validUntil', '"never"')],
    ['with a validFrom that is a number', { validFrom: 1_900_000_000 }, notADate('a validFrom', 'of type number')],
    ['with a null validUntil, which hides its expirationDate', { validUntil: null, expirationDate: FUTURE }, notADate('a validUntil', 'of type null')],
    ['with an expirationDate that is not a date', { expirationDate: 'soon' }, notADate('an expirationDate', '"soon"')],
    ['with a validFrom that states no zone, which names no single instant', { validFrom: '2026-06-29T00:00:00' }, notADate('a validFrom', '"2026-06-29T00:00:00"')],
    ['with an issuanceDate that states no zone', { issuanceDate: '2026-06-29T00:00:00.000' }, notADate('an issuanceDate', '"2026-06-29T00:00:00.000"')],
    ['with a validUntil that is a date alone', { validUntil: '2026-07-01' }, notADate('a validUntil', '"2026-07-01"')],
    ['with a validUntil that is an HTTP date', { validUntil: 'Wed, 01 Jul 2026 00:00:00 GMT' }, notADate('a validUntil', '"Wed, 01 Jul 2026 00:00:00 GMT"')],
    ['with a validUntil no calendar has', { validUntil: '2026-06-31T00:00:00Z' }, notADate('a validUntil', '"2026-06-31T00:00:00Z"')],
  ])('refuses a list %s, saying so', (_label, list, reason) => {
    expect(acceptStatusListValidity(list, NOW)).toEqual({ valid: false, reason });
  });

  it('reads a value that is not an object as a list that states no bound', () => {
    expect(acceptStatusListValidity(null, NOW)).toEqual({ valid: true });
  });

  it('holds each bound with the tolerance it is given, exactly with none', () => {
    expect(acceptStatusListValidity({ validFrom: at(1) }, NOW, 0)).toEqual({ valid: false, reason: `status list is not valid until "${at(1)}" (its validFrom)` });
    expect(acceptStatusListValidity({ validUntil: at(-1) }, NOW, 0)).toEqual({ valid: false, reason: `status list expired at "${at(-1)}" (its validUntil)` });
    expect(acceptStatusListValidity({ validFrom: at(300 * SECOND) }, NOW, 300_000)).toEqual({ valid: true });
  });

  it.each([-1, Number.NaN, 600_001])('throws a TypeError for a tolerance of %s', (skew) => {
    expect(() => acceptStatusListValidity({}, NOW, skew)).toThrow(TypeError);
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
