/**
 * The date rule (`../rfc3339.ts`): a date is an RFC 3339 date-time with its zone, read as one instant
 * wherever it is read, and anything else is no date, whatever `Date.parse` makes of it.
 */

import { describe, expect, it } from 'vitest';
import { parseDateTime } from '../rfc3339.js';

const MIDNIGHT = Date.UTC(2026, 10, 17);

describe('parseDateTime', () => {
  it.each<[string, string, number]>([
    ['in UTC as Z', '2026-11-17T00:00:00Z', MIDNIGHT],
    ['with small letters, as RFC 3339 allows', '2026-11-17t00:00:00z', MIDNIGHT],
    ['at a positive offset', '2026-11-17T05:30:00+05:30', MIDNIGHT],
    ['at a negative offset', '2026-11-16T18:00:00-06:00', MIDNIGHT],
    ['at the offset -00:00', '2026-11-17T00:00:00-00:00', MIDNIGHT],
    ['with milliseconds', '2026-11-17T00:00:00.250Z', MIDNIGHT + 250],
    ['with one digit of a second', '2026-11-17T00:00:00.5Z', MIDNIGHT + 500],
    ['with nanoseconds, cut to the millisecond and never rounded up', '2026-11-17T00:00:00.999999999Z', MIDNIGHT + 999],
    ['on the 29th of February of a leap year', '2028-02-29T00:00:00Z', Date.UTC(2028, 1, 29)],
    ['on the 29th of February of a year divisible by 400', '2000-02-29T00:00:00Z', Date.UTC(2000, 1, 29)],
  ])('reads a date-time %s', (_label, value, instant) => {
    expect(parseDateTime(value)).toBe(instant);
  });

  it('reads a year before 100 as that year, not as one of the twentieth century', () => {
    const year99 = new Date(0);
    year99.setUTCFullYear(99, 0, 1);
    expect(parseDateTime('0099-01-01T00:00:00Z')).toBe(year99.getTime());
  });

  it.each<[string, unknown]>([
    ['a date-time with no zone, which names no single instant', '2026-11-17T00:00:00'],
    ['a date-time with milliseconds and no zone', '2026-11-17T00:00:00.000'],
    ['a date alone', '2026-11-17'],
    ['an HTTP date', 'Tue, 17 Nov 2026 00:00:00 GMT'],
    ['a date-time with a space for its T', '2026-11-17 00:00:00Z'],
    ['a date-time with no seconds', '2026-11-17T00:00Z'],
    ['an offset with no colon', '2026-11-17T00:00:00+0000'],
    ['an offset of hours alone', '2026-11-17T00:00:00+00'],
    ['a fraction with no digits', '2026-11-17T00:00:00.Z'],
    ['a year of more than four digits', '+02026-11-17T00:00:00Z'],
    ['the 30th of February', '2026-02-30T00:00:00Z'],
    ['the 29th of February of a common year', '2026-02-29T00:00:00Z'],
    ['the 29th of February of a century not divisible by 400', '2100-02-29T00:00:00Z'],
    ['the 31st of a month of 30 days', '2026-11-31T00:00:00Z'],
    ['month 13', '2026-13-01T00:00:00Z'],
    ['month 0', '2026-00-01T00:00:00Z'],
    ['day 0', '2026-11-00T00:00:00Z'],
    ['hour 24', '2026-11-17T24:00:00Z'],
    ['minute 60', '2026-11-17T00:60:00Z'],
    ['a leap second, which an instant in milliseconds cannot hold', '2016-12-31T23:59:60Z'],
    ['an offset of 24 hours', '2026-11-17T00:00:00+24:00'],
    ['an offset of 60 minutes', '2026-11-17T00:00:00+00:60'],
    ['text around a date-time', ' 2026-11-17T00:00:00Z'],
    ['a date-time with a line after it', '2026-11-17T00:00:00Z\n'],
    ['digits that are not ASCII', '２０２６-11-17T00:00:00Z'],
    ['an empty string', ''],
    ['a number of milliseconds', MIDNIGHT],
    ['a Date', new Date(MIDNIGHT)],
    ['null', null],
    ['undefined', undefined],
  ])('reads %s as no date', (_label, value) => {
    expect(parseDateTime(value)).toBeUndefined();
  });

  it('reads a date-time with no zone as no date in every zone, where Date.parse reads it in the zone it runs in', () => {
    const stated = '2026-11-17T00:00:00';
    expect(Number.isNaN(Date.parse(stated))).toBe(false);
    expect(parseDateTime(stated)).toBeUndefined();
  });
});
