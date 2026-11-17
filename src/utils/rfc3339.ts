/**
 * Dates as credentials state them. A date is an RFC 3339 date-time (§5.6) with its zone given, as
 * `Z` or as a numeric offset: the form the VC Data Model 2.0 gives `validFrom` and `validUntil`,
 * `xsd:dateTimeStamp`, which requires a zone. Anything else is no date.
 *
 * `Date.parse` is no such rule. It takes forms of its own, such as `2026-01-01` or `Thu, 01 Jan
 * 2026 00:00:00 GMT`, it may roll an impossible day such as the 30th of February over into the
 * next month, and it reads a date-time that gives no zone in the zone of the machine it runs on,
 * so two verifiers read one date as two instants hours apart and give one credential two answers.
 * A date read here names one instant wherever it is read, or is refused by its text alone.
 */

/** The form a date must take, as a reason that refuses one names it. */
export const DATE_TIME_FORM = 'an RFC 3339 date-time with a time zone';

/**
 * The fields of an RFC 3339 date-time with its zone. The separator and the zone may each be a
 * capital or a small letter, `T` or `t` and `Z` or `z`, as the note to §5.6 allows.
 */
const DATE_TIME = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:[Zz]|([+-])(\d{2}):(\d{2}))$/;

/** The days in `month` (1 to 12) of `year`, by the Gregorian calendar. */
function daysIn(year: number, month: number): number {
  if (month === 2) return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

/**
 * The instant an RFC 3339 date-time names, in epoch milliseconds, or `undefined` for anything that
 * is not one, a value that is not a string included. Its zone is given, as `Z` or as an offset, so
 * it names one instant wherever it is read. A fraction of a second has one digit or more, as §5.6
 * writes it (`time-secfrac = "." 1*DIGIT`), and is cut to the millisecond, never rounded up past
 * the instant it states. A leap second is refused: an instant in milliseconds cannot hold one.
 */
export function parseDateTime(value: unknown): number | undefined {
  if (typeof value !== 'string') return undefined;
  const fields = DATE_TIME.exec(value);
  if (fields === null) return undefined;
  const [year, month, day, hour, minute, second] = fields.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  const [, , , , , , , fraction = '', sign, offsetHours = '00', offsetMinutes = '00'] = fields;
  if (month < 1 || month > 12 || day < 1 || day > daysIn(year, month)) return undefined;
  if (hour > 23 || minute > 59 || second > 59 || Number(offsetHours) > 23 || Number(offsetMinutes) > 59) return undefined;
  const offset = Number(offsetHours) * 60 + Number(offsetMinutes);
  const instant = new Date(0);
  // Set as a full year, so a year before 100 is not read as one of the twentieth century.
  instant.setUTCFullYear(year, month - 1, day);
  instant.setUTCHours(hour, minute, second, Number(fraction.padEnd(3, '0').slice(0, 3)));
  return instant.getTime() - (sign === '-' ? -offset : offset) * 60_000;
}
