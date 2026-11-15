/**
 * Test helpers: the `statusSize` values a status entry can state, and the reason the one rule every
 * status-list reader shares (`acceptEntrySize`) gives for each it refuses. Bitstring Status List
 * v1.0 has `statusSize` an integer greater than zero, 1 when the entry states none, and the
 * library's readers read entries of one bit alone.
 */

/** Values that are not an integer greater than zero, each with how a refusal names it. */
export const MALFORMED_STATUS_SIZES: readonly (readonly [string, unknown, string])[] = [
  ['0', 0, '0'],
  ['-1', -1, '-1'],
  ['1.5', 1.5, '1.5'],
  ['the string "2"', '2', '"2"'],
  ['null', null, 'of type null'],
  ['an array', [2], 'of type array'],
];

/** Why an entry whose `statusSize` is malformed is refused; `named` is how the reason names the value. */
export const malformedSizeReason = (named: string): string =>
  `the entry's statusSize (${named}) is not an integer greater than zero`;

/** Why an entry of `statusSize` bits, more than one, is refused. */
export const wideSizeReason = (statusSize: number): string =>
  `the entry's statusSize is ${statusSize}, and only an entry of one bit is read`;

/** The four messages a two-bit entry states, as Bitstring Status List v1.0 writes a `statusMessage`. */
export const TWO_BIT_MESSAGES = [
  { status: '0x0', message: 'valid' },
  { status: '0x1', message: 'revoked' },
  { status: '0x2', message: 'revoked' },
  { status: '0x3', message: 'revoked' },
];
