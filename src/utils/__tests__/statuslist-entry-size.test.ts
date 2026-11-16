/**
 * The one decision about an entry's `statusSize`, made for every status-list reader. An entry that
 * states none, or states 1, is read; one that states more is refused, since its status is not the
 * bit at its index; and a value that is not an integer greater than zero is refused as malformed.
 */
import { describe, expect, it } from 'vitest';
import { MALFORMED_STATUS_SIZES, malformedSizeReason, wideSizeReason } from '../../__tests__/utils/status-sizes.js';
import { acceptEntrySize } from '../statuslist-acceptance.js';

describe('acceptEntrySize', () => {
  it('accepts an entry that states no statusSize, or states 1', () => {
    expect(acceptEntrySize(undefined)).toEqual({ valid: true });
    expect(acceptEntrySize(1)).toEqual({ valid: true });
  });

  it.each([2, 3, 8, 2 ** 53])('refuses an entry of %d bits, naming the size', (statusSize) => {
    expect(acceptEntrySize(statusSize)).toEqual({ valid: false, reason: wideSizeReason(statusSize) });
  });

  it.each(MALFORMED_STATUS_SIZES)('refuses a statusSize of %s as malformed', (_label, statusSize, named) => {
    expect(acceptEntrySize(statusSize)).toEqual({ valid: false, reason: malformedSizeReason(named) });
  });

  it.each([
    ['NaN', Number.NaN, 'NaN'],
    ['Infinity', Number.POSITIVE_INFINITY, 'Infinity'],
    ['true', true, 'of type boolean'],
    ['the string "1"', '1', '"1"'],
    ['a boxed 1', new Number(1), 'of type object'],
    ['an object', { valueOf: () => 1 }, 'of type object'],
  ])('refuses a statusSize of %s as malformed, converting nothing', (_label, statusSize, named) => {
    expect(acceptEntrySize(statusSize)).toEqual({ valid: false, reason: malformedSizeReason(named) });
  });
});
