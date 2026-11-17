/**
 * The window rule (`../validity-window.ts`): where an instant stands against a window whose bounds are
 * held with a clock tolerance, and the `maxClockSkewMs` option that sets it.
 */

import { describe, expect, it } from 'vitest';
import { DEFAULT_CLOCK_SKEW_SECONDS, MAX_CLOCK_SKEW_SECONDS } from '../../proof/verifier.js';
import { DEFAULT_MAX_CLOCK_SKEW_MS, LONGEST_CLOCK_SKEW_MS, clockSkewOption, windowBreach } from '../validity-window.js';

const NOW = Date.UTC(2026, 10, 17);
const SKEW = 120_000;

describe('windowBreach', () => {
  it.each<[string, number | undefined, number | undefined]>([
    ['no bound', undefined, undefined],
    ['a window around now', NOW - 1, NOW + 1],
    ['a start at now exactly', NOW, undefined],
    ['an end at now exactly', undefined, NOW],
    ['a start ahead by the tolerance exactly', NOW + SKEW, undefined],
    ['an end behind by the tolerance exactly', undefined, NOW - SKEW],
    ['a start 2 seconds ahead', NOW + 2_000, undefined],
  ])('finds nothing for %s', (_label, from, until) => {
    expect(windowBreach(from, until, NOW, SKEW)).toBeUndefined();
  });

  it('finds an end behind by more than the tolerance expired', () => {
    expect(windowBreach(undefined, NOW - SKEW - 1, NOW, SKEW)).toBe('expired');
  });

  it('finds a start ahead by more than the tolerance not yet valid', () => {
    expect(windowBreach(NOW + SKEW + 1, undefined, NOW, SKEW)).toBe('not_yet_valid');
  });

  it('holds both bounds exactly with no tolerance', () => {
    expect(windowBreach(NOW + 1, undefined, NOW, 0)).toBe('not_yet_valid');
    expect(windowBreach(undefined, NOW - 1, NOW, 0)).toBe('expired');
    expect(windowBreach(NOW, NOW, NOW, 0)).toBeUndefined();
  });

  it('finds a window that ended before it started expired', () => {
    expect(windowBreach(NOW + 10 * SKEW, NOW - 10 * SKEW, NOW, SKEW)).toBe('expired');
  });
});

describe('clockSkewOption', () => {
  it('is the proof verifier default, 120 seconds, when the option is left out', () => {
    expect(clockSkewOption(undefined, 'maxClockSkewMs')).toBe(DEFAULT_MAX_CLOCK_SKEW_MS);
    expect(DEFAULT_MAX_CLOCK_SKEW_MS).toBe(DEFAULT_CLOCK_SKEW_SECONDS * 1000);
  });

  it('takes at most the longest skew the proof verifier takes, 600 seconds', () => {
    expect(LONGEST_CLOCK_SKEW_MS).toBe(MAX_CLOCK_SKEW_SECONDS * 1000);
  });

  it.each([0, 1, 2_500.5, 120_000, LONGEST_CLOCK_SKEW_MS])('takes %s', (value) => {
    expect(clockSkewOption(value, 'maxClockSkewMs')).toBe(value);
  });

  it.each<[string, unknown, string]>([
    ['a negative number', -1, '-1'],
    ['more than 600 seconds', LONGEST_CLOCK_SKEW_MS + 1, '600001'],
    ['NaN, which would hold no bound at all', Number.NaN, 'NaN'],
    ['Infinity', Number.POSITIVE_INFINITY, 'Infinity'],
    ['a numeric string', '120000', 'a value "120000"'],
    ['null', null, 'a value of type null'],
  ])('throws a TypeError naming the option for %s', (_label, value, got) => {
    expect(() => clockSkewOption(value, 'RevocationCheckerDeps.maxClockSkewMs')).toThrow(TypeError);
    expect(() => clockSkewOption(value, 'RevocationCheckerDeps.maxClockSkewMs')).toThrow(
      new RegExp(`^\\[kya-os\\] RevocationCheckerDeps\\.maxClockSkewMs must be a number of milliseconds from 0 to 600000 \\(got ${got}`),
    );
  });
});
