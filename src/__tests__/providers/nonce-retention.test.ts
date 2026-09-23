import { describe, expect, it } from 'vitest';
import { nonceRetentionSeconds } from '../../providers/nonce-retention.js';

describe('nonce retention floor', () => {
  it('covers the entire inclusive final second, rounding up fractional cache time', () => {
    expect(nonceRetentionSeconds(1, 120, 0)).toBe(121);
    expect(nonceRetentionSeconds(1, 120, 500)).toBe(121);
    expect(nonceRetentionSeconds(1, 120, 120_999)).toBe(1);
  });

  it('preserves longer configured retention', () => {
    expect(nonceRetentionSeconds(500, 120, 0)).toBe(500);
  });

  it.each([
    [0, 120, 0], [-1, 120, 0], [NaN, 120, 0], [Infinity, 120, 0],
    [1, Infinity, 0], [1, NaN, 0], [1, 120, NaN],
  ])('rejects an unbounded or invalid configuration (%s, %s, %s)', (ttl, end, now) => {
    expect(() => nonceRetentionSeconds(ttl!, end!, now!)).toThrow('bounded acceptance window');
  });
});
