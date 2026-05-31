import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SystemClockProvider } from '../../providers/system-clock.js';

describe('SystemClockProvider', () => {
  let clock: SystemClockProvider;

  beforeEach(() => {
    clock = new SystemClockProvider();
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('now', () => {
    it('returns the current wall-clock time in ms', () => {
      expect(clock.now()).toBe(Date.parse('2026-01-01T00:00:00.000Z'));
    });
  });

  describe('isWithinSkew', () => {
    // The verifier calls isWithinSkew(proof.meta.ts * 1000, skew) — the arg is MS.
    it('returns true inside the skew window', () => {
      expect(clock.isWithinSkew(clock.now() - 4000, 5)).toBe(true);
      expect(clock.isWithinSkew(clock.now() + 4000, 5)).toBe(true);
    });
    it('is inclusive at exactly the boundary', () => {
      expect(clock.isWithinSkew(clock.now() - 5000, 5)).toBe(true);
    });
    it('returns false outside the skew window (past and future)', () => {
      expect(clock.isWithinSkew(clock.now() - 6000, 5)).toBe(false);
      expect(clock.isWithinSkew(clock.now() + 6000, 5)).toBe(false);
    });
  });

  describe('hasExpired', () => {
    it('reports expiry relative to now (ms epoch)', () => {
      expect(clock.hasExpired(clock.now() - 1)).toBe(true);
      expect(clock.hasExpired(clock.now() + 1000)).toBe(false);
    });
    it('is not expired exactly at now', () => {
      expect(clock.hasExpired(clock.now())).toBe(false);
    });
  });

  describe('calculateExpiry', () => {
    it('adds ttlSeconds (converted to ms) to now', () => {
      expect(clock.calculateExpiry(60)).toBe(clock.now() + 60_000);
    });
  });

  describe('format', () => {
    it('renders ISO-8601', () => {
      expect(clock.format(clock.now())).toBe('2026-01-01T00:00:00.000Z');
    });
  });
});
