/**
 * The directory a bundling suite works in exists only while that suite runs. A suite that is
 * skipped, as the bundling suites are when `dist/` is not built, still has its body read for its
 * tests, so a directory made there was left behind on every run.
 */
import { existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { PACKAGE, useConsumerDir } from './bundling.js';

const PREFIX = `kya-os-bundle-probe-${process.pid}-`;

/** The consumer directories of this file that exist now. */
const standing = (): string[] => readdirSync(tmpdir()).filter((name) => name.startsWith(PREFIX));

describe('useConsumerDir', () => {
  let ofSkippedSuite: (() => string) | undefined;

  describe.skip('in a suite that is skipped', () => {
    ofSkippedSuite = useConsumerDir(PREFIX);
    it('is never asked for', () => undefined);
  });

  describe('in a suite that runs', () => {
    const consumerDir = useConsumerDir(PREFIX);

    it('is one directory, which resolves the package through node_modules', () => {
      expect(standing()).toHaveLength(1);
      expect(existsSync(join(consumerDir(), 'node_modules', PACKAGE.name, 'package.json'))).toBe(true);
    });
  });

  it('is gone once its suite is over, and was never made for the suite that was skipped', () => {
    expect(standing()).toEqual([]);
    expect(() => ofSkippedSuite?.()).toThrow('a consumer directory exists only while its suite runs');
  });
});
