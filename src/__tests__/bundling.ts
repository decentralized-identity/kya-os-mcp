/**
 * What the bundling tests share: the package as it is published (`dist/`, with its real
 * `package.json`), its code entries, and a consumer directory that resolves the package through
 * `node_modules`, so a bundler reads the exports map and `sideEffects` as an adopter's does.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll } from 'vitest';

export const PACKAGE_ROOT = fileURLToPath(new URL('../..', import.meta.url));

export const PACKAGE = JSON.parse(readFileSync(join(PACKAGE_ROOT, 'package.json'), 'utf8')) as {
  name: string;
  exports: Record<string, string | { default: string }>;
};

/** Whether `dist/` is built. A test that bundles the package runs only then, and CI must build it first. */
export const BUILT = existsSync(join(PACKAGE_ROOT, 'dist/index.js'));

if (!BUILT && process.env.CI) {
  throw new Error('bundling tests: dist/ is missing; CI must run `pnpm build` before `pnpm test`');
}

/** Every code entry in `exports` (wildcards and JSON excluded): its specifier and built file. */
export const ENTRIES = Object.entries(PACKAGE.exports)
  .filter(([key]) => !key.includes('*') && !key.endsWith('.json'))
  .map(([key, target]) => ({
    specifier: key === '.' ? PACKAGE.name : `${PACKAGE.name}/${key.slice(2)}`,
    file: resolve(PACKAGE_ROOT, typeof target === 'string' ? target : target.default),
  }));

/**
 * The directory a suite's consumer bundles from, with the package linked into its `node_modules`.
 * Call this in the suite's body, and the function it returns inside a test. The directory is made
 * before the suite's first test and removed after its last, so a suite that is skipped, whose body
 * is still read for its tests, makes none. A junction needs no privileges on Windows and is a plain
 * symlink elsewhere.
 */
export function useConsumerDir(prefix: string): () => string {
  let dir: string | undefined;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), prefix));
    mkdirSync(join(dir, 'node_modules', '@kya-os'), { recursive: true });
    symlinkSync(PACKAGE_ROOT, join(dir, 'node_modules', PACKAGE.name), 'junction');
  });
  afterAll(() => {
    if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
    dir = undefined;
  });
  return () => {
    if (dir === undefined) throw new Error('a consumer directory exists only while its suite runs');
    return dir;
  };
}
