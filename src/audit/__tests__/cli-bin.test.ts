/**
 * The published `kya-audit` bin must run when invoked the way npm installs it.
 *
 * On macOS and Linux npm links a package bin into `node_modules/.bin` as a
 * symlink, so Node sees the link path in `argv[1]` rather than
 * `dist/audit/cli.js`. An entry check that matched on the file name never fired
 * there: the installed command printed nothing and exited 0 for every input,
 * including a bundle it never read. This test runs the built bin (`dist/`)
 * through such a link. npm installs `.cmd` shims instead of symlinks on Windows,
 * so the test skips there.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

const PACKAGE_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const PACKAGE = JSON.parse(readFileSync(join(PACKAGE_ROOT, 'package.json'), 'utf8')) as {
  bin: { 'kya-audit': string };
};
const BIN = resolve(PACKAGE_ROOT, PACKAGE.bin['kya-audit']);
const BUILT = existsSync(BIN);

if (!BUILT && process.env.CI) {
  throw new Error('cli-bin: dist/ is missing; CI must run `pnpm build` before `pnpm test`');
}

describe.skipIf(!BUILT || process.platform === 'win32')('kya-audit bin as npm links it', () => {
  const binDir = mkdtempSync(join(tmpdir(), 'kya-audit-bin-'));
  const link = join(binDir, 'kya-audit');
  symlinkSync(BIN, link);
  afterAll(() => rmSync(binDir, { recursive: true, force: true }));

  const run = (...args: string[]) =>
    spawnSync(process.execPath, [link, ...args], { encoding: 'utf8' });

  it('prints usage for --help', () => {
    const result = run('--help');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('kya-audit verify');
  });

  it('refuses to verify without trust inputs supplied outside the bundle', () => {
    const result = run('verify', 'bundle.json');
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/cannot bootstrap trust/i);
  });
});
