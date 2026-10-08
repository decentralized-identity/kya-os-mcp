import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { afterAll, describe, expect, it } from 'vitest';
import { isMainModule } from '../src/lib/main-module.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'commerce entry point '));
const otherDirectory = path.join(directory, 'unrelated cwd');
fs.mkdirSync(otherDirectory);
const entrypoint = path.join(directory, 'example command.mjs');
const helperUrl = new URL('../src/lib/main-module.ts', import.meta.url).href;
fs.writeFileSync(entrypoint, `
  import { isMainModule } from ${JSON.stringify(helperUrl)};
  export const enteredMain = isMainModule(import.meta.url);
  if (enteredMain) console.log('direct entrypoint');
`);
const importer = path.join(otherDirectory, 'example command.mjs');
fs.writeFileSync(importer, `
  import { enteredMain } from ${JSON.stringify(pathToFileURL(entrypoint).href)};
  console.log(JSON.stringify({ enteredMain }));
`);
afterAll(() => fs.rmSync(directory, { recursive: true, force: true }));

describe('portable standalone command entrypoints', () => {
  it('enters a directly invoked command from an unrelated cwd, including paths with spaces', async () => {
    const { stdout, stderr } = await promisify(execFile)(process.execPath, [
      path.join(root, 'node_modules/tsx/dist/cli.mjs'), entrypoint,
    ], { cwd: otherDirectory });
    expect(stdout.trim()).toBe('direct entrypoint');
    expect(stderr).toBe('');
  });

  it('does not start an imported command, even when its importer has the same filename', async () => {
    const { stdout, stderr } = await promisify(execFile)(process.execPath, [
      path.join(root, 'node_modules/tsx/dist/cli.mjs'), importer,
    ], { cwd: otherDirectory });
    expect(JSON.parse(stdout)).toEqual({ enteredMain: false });
    expect(stderr).toBe('');
  });

  it('enters a command invoked through a symlinked directory', async () => {
    const alias = path.join(directory, 'linked directory');
    fs.symlinkSync(directory, alias, 'junction');
    const { stdout, stderr } = await promisify(execFile)(process.execPath, [
      path.join(root, 'node_modules/tsx/dist/cli.mjs'), path.join(alias, path.basename(entrypoint)),
    ], { cwd: otherDirectory });
    expect(stdout.trim()).toBe('direct entrypoint');
    expect(stderr).toBe('');
  });

  it('compares native absolute paths with module URLs and rejects absent or different entrypoints', () => {
    const url = pathToFileURL(entrypoint).href;
    expect(isMainModule(url, entrypoint)).toBe(true);
    expect(isMainModule(url, path.relative(process.cwd(), entrypoint))).toBe(true);
    expect(isMainModule(url, importer)).toBe(false);
    expect(isMainModule(url, '')).toBe(false);
  });
});
