/**
 * `conformance/verify.py` imports the modules beside it, so it must find them however Python is
 * started: in isolated mode (`-I`) Python leaves the script's directory off the import path, and
 * the script may be run from any directory. A run also writes no bytecode cache into
 * `conformance/`, which `.gitignore` does not cover. Treat implicit text encodings as errors on
 * every platform: the vectors are UTF-8, even when Python's locale defaults to a Windows code page.
 */

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { requirePython } from './python.js';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const script = fileURLToPath(new URL('../verify.py', import.meta.url));
const bytecodeCache = fileURLToPath(new URL('../__pycache__', import.meta.url));

describe('the cross-language verifier', () => {
  it.for([
    ['the repository root', repositoryRoot, 'conformance/verify.py'],
    ['another directory', tmpdir(), script],
  ] as const)('passes in isolated mode from %s and leaves no bytecode cache in conformance/', { timeout: 60_000 }, ([, cwd, path], context) => {
    const [python, ...args] = requirePython(context);
    const run = spawnSync(python, [...args, '-I', '-X', 'warn_default_encoding', '-W', 'error', path], { cwd, encoding: 'utf8' });
    expect(run.stderr).toBe('');
    expect(run.status).toBe(0);
    expect(run.stdout).toContain('RESULT: PASS');
    expect(existsSync(bytecodeCache)).toBe(false);
  });
});
