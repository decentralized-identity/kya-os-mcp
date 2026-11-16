/**
 * An implementer of another language or library runs the suite by copying three files, `types.ts`,
 * `loader.ts` and `runner.ts`, beside the vectors, and writing an adapter of its own. So those
 * three stand alone: each imports only Node.js built-ins and the other two, never the package's
 * source. The loader's check of a status-list vector's configuration is therefore its own code, and
 * it refuses and admits what the library's `assertStatusListIssuers` does.
 */

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { assertStatusListConfiguration } from '../loader.js';
import { assertStatusListIssuers } from '../../src/utils/statuslist-acceptance.js';

const STANDALONE = ['types.ts', 'loader.ts', 'runner.ts'];
const ALLOWED = new Set(STANDALONE.map((file) => `./${file.replace(/\.ts$/, '.js')}`));

/** Every module specifier `file` imports or re-exports from. */
function specifiers(file: string): string[] {
  const source = readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');
  return [...source.matchAll(/^\s*(?:import|export)\b[^;]*?\bfrom\s*['"]([^'"]+)['"]/gms)].map((match) => match[1]!);
}

describe('the harness files an implementer copies', () => {
  it('import only Node.js built-ins and each other', () => {
    for (const file of STANDALONE) {
      const outside = specifiers(file).filter((specifier) => !specifier.startsWith('node:') && !ALLOWED.has(specifier));
      expect(outside, file).toEqual([]);
    }
  });

  it('refuse and admit the statusListIssuers the library refuses and admits', () => {
    const maps: unknown[] = [
      undefined, {}, { 'did:x': [] }, { 'did:x': ['https://y.example', 'https://y.example/1', 'http://y.example/1'] }, Object.create(null),
      { 'did:x': ['https://y.example/1', 'https://y.example/1'], 'did:z': ['https://Y.example'] },
      null, 'did:x', 7, [], ['did:x'], { 'did:x': 'https://y.example' }, { 'did:x': [7] }, { 'did:x': null }, new Map(), new Date(0),
      { 'did:x': ['did:y', 'did:z'] }, { 'did:x': ['y.example'] }, { 'did:x': [['https://y.example']] }, { 'did:x': ['ftp://y.example'] }, { 'did:x': [''] }, { '': ['https://y.example'] },
      { 'did:x': ['https://y.example'], 'did:z': ['https://y.example'] },
    ];
    const refuses = (check: () => void): boolean => {
      try {
        check();
        return false;
      } catch (error) {
        expect(error).toBeInstanceOf(TypeError);
        return true;
      }
    };
    for (const statusListIssuers of maps) {
      const label = JSON.stringify(statusListIssuers) ?? String(statusListIssuers);
      expect(refuses(() => assertStatusListConfiguration({ statusListIssuers })), label)
        .toBe(refuses(() => assertStatusListIssuers(statusListIssuers)));
    }
  });
});
