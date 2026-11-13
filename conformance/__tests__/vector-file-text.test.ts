/**
 * The text of a vector file shows what it holds: a character that does not
 * print as itself (SPEC.md §7.8), a bidirectional override say, is written
 * as a `\u` escape, so a reader of the file, or of a diff of it, sees the
 * escape and not text in another order or no text at all.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { hasUnprintableCharacter } from '../../src/utils/plain-text.js';
import { VECTORS_DIR } from '../loader.js';
import { vectorFileText } from '../numbers-as-written.js';
import type { VectorFile } from '../types.js';

/** A vector file of one vector, whose id is `id`. */
const fileWithId = (id: string): VectorFile =>
  ({ version: '1.5.0', category: 'signed-proof', vectors: [{ id }] }) as unknown as VectorFile;

describe('the text of a vector file', () => {
  it.each([
    ['a right-to-left override', 'del-\u202egnp.exe', 'del-\\u202egnp.exe'],
    ['a zero-width space', 'del-\u200b1', 'del-\\u200b1'],
    ['a C1 control', 'del-\u00851', 'del-\\u00851'],
    ['a tag character outside the basic plane', 'del-\u{e0041}', 'del-\\udb40\\udc41'],
  ])('writes %s as an escape, and reads as what was generated', (_name, id, written) => {
    const text = vectorFileText(fileWithId(id), 'test.json', []);

    expect(text).toContain(`"id": "${written}"`);
    expect(JSON.parse(text)).toEqual(fileWithId(id));
  });

  it('writes a character that prints as itself as it is', () => {
    expect(vectorFileText(fileWithId('del-é→1'), 'test.json', [])).toContain('"id": "del-é→1"');
  });

  it.each(readdirSync(VECTORS_DIR).filter((name) => name.endsWith('.json')))(
    'holds no character that does not print as itself, committed: %s',
    (name) => {
      const lines = readFileSync(join(VECTORS_DIR, name), 'utf8').split('\n');
      expect(lines.filter((line) => hasUnprintableCharacter(line))).toEqual([]);
    },
  );
});
