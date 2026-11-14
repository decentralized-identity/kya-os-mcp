/**
 * The code points a name must not hold because a reader does not see them: one frozen table,
 * `conformance/unseen-code-points.json`, which the Python reference reads as it is and the package
 * carries as code. These tests hold the code to the table number for number, hold the table to
 * Unicode's own properties on a runtime whose Unicode version the table states, and hold the test
 * of a string to the table at the edges of every run.
 */

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { hasUnseenCodePoint, UNSEEN_CODE_POINTS } from '../unseen-code-points.js';

interface Table {
  unicode: string[];
  ranges: [string, string][];
}
const table = JSON.parse(readFileSync(new URL('../../../conformance/unseen-code-points.json', import.meta.url), 'utf8')) as Table;
const ranges = table.ranges.map(([first, last]) => [Number.parseInt(first, 16), Number.parseInt(last, 16)] as const);

describe('the table of code points a reader does not see', () => {
  it('is the same in the package as in the file the Python reference reads', () => {
    expect(UNSEEN_CODE_POINTS).toEqual(ranges);
  });

  it('is written as runs in ascending order that neither touch nor overlap, in upper-case hex of four to six digits', () => {
    for (const [first, last] of table.ranges) {
      expect(first).toMatch(/^[0-9A-F]{4,6}$/);
      expect(last).toMatch(/^[0-9A-F]{4,6}$/);
    }
    ranges.forEach(([first, last], index) => {
      expect(first).toBeLessThanOrEqual(last);
      if (index > 0) expect(first).toBeGreaterThan(ranges[index - 1]![1] + 1);
    });
    expect(ranges.reduce((count, [first, last]) => count + last - first + 1, 0)).toBe(4273);
  });

  it.runIf(table.unicode.includes(process.versions.unicode ?? ''))(
    'is every Cc, Cf, Zl, Zp and Default_Ignorable_Code_Point code point of the Unicode versions it names, and no other',
    () => {
      const property = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/u;
      const differing: string[] = [];
      for (let code = 0; code <= 0x10ffff; code += 1) {
        if (code >= 0xd800 && code <= 0xdfff) continue;
        const listed = ranges.some(([first, last]) => code >= first && code <= last);
        if (listed !== property.test(String.fromCodePoint(code))) differing.push(code.toString(16));
      }
      expect(differing).toEqual([]);
    },
  );
});

describe('hasUnseenCodePoint', () => {
  it('finds the first and last code point of every run, and neither neighbour of a run', () => {
    for (const [first, last] of ranges) {
      for (const code of [first, last]) expect(hasUnseenCodePoint(`a${String.fromCodePoint(code)}b`), code.toString(16)).toBe(true);
      // U+D7FF and U+E000 border the surrogates, which are no code points of a well-formed string.
      for (const code of [first - 1, last + 1]) {
        if (code < 0 || (code >= 0xd800 && code <= 0xdfff)) continue;
        expect(hasUnseenCodePoint(`a${String.fromCodePoint(code)}b`), code.toString(16)).toBe(false);
      }
    }
  });

  it('finds none in text a reader sees whole, in any script', () => {
    for (const text of ['', 'did:web:acme.example', 'exämple', 'é', '例え', '\u{1f600}', '  　']) {
      expect(hasUnseenCodePoint(text), JSON.stringify(text)).toBe(false);
    }
  });
});
