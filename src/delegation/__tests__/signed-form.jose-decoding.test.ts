/**
 * The signed form of a credential (SPEC.md §7.8) reads a JWS segment the way
 * the library that verifies a VC-JWT's envelope reads it.
 */
import { base64url } from 'jose';
import { describe, it, expect } from 'vitest';
import { decodeJwsSegment } from '../signed-form.js';

describe('decodeJwsSegment', () => {
  // A VC-JWT's envelope is verified by jose, which decodes a segment with
  // Uint8Array.fromBase64 where the runtime has it and with atob where it
  // does not. A credential's signed form must be one for exactly the JWTs
  // that verify, so this reading is held to each of those, string for string.
  const native = Object.getOwnPropertyDescriptor(Uint8Array, 'fromBase64');
  const joseDecodingPaths: Array<[string, boolean]> = [
    ...(native === undefined ? [] : [['Uint8Array.fromBase64', false] as [string, boolean]]),
    ['atob', true],
  ];

  describe.each(joseDecodingPaths)('reads what jose reads through %s', (_path, withoutNative) => {
    // Each of these puts well over a hundred thousand strings through both
    // readers: about a second on a laptop, and more on a busy CI runner.
    const comparison = { timeout: 60_000 };

    /** Each reading of every string: the bytes as hex, or `refused`. */
    function readings(strings: Iterable<string>): { ours: string[]; theirs: string[] } {
      const hex = (decode: (encoded: string) => Uint8Array, encoded: string): string => {
        try {
          return Buffer.from(decode(encoded)).toString('hex');
        } catch {
          return 'refused';
        }
      };
      const ours: string[] = [];
      const theirs: string[] = [];
      if (withoutNative) delete (Uint8Array as { fromBase64?: unknown }).fromBase64;
      try {
        for (const encoded of strings) {
          ours.push(`${JSON.stringify(encoded)} ${hex(decodeJwsSegment, encoded)}`);
          theirs.push(`${JSON.stringify(encoded)} ${hex(base64url.decode, encoded)}`);
        }
      } finally {
        if (withoutNative && native) Object.defineProperty(Uint8Array, 'fromBase64', native);
      }
      return { ours, theirs };
    }

    it('for every string of up to five characters that matter', comparison, () => {
      // A character with spare bits clear and two with them set, padding, two
      // kinds of whitespace, and what a segment may not hold: the base64
      // alphabet, a vertical tab, and punctuation.
      const alphabet = ['A', '-', '_', '=', ' ', '\n', '+', '/', '\v', '!'];
      const strings = [''];
      for (let from = 0, length = 1; length <= 5; length += 1) {
        const upTo = strings.length;
        for (let index = from; index < upTo; index += 1) {
          for (const character of alphabet) strings.push(strings[index]! + character);
        }
        from = upTo;
      }
      expect(strings).toHaveLength(111_111);
      const { ours, theirs } = readings(strings);
      expect(ours.filter((reading) => !reading.endsWith('refused')).length).toBeGreaterThan(1000);
      expect(ours.filter((reading, index) => reading !== theirs[index])).toEqual([]);
    });

    it('for longer strings, as a signature is', comparison, () => {
      // A fixed sequence, so a failure can be reproduced.
      let state = 0x2545f491;
      const next = (below: number): number => {
        state ^= state << 13;
        state ^= state >>> 17;
        state ^= state << 5;
        return (state >>> 0) % below;
      };
      const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
      const others = ['=', '=', ' ', '\t', '\n', '\r', '\f', '\v', '+', '/', '.', 'é', '\u{1F512}'];
      const strings: string[] = [];
      for (let count = 0; count < 20_000; count += 1) {
        let encoded = '';
        const length = next(96);
        for (let index = 0; index < length; index += 1) {
          encoded += letters[next(letters.length)]!;
        }
        // Most of them altered in one or two places, where the readings could differ.
        for (let edits = next(3); edits > 0; edits -= 1) {
          const at = next(encoded.length + 1);
          encoded = encoded.slice(0, at) + others[next(others.length)]! + encoded.slice(at);
        }
        strings.push(encoded, `${encoded}=`, `${encoded}==`);
      }
      const { ours, theirs } = readings(strings);
      expect(ours.filter((reading) => !reading.endsWith('refused')).length).toBeGreaterThan(10_000);
      expect(ours.filter((reading, index) => reading !== theirs[index])).toEqual([]);
    });
  });
});
