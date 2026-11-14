/**
 * The segments of a compact JWS read as JSON: one reading, with one choice
 * in it. `strict` is how SPEC.md §7.8 reads a VC-JWT's payload for the id it
 * shows; `lenient` is how `parseVCJWT` reads a VC-JWT for verification, by
 * the runtime's decoder. Both count how deep a text nests before a parser
 * reads it.
 */
import { describe, expect, it, vi } from 'vitest';
import { jwsSegmentsJson } from '../jws-segment.js';

const READINGS = ['strict', 'lenient'] as const;
const segment = (text: string | Uint8Array): string => Buffer.from(text).toString('base64url');
const nested = (levels: number): string => '['.repeat(levels) + ']'.repeat(levels);

describe('jwsSegmentsJson', () => {
  it.each(READINGS)('reads base64url segments of JSON, in order, %s', (reading) => {
    expect(jwsSegmentsJson([segment('{"vc":{"id":"urn:uuid:1"}}'), 'e30='], reading)).toEqual([
      { vc: { id: 'urn:uuid:1' } },
      {},
    ]);
  });

  it.each(READINGS)('reads a text nested 64 levels deep, and not one nested 65, %s', (reading) => {
    expect(JSON.stringify(jwsSegmentsJson([segment(nested(64))], reading)[0])).toBe(nested(64));
    expect(() => jwsSegmentsJson([segment(nested(65))], reading))
      .toThrow(new TypeError("A JWS segment's JSON nests at most 64 levels deep"));
  });

  it.each(READINGS)('hands no parser any segment when one nests deeper than that, %s', (reading) => {
    const parse = vi.spyOn(JSON, 'parse');
    try {
      expect(() => jwsSegmentsJson(['e30', segment(nested(200_000))], reading)).toThrow('nests at most');
      expect(parse).not.toHaveBeenCalled();
    } finally {
      parse.mockRestore();
    }
  });

  it.each(READINGS)('refuses a segment that is not JSON, %s', (reading) => {
    expect(() => jwsSegmentsJson([segment('{"vc":')], reading)).toThrow(SyntaxError);
  });

  it('reads a segment strictly as RFC 7515 writes one, where the lenient reading takes more', () => {
    // The base64 alphabet, padding short of the last group, and a byte that
    // is not UTF-8 (read as U+FFFD by the lenient reading).
    const written: Array<[string, unknown]> = [
      ['eyJhIjoifn5+In0=', { a: '~~~' }],
      ['eyJhIjoxfQ=', { a: 1 }],
      ['eyJhIjoi_yJ9', { a: '�' }],
    ];
    for (const [encoded, read] of written) {
      expect(jwsSegmentsJson([encoded], 'lenient')).toEqual([read]);
      expect(() => jwsSegmentsJson([encoded], 'strict'))
        .toThrow(new TypeError('A JWS segment is base64url of UTF-8 text (RFC 7515 §2)'));
    }
  });

  it('keeps a byte order mark when it reads strictly, so the text is not JSON', () => {
    const marked = segment(new Uint8Array([0xef, 0xbb, 0xbf, ...Buffer.from('{}')]));
    expect(() => jwsSegmentsJson([marked], 'strict')).toThrow(SyntaxError);
  });
});
