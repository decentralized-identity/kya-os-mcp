/**
 * The segments of a compact JWS read as JSON: the header and the payload of
 * a VC-JWT. This is the one reading of either, with one choice in it.
 *
 * `parseVCJWT` reads a VC-JWT for verification by the runtime's decoder
 * (`lenient`, `../utils/base64.ts`): SPEC.md states no reading of a header
 * or a payload for that, and the verdict is the JWS library's. The id a VC-JWT
 * shows is read as SPEC.md §7.8 has it (`strict`, in `./delegation-ref.ts`),
 * so that every implementation derives one reference from one JWT. Both
 * count how deep a text nests before a parser reads it.
 *
 * Pure: no transport, no framework, no key material.
 */

import { base64urlDecodeToString } from '../utils/base64.js';
import { jwsSegmentText } from '../utils/base64-reading.js';
import { jsonTextNestsDeeperThan } from '../utils/plain-data.js';
import { MAX_CREDENTIAL_NESTING_DEPTH } from './signed-form.js';

/**
 * How a segment's characters are read to the text of its JSON.
 *
 * - `strict`, as SPEC §7.8 reads a payload: base64url as RFC 7515 §2 has it,
 *   and UTF-8 that is well formed, with a byte order mark kept in the text,
 *   where JSON refuses it ({@link jwsSegmentText}).
 * - `lenient`, as the runtime's decoder reads a segment
 *   (`base64urlDecodeToString`): the base64 and the base64url alphabets
 *   alike, padding that completes the last group or falls short of it, and
 *   UTF-8 as the runtime decodes it, a byte that is not UTF-8 read as U+FFFD.
 */
export type JwsSegmentReading = 'strict' | 'lenient';

function textOf(segment: string, reading: JwsSegmentReading): string {
  if (reading === 'lenient') return base64urlDecodeToString(segment);
  const text = jwsSegmentText(segment);
  if (text === undefined) throw new TypeError('A JWS segment is base64url of UTF-8 text (RFC 7515 §2)');
  return text;
}

/**
 * The JSON values `segments` of a compact JWS carry, in order, each read as
 * `reading` says.
 *
 * Every text is counted before any is parsed: when one nests its arrays and
 * objects more than {@link MAX_CREDENTIAL_NESTING_DEPTH} levels deep, no
 * parser is handed it or any other of them. So whether a JWS is read never
 * turns on how deep a text the parser underneath can read.
 *
 * @throws when a segment is not JSON as `reading` reads it, or one nests
 *   deeper than that.
 */
export function jwsSegmentsJson(segments: readonly string[], reading: JwsSegmentReading): unknown[] {
  const texts = segments.map((segment) => textOf(segment, reading));
  if (texts.some((text) => jsonTextNestsDeeperThan(text, MAX_CREDENTIAL_NESTING_DEPTH))) {
    throw new TypeError(`A JWS segment's JSON nests at most ${MAX_CREDENTIAL_NESTING_DEPTH} levels deep`);
  }
  return texts.map((text) => JSON.parse(text) as unknown);
}
