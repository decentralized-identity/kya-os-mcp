/**
 * Test helper: `statusListIssuers` bindings that SPEC.md §6.6 says a verifier should refuse as a
 * configuration error, each with the words the harness refuses it in, and the look-alikes it reads
 * as an exact URL or an origin and leaves alone. The library, the TypeScript loader and
 * `conformance/status_list.py` are each held to both lists, so all three refuse the same bindings.
 */

/** The harness's words for an origin followed by `/`. */
export const ORIGIN_WITH_SLASH = 'statusListIssuers binds an origin followed by "/"';
/** The harness's words for an origin whose host has an upper-case letter. */
export const ORIGIN_NOT_LOWER_CASE = 'statusListIssuers binds an origin whose host is not in lower case';
/** The harness's words for any other binding that ends in `/`. */
export const ENDS_IN_SLASH = 'statusListIssuers binds a URL that ends in "/"';

/** Each binding §6.6 says a verifier should refuse, and the words the harness refuses it in. */
export const MISTAKEN_BINDINGS: readonly (readonly [binding: string, words: string])[] = [
  ['https://y.example/', ORIGIN_WITH_SLASH],
  ['https://y.example:8443/', ORIGIN_WITH_SLASH],
  ['https://Y.example/', ORIGIN_WITH_SLASH],
  ['https://Y.example', ORIGIN_NOT_LOWER_CASE],
  ['https://y.EXAMPLE:8443', ORIGIN_NOT_LOWER_CASE],
  ['https://y.example/lists/', ENDS_IN_SLASH],
  ['https://y.example/lists?after=/', ENDS_IN_SLASH],
  ['https://Y.example/lists/', ENDS_IN_SLASH],
  ['https://y.example:/', ENDS_IN_SLASH],
  ['http://y.example/', ENDS_IN_SLASH],
  ['https://[::1]/', ENDS_IN_SLASH],
  ['https://', ENDS_IN_SLASH],
];

/**
 * Bindings that look like those above but are an origin in §6.6's form, or an exact URL that ends
 * in no `/`, whatever the case of its host and whether or not a URL parser takes it. A line feed
 * after an origin makes it no origin, as a pattern that lets `$` match before a final line feed
 * would miss.
 */
export const LOOK_ALIKE_BINDINGS: readonly string[] = [
  'https://y.example',
  'https://y.example:8443',
  'https://Y.example/1',
  'https://y.EXAMPLE/lists/1',
  'https://user@Y.example/1',
  'https://[::FFFF:7f00:1]/1',
  'http://Y.example',
  'https://y.example/lists',
  'https://y.example?list=1',
  'https://y.example#list',
  'https://y.example//1',
  'https://y example/1',
  'https://y.example:99999',
  'http://[::1/1',
  'https://Bücher.example',
  'https://Y.example\n',
  'https://y.example/\n',
];
