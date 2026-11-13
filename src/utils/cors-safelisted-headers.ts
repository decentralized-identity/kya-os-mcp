/**
 * The request headers a redirect followed by hand may carry to an origin other than the one first
 * asked: those the Fetch standard calls CORS-safelisted, which a browser sends to any origin, so
 * they say nothing a caller meant only for that first origin, and the request's cache directives,
 * `Cache-Control` and `Pragma`, which carry no credential, so a read that asks caches to revalidate
 * asks it at every origin. A credential or API key does not reach a host a counterparty redirected
 * the read to.
 *
 * Of the safelisted names, a GET without a body uses `Accept`, `Accept-Language` and
 * `Content-Language`; every other header is dropped.
 * See https://fetch.spec.whatwg.org/#cors-safelisted-request-header.
 */

/** The longest value the standard safelists. */
const MAX_SAFELISTED_VALUE_LENGTH = 128;

/** The printable bytes the standard calls CORS-unsafe in a request header's value. */
const UNSAFE_PRINTABLE = new Set('"():<>?@[\\]{}');

/** Whether `value` holds a CORS-unsafe byte: one of those, or a control byte other than tab. */
function hasCorsUnsafeByte(value: string): boolean {
  for (const char of value) {
    const code = char.charCodeAt(0);
    if ((code < 0x20 && code !== 0x09) || code === 0x7f || UNSAFE_PRINTABLE.has(char)) return true;
  }
  return false;
}

/** The only bytes a safelisted language tag list may hold. */
const LANGUAGE_VALUE = /^[0-9A-Za-z *,\-.;=]*$/;

/** Each safelisted name, as `Headers` writes it, with the test its value must pass. */
const SAFELISTED_VALUE: ReadonlyMap<string, (value: string) => boolean> = new Map([
  ['accept', (value: string) => !hasCorsUnsafeByte(value)],
  ['accept-language', (value: string) => LANGUAGE_VALUE.test(value)],
  ['content-language', (value: string) => LANGUAGE_VALUE.test(value)],
]);

/** `headers` with only the CORS-safelisted request headers kept. */
export function corsSafelistedHeaders(headers: RequestInit['headers']): Headers {
  const kept = new Headers();
  for (const [name, value] of new Headers(headers)) {
    const safelisted = SAFELISTED_VALUE.get(name);
    if (safelisted !== undefined && value.length <= MAX_SAFELISTED_VALUE_LENGTH && safelisted(value)) kept.append(name, value);
  }
  return kept;
}

/** The request's cache directives, kept whatever their values. */
const CACHE_DIRECTIVES: ReadonlySet<string> = new Set(['cache-control', 'pragma']);

/** `headers` as a hop to another origin carries them: the CORS-safelisted ones and the cache directives. */
export function crossOriginRequestHeaders(headers: RequestInit['headers']): Headers {
  const kept = corsSafelistedHeaders(headers);
  for (const [name, value] of new Headers(headers)) {
    if (CACHE_DIRECTIVES.has(name)) kept.append(name, value);
  }
  return kept;
}
