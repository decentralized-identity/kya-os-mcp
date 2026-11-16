/**
 * Redirects followed by hand, each target checked by the caller's own rule for the first URL. A
 * runtime that follows redirects itself would carry a request from a host the rule admitted to one
 * it refuses, such as a cloud metadata address. Every hop shares the caller's `signal`, so one
 * deadline covers them all, and a hop to an origin other than the first carries only the
 * CORS-safelisted request headers and the request's cache directives (`./cors-safelisted-headers`).
 *
 * Each request asks the provider for `redirect: 'manual'`. A provider that drops that option lets
 * its runtime follow a redirect itself, making the request before the response comes back; the
 * response then says so, by `redirected` or by a `url` other than the one asked for, and is refused
 * unread. Only a provider that passes the option on keeps every request to hosts the rule admits.
 */

import { cancelQuietly } from './bounded-read.js';
import { crossOriginRequestHeaders } from './cors-safelisted-headers.js';
import { followRedirects, type RedirectRefusals } from './redirect-follower.js';

/** Fetch one URL as given, without following a redirect. */
export type SingleFetch = (url: string, init: RequestInit) => Promise<Response>;

/**
 * How the caller's rule refuses a URL, as the text that follows `Redirect to `: the URL's name, the
 * word `refused`, and anything the rule says after it; or `undefined` when it admits the URL.
 */
export type TargetRefusal = (url: string) => string | undefined;

const REFUSALS: RedirectRefusals = {
  limitExceeded: maxRedirects => new Error(`Redirect limit of ${maxRedirects} exceeded`),
  missingLocation: () => new Error('Redirect without a Location header'),
  invalidLocation: () => new Error('Redirect to an invalid URL'),
  httpsToHttp: () => new Error('Redirect from https to http refused'),
};

/**
 * GET `url`, following redirects by the one rule and up to its limit (`./redirect-follower`), and
 * refuse any target `refusal` names, any step down from https to http, and any response the
 * provider reached by a redirect.
 */
export function fetchWithCheckedRedirects(
  fetch: SingleFetch,
  url: string,
  init: RequestInit,
  refusal: TargetRefusal,
): Promise<Response> {
  return followRedirects<Response>(url, {
    async request(hop) {
      const sent = hop.crossOrigin ? { ...init, headers: crossOriginRequestHeaders(init.headers) } : init;
      const response = await fetch(hop.url, { ...sent, redirect: 'manual' });
      if (followedByProvider(response, hop.url)) {
        cancelQuietly(() => response.body?.cancel());
        throw new Error('Redirect followed by the fetch provider refused');
      }
      return response;
    },
    vetTarget({ target }) {
      const refused = refusal(target.href);
      if (refused !== undefined) throw new Error(`Redirect to ${refused}`);
    },
    discard: redirect => cancelQuietly(() => redirect.body?.cancel()),
    // An empty Location is the relative reference to the URL that sent it, which is asked again
    // until the limit ends the read.
    emptyLocationIsMissing: false,
    refusals: REFUSALS,
  });
}

/**
 * Whether `response` came from a redirect the provider followed: it says it was redirected, or it
 * names a URL other than `requested`, compared as the URL parser writes both, without a fragment.
 * A response that names no URL, as a `Response` built in code does not, is not suspected.
 */
function followedByProvider(response: Response, requested: string): boolean {
  if (response.redirected === true) return true;
  const named: unknown = response.url;
  return typeof named === 'string' && named !== '' && withoutFragment(named) !== withoutFragment(requested);
}

function withoutFragment(url: string): string | undefined {
  try {
    const parsed = new URL(url);
    parsed.hash = '';
    return parsed.href;
  } catch {
    return undefined;
  }
}
