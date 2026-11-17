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
 *
 * A request other than GET or HEAD, such as a POST to a registrar, follows only a 307 or 308, the
 * redirects that keep its method and body, and only to its own origin, so its body and headers
 * reach no host but the one it was sent to. A 301, 302 or 303 is refused: to follow one by the
 * standard turns the request into a GET without its body, which the server cannot act on, and to
 * send the request again as it was may repeat what it does.
 */

import { logger } from '../logging/index.js';
import { cancelQuietly } from './bounded-read.js';
import { crossOriginRequestHeaders } from './cors-safelisted-headers.js';
import { ReadFailureError } from './read-failure.js';
import { followRedirects, REDIRECT_STATUSES, type RedirectHop, type RedirectRefusals } from './redirect-follower.js';

/** Fetch one URL as given, without following a redirect, told which request of the read it is. */
export type SingleFetch = (url: string, init: RequestInit, hop: RedirectHop) => Promise<Response>;

/**
 * How the caller's rule refuses a URL, as the text that follows `Redirect to `: how it names the
 * URL, the word `refused`, and anything the rule says after it; or `undefined` when it admits the
 * URL.
 */
export type TargetRefusal = (url: string) => string | undefined;

/**
 * How a redirect is refused. A redirect the server got wrong leaves the resource `unavailable`; one
 * the scheme rule refuses, a step down from https, is `host_refused`, as is a target the caller's
 * rule refuses and a redirect the provider followed itself.
 */
const REFUSALS: RedirectRefusals = {
  limitExceeded: maxRedirects => new ReadFailureError('unavailable', `Redirect limit of ${maxRedirects} exceeded`),
  missingLocation: () => new ReadFailureError('unavailable', 'Redirect without a Location header'),
  invalidLocation: () => new ReadFailureError('unavailable', 'Redirect to an invalid URL'),
  httpsToHttp: () => new ReadFailureError('host_refused', 'Redirect from https to http refused'),
};

/** The redirects that keep a request's method and body (RFC 9110 §15.4.8 and §15.4.9). */
const METHOD_KEEPING_REDIRECTS: ReadonlySet<number> = new Set([307, 308]);

/**
 * Request `url`, following redirects by the one rule and up to its limit (`./redirect-follower`),
 * and refuse any target `refusal` names, any step down from https to http, and any response the
 * provider reached by a redirect. A request other than GET or HEAD is refused a 301, 302 or 303,
 * and a redirect to another origin.
 */
export function fetchWithCheckedRedirects(
  fetch: SingleFetch,
  url: string,
  init: RequestInit,
  refusal: TargetRefusal,
): Promise<Response> {
  const method = (init.method ?? 'GET').toUpperCase();
  const keptToOrigin = method !== 'GET' && method !== 'HEAD';
  return followRedirects<Response>(url, {
    async request(hop) {
      const sent = hop.crossOrigin ? { ...init, headers: crossOriginRequestHeaders(init.headers) } : init;
      const response = await fetch(hop.url, { ...sent, redirect: 'manual' }, hop);
      if (followedByProvider(response, hop.url)) {
        cancelQuietly(() => response.body?.cancel());
        throw new ReadFailureError('host_refused', 'Redirect followed by the fetch provider refused');
      }
      if (keptToOrigin && REDIRECT_STATUSES.has(response.status) && !METHOD_KEEPING_REDIRECTS.has(response.status)) {
        cancelQuietly(() => response.body?.cancel());
        throw new ReadFailureError('unavailable', `Redirect of a ${method} by HTTP ${response.status} refused: only a 307 or 308 keeps its method and body`);
      }
      return response;
    },
    vetTarget({ target, crossOrigin }) {
      if (keptToOrigin && crossOrigin) {
        logger.warn(`[kya-os] Redirect of a ${method} to ${target.origin} refused: another origin`);
        throw new ReadFailureError('host_refused', `Redirect of a ${method} to another origin refused`);
      }
      const refused = refusal(target.href);
      if (refused !== undefined) throw new ReadFailureError('host_refused', `Redirect to ${refused}`);
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
