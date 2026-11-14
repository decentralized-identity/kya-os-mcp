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

/** Redirects followed before the request is refused. */
export const MAX_REDIRECTS = 3;

/** The HTTP statuses that redirect a GET. */
export const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

/** Fetch one URL as given, without following a redirect. */
export type SingleFetch = (url: string, init: RequestInit) => Promise<Response>;

/** How the caller's rule names a URL it refuses, or `undefined` when it admits the URL. */
export type TargetRefusal = (url: string) => string | undefined;

/**
 * GET `url`, following at most {@link MAX_REDIRECTS} redirects, and refuse any target `refusal`
 * names, any step down from https to http, and any response the provider reached by a redirect.
 */
export async function fetchWithCheckedRedirects(
  fetch: SingleFetch,
  url: string,
  init: RequestInit,
  refusal: TargetRefusal,
): Promise<Response> {
  const origin = new URL(url).origin;
  let current = url;
  for (let redirects = 0; ; redirects++) {
    const hop = new URL(current).origin === origin ? init : { ...init, headers: crossOriginRequestHeaders(init.headers) };
    const response = await fetch(current, { ...hop, redirect: 'manual' });
    if (followedByProvider(response, current)) {
      cancelQuietly(() => response.body?.cancel());
      throw new Error('Redirect followed by the fetch provider refused');
    }
    if (!REDIRECT_STATUSES.has(response.status)) return response;
    cancelQuietly(() => response.body?.cancel());
    if (redirects === MAX_REDIRECTS) throw new Error(`Redirect limit of ${MAX_REDIRECTS} exceeded`);
    current = redirectTarget(current, response.headers.get('location'), refusal);
  }
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

function redirectTarget(from: string, location: string | null, refusal: TargetRefusal): string {
  if (location === null) throw new Error('Redirect without a Location header');
  let target: URL;
  try {
    target = new URL(location, from);
  } catch {
    throw new Error('Redirect to an invalid URL');
  }
  if (target.protocol === 'http:' && new URL(from).protocol === 'https:') {
    throw new Error('Redirect from https to http refused');
  }
  const refused = refusal(target.href);
  if (refused !== undefined) throw new Error(`Redirect to ${refused} refused`);
  return target.href;
}
