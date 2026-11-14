/**
 * The one rule for following HTTP redirects by hand: which statuses redirect, how many are followed,
 * how the next URL is read from `Location`, and the refusal of a step down from https to http.
 *
 * A caller supplies what differs between readers as a {@link RedirectPolicy}: how one request is
 * made, how a target is vetted, what a hop to another origin means (the policy is told of one, and
 * may send it fewer headers or refuse it), and the text of each refusal. The private-network rule's
 * policy is in `./checked-redirects`, SafeFetch's in `./safe-fetch`.
 */

/** Redirects followed before the request is refused, unless a policy sets its own limit. */
export const MAX_REDIRECTS = 3;

/** The HTTP statuses that redirect a GET. */
export const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

/** What the rule reads of a response: its status, and its `Location` header. */
export interface RedirectableResponse {
  readonly status: number;
  readonly headers: { get(name: string): string | null };
}

/** One request of a followed read. */
export interface RedirectHop {
  /** The URL to request, as the URL parser writes it after the first. */
  readonly url: string;
  /** Whether `url`'s origin is other than the origin of the URL first asked for. */
  readonly crossOrigin: boolean;
}

/** A redirect target, parsed, and the hop that led to it. */
export interface RedirectTarget {
  readonly target: URL;
  /** The URL whose response named `target`. */
  readonly from: URL;
  /** Whether `target`'s origin is other than the origin of the URL first asked for. */
  readonly crossOrigin: boolean;
}

/** The error each refusal of the rule throws, in the caller's own words. */
export interface RedirectRefusals {
  /** One more redirect than `maxRedirects` arrived. */
  limitExceeded(maxRedirects: number): Error;
  /** A response with redirect status `status` named no target. */
  missingLocation(status: number): Error;
  /** `location` does not parse as a URL, absolute or relative to the URL that named it. */
  invalidLocation(location: string): Error;
  /** A response to an https URL named the http URL `target`. */
  httpsToHttp(target: URL): Error;
}

/** What differs between the readers that follow redirects by this rule. */
export interface RedirectPolicy<R extends RedirectableResponse> {
  /** Make one request, without following a redirect. */
  request(hop: RedirectHop): Promise<R>;
  /** Throw to refuse a target the rule itself admits; return to follow it. */
  vetTarget(redirect: RedirectTarget): void;
  /** Release a redirect response, whose body is never read. */
  discard?(redirect: R): void;
  /** Redirects followed before the read is refused; {@link MAX_REDIRECTS} when absent. */
  readonly maxRedirects?: number;
  /**
   * How an empty `Location` value is read. `true` refuses it as a missing header. `false` resolves
   * it as the relative reference it is, to the URL that named it, which is then asked again. The
   * two readers differ here, and each keeps the reading its callers have.
   */
  readonly emptyLocationIsMissing: boolean;
  readonly refusals: RedirectRefusals;
}

/**
 * Request `url` and each URL a redirect names in turn, and return the first response that is not a
 * redirect. Refuses, with the policy's errors, more redirects than the limit, a redirect without a
 * usable `Location`, a step from https down to http, and any target the policy's `vetTarget` refuses.
 */
export async function followRedirects<R extends RedirectableResponse>(url: string, policy: RedirectPolicy<R>): Promise<R> {
  const origin = new URL(url).origin;
  const maxRedirects = policy.maxRedirects ?? MAX_REDIRECTS;
  let current = url;
  for (let followed = 0; ; followed++) {
    const from = new URL(current);
    const response = await policy.request({ url: current, crossOrigin: from.origin !== origin });
    if (!REDIRECT_STATUSES.has(response.status)) return response;
    policy.discard?.(response);
    if (followed >= maxRedirects) throw policy.refusals.limitExceeded(maxRedirects);
    const target = redirectTarget(from, response, policy);
    policy.vetTarget({ target, from, crossOrigin: target.origin !== origin });
    current = target.href;
  }
}

/** The URL `response`'s `Location` names, resolved against `from`, the URL that was asked. */
function redirectTarget<R extends RedirectableResponse>(from: URL, response: R, policy: RedirectPolicy<R>): URL {
  const { refusals } = policy;
  const location = response.headers.get('location');
  if (location === null || (location === '' && policy.emptyLocationIsMissing)) {
    throw refusals.missingLocation(response.status);
  }
  let target: URL;
  try {
    target = new URL(location, from);
  } catch {
    throw refusals.invalidLocation(location);
  }
  if (target.protocol === 'http:' && from.protocol === 'https:') throw refusals.httpsToHttp(target);
  return target;
}
