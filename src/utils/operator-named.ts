/**
 * Which requests of a read are the operator's own: decided request by request, the first and each
 * redirect, on the URL that request asks for, as SafeFetch decides its `allowOrigins`. A URL the
 * operator names, such as a status-list URL `statusListIssuers` binds or the document URL of a DID
 * it pins, is read wherever its host is; a redirect from it to a URL the operator does not name is
 * held to the private-network rule as any URL a presenter names, so an open redirect on an operator's
 * host reaches no private address.
 */

/**
 * Which requests of a read of `url` the operator named, asked of each by the URL it asks for: those
 * `named` names, and the first, which asks for `url` as the URL parser writes it, when `named` names
 * `url` as written. A `named` that throws names none.
 */
export function operatorNamedRequests(url: string, named: (url: string) => boolean): (request: string) => boolean {
  const first = hrefOf(url);
  const names = (candidate: string): boolean => {
    try {
      return named(candidate) === true;
    } catch {
      return false;
    }
  };
  return (request) => names(request) || (request === first && names(url));
}

/** `url` as the URL parser writes it, or `undefined` when it does not parse. */
function hrefOf(url: string): string | undefined {
  try {
    return new URL(url).href;
  } catch {
    return undefined;
  }
}
