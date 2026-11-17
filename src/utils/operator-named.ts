/**
 * Which requests of a read are the operator's own: decided request by request, the first and each
 * redirect, on the URL that request asks for, as SafeFetch decides its `allowOrigins`. A URL the
 * operator names, such as a status-list URL `statusListIssuers` binds or the document URL of a DID
 * it pins, is read wherever its host is; a redirect from it to a URL the operator does not name is
 * held to the private-network rule as any URL a presenter names, so an open redirect on an operator's
 * host reaches no private address.
 *
 * A URL is named byte for byte, as the keeper (`./statuslist-keeper`) binds a list's URL to its
 * issuer: the first request by the URL as the read was given it, never by the spelling the URL
 * parser makes of it, so a presenter who writes a bound URL with its host in upper case, or a `/./`
 * in its path, has that read held to the rule, as the keeper holds that list to the credential's
 * own issuer; a redirect by the URL the follower resolved its `Location` to.
 *
 * What a request the operator named is spared is the same in each reader that takes one: the
 * refusal of a private or local address, and of http for the read's first request. How it connects
 * is each reader's own, as for any other request it makes. SafeFetch has one connection seam, its
 * `transport`, so it resolves such a request and pins its connection, private addresses admitted.
 * `RuntimeFetchProvider` reads it through its own `fetch`, as 1.23.0 read every request, neither
 * resolved nor pinned: the operator chose the host, so no check is owed to it, and that `fetch`
 * carries what the application configures for its own hosts, such as a dispatcher with client
 * certificates or a proxy, which a connection the provider pinned itself would go around.
 */

/**
 * `named` as a reader asks it: only its own `true` names a URL, and one that is not a function, or
 * that throws, names none.
 */
export function guardedNamer(named: unknown): (url: string) => boolean {
  if (typeof named !== 'function') return () => false;
  return (url) => {
    try {
      return (named as (url: string) => unknown)(url) === true;
    } catch {
      return false;
    }
  };
}

/**
 * Which requests of a read of `url` the operator named, asked of each by the URL it asks for, as
 * this module opens by saying: the first, which asks for `url` as the URL parser writes it, when
 * `named` names `url` as written, and any other that `named` names.
 */
export function operatorNamedRequests(url: string, named: (url: string) => boolean): (request: string) => boolean {
  const first = hrefOf(url);
  const names = guardedNamer(named);
  return (request) => (request === first ? names(url) : names(request));
}

/** `url` as the URL parser writes it, or `undefined` when it does not parse. */
function hrefOf(url: string): string | undefined {
  try {
    return new URL(url).href;
  } catch {
    return undefined;
  }
}
