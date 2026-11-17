/**
 * How the Entity Card compares two DIDs: as `resolveCard` binds a fetched Card to the DID it was
 * resolved for, and as `verifyCard` ties a live proof to the Card it lifts. Internal to the card
 * module, and not exported from the package.
 */

/**
 * Canonicalize a DID for identity comparison. For `did:web` the DNS host is case-INsensitive, so it
 * is lowercased, and every `:`-separated segment is percent-decoded and RE-encoded, so two spellings
 * of one DID (`%3a` vs `%3A`, a needlessly escaped letter) compare equal. The re-encode is what keeps
 * distinct DIDs distinct: a decoded `:` inside a segment (the port of `did:web:host%3A8443`, or a
 * user named `alice:agent`) goes back to `%3A`, so it never collapses into a segment separator and
 * `did:web:host:users:alice%3Aagent` stays a different DID from `did:web:host:users:alice:agent`.
 * Other DID methods (e.g. `did:key`, case-sensitive base58) compare verbatim. Throws a `URIError`
 * for a `did:web` segment whose percent-encoding is malformed.
 */
export function normalizeDid(did: string): string {
  if (!did.startsWith('did:web:')) return did;
  const [host = '', ...path] = did.slice('did:web:'.length).split(':').map(decodeURIComponent);
  return `did:web:${[host.toLowerCase(), ...path].map(encodeURIComponent).join(':')}`;
}

/**
 * Whether `a` and `b` are one DID, compared as {@link normalizeDid} writes them. A DID whose
 * percent-encoding is malformed is no DID's equal, so the comparison never throws.
 */
export function sameDid(a: string, b: string): boolean {
  try {
    return normalizeDid(a) === normalizeDid(b);
  } catch {
    return false;
  }
}
