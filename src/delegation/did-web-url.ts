/**
 * A did:web DID as its method reads it: its host, which must be a host and nothing more, and its
 * path, each segment one segment, and the HTTPS URL of the document it names.
 *
 * Each part is percent-decoded once and written into the URL as decoded. The URL parser and the
 * server percent-decode that URL again, so a part that still holds a `%` after the one decode is
 * refused: `%252E%252E` would become a dot-segment there, `%252F` a separator, and
 * `example%252Ecom` the host `example.com`, so that two DIDs would name one document.
 *
 * @see https://w3c-ccg.github.io/did-method-web/
 */

/**
 * Parsed components of a did:web DID
 */
export interface ParsedDidWeb {
  domain: string;
  path: string[];
}

/**
 * Check if a DID is a did:web DID
 *
 * @param did - The DID to check
 * @returns true if it's a did:web DID
 */
export function isDidWeb(did: string): boolean {
  return did.startsWith('did:web:');
}

/**
 * Decode and validate the host component of a did:web DID. It is
 * percent-decoded whole, as before, so a port (`%3A`), a bracketed IPv6
 * literal and an internationalized name still resolve. What it decodes to
 * must still be a host and nothing more: `@`, `/`, `\`, `?` or `#` would let
 * it supply userinfo, a path, a query or a fragment and fetch from a host or
 * resource other than the one the DID names, and so would whitespace, a
 * control character, a `%` the URL parser would decode again, or a `:` beyond
 * one port separator (a bracketed IPv6 literal keeps its own colons). Returns
 * the host with its optional `:port`, or `null`.
 */
function parseDidWebHost(label: string): string | null {
  let host: string;
  try {
    host = decodeURIComponent(label);
  } catch {
    return null;
  }
  if (host.length === 0 || /[@/\\?#%\s\p{Cc}]/u.test(host)) {
    return null;
  }
  const afterLiteral = host.startsWith('[') ? host.slice(host.indexOf(']') + 1) : host;
  return afterLiteral.split(':').length <= 2 ? host : null;
}

/**
 * Parse a did:web DID into its components
 *
 * @param did - The did:web DID to parse
 * @returns Parsed components or null if invalid
 */
export function parseDidWeb(did: string): ParsedDidWeb | null {
  if (!isDidWeb(did)) {
    return null;
  }

  // Remove the 'did:web:' prefix
  const remainder = did.slice(8);

  if (remainder.length === 0) {
    return null;
  }

  // Split by ':' to get domain and path components
  const parts = remainder.split(':');

  const domain = parseDidWebHost(parts[0]!);
  if (domain === null) {
    return null;
  }

  // Remaining parts form the path. Each is one segment: a decoded separator
  // or dot-segment would move the fetch to a different resource, and so would
  // one the URL parser or the server decodes from a `%` left after this decode.
  let path: string[];
  try {
    path = parts.slice(1).map((p) => decodeURIComponent(p));
  } catch {
    return null;
  }
  const isSegment = (segment: string): boolean =>
    segment !== '' && segment !== '.' && segment !== '..' && !/[/\\?#%]/.test(segment);
  if (!path.every(isSegment)) {
    return null;
  }

  return { domain, path };
}

/**
 * Convert a did:web DID to its resolution URL
 *
 * did:web:example.com → https://example.com/.well-known/did.json
 * did:web:example.com:path:to:doc → https://example.com/path/to/doc/did.json
 *
 * @param did - The did:web DID
 * @returns The resolution URL or null if invalid
 */
export function didWebToUrl(did: string): string | null {
  const parsed = parseDidWeb(did);

  if (!parsed) {
    return null;
  }

  const { domain, path } = parsed;

  // Build the URL
  // Note: did:web specification requires HTTPS
  let url = `https://${domain}`;

  if (path.length === 0) {
    // Root domain: use /.well-known/did.json
    url += '/.well-known/did.json';
  } else {
    // Path-based: use /path/to/resource/did.json
    url += '/' + path.join('/') + '/did.json';
  }

  return url;
}
