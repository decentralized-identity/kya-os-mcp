/**
 * Which `statusListIssuers` bindings no redirect reaches, said once, when a reader is configured.
 * SPEC.md §6.6 reads a binding on the bytes as written: an exact URL binds a status entry that names
 * it byte for byte, and an https origin a URL that continues it. So
 * `https://lists.example:443/list` binds the entries that name it so. A redirect, though, is matched
 * by the URL it resolves to, as the URL parser writes it (`./operator-named`), and the parser writes
 * that URL `https://lists.example/list`, so no redirect ever reaches the binding as written.
 *
 * Such a binding is said, not refused. §6.6 takes it as written, and so does the conformance
 * harness that the library, its TypeScript loader and its Python reader are each held to, so a
 * refusal here would refuse a configuration every other implementation takes; and the binding
 * still does its work for a status entry that names it as written. A binding is said once per
 * process, naming the form a redirect reaches, so an operator who meant a redirect to reach it can
 * bind that form as well. Said too is a binding no read reaches at all: one that includes
 * credentials, which every reader refuses before any request, or one that does not parse. An http
 * binding is left alone, since no redirect to http is ever followed.
 */

import { logger } from '../logging/index.js';
import { describeValue } from './describe-value.js';
import { isOriginBinding, type StatusListIssuers } from './statuslist-keeper.js';
import { includesCredentials } from './url.js';

/** The bindings this package copy has said, each under its keeper. */
const said = new Set<string>();

/**
 * Say once, through `logger.warn`, of each binding of `statusListIssuers` that no redirect reaches,
 * why, and the form a redirect reaches where there is one. `statusListIssuers` is one
 * `assertStatusListIssuers` has taken.
 */
export function sayBindingsNoRedirectReaches(statusListIssuers: StatusListIssuers | undefined): void {
  for (const [keeper, bindings] of Object.entries(statusListIssuers ?? {})) {
    for (const binding of bindings) {
      const why = unreachedBecause(binding);
      const key = JSON.stringify([keeper, binding]);
      if (why === undefined || said.has(key)) continue;
      said.add(key);
      logger.warn(`[kya-os] statusListIssuers[${describeValue(keeper)}] holds ${describeValue(binding)}, ${why}`);
    }
  }
}

/** Why no redirect reaches `binding`, an https binding §6.6 takes, or `undefined` when one does or it is http. */
function unreachedBecause(binding: string): string | undefined {
  if (!binding.startsWith('https://')) return undefined;
  let url: URL;
  try {
    url = new URL(binding);
  } catch {
    return 'which does not parse as a URL, so no read reaches it.';
  }
  if (includesCredentials(url)) return 'a URL that includes credentials, which every reader refuses before any request, so no read reaches it.';
  const reached = isOriginBinding(binding) ? url.origin : url.href;
  if (reached === binding) return undefined;
  // A binding may not end in "/" (§6.6), so a form that does is named, not offered.
  const bindIt = reached.endsWith('/') ? '.' : ': bind that as well for a redirect to reach it.';
  return (
    'which a status entry reaches as written but a redirect never does, since a redirect is matched as the URL parser ' +
    `writes it, ${JSON.stringify(reached)}${bindIt}`
  );
}
