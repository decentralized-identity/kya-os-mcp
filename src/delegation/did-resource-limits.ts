/**
 * The boundary a verifier puts around a DID resolver (SPEC §4.4.2): identifier limits before the
 * call, one deadline on its promise, and the walk over what it returns. The policy, the walk and
 * the cache live in their own modules and are re-exported here.
 */

import type { DIDDocument, DIDResolver } from './vc-verifier.types.js';
import { boundedIdentifiers, DID_RESOLUTION_TIMEOUT_MS } from './did-resource-policy.js';
import { isAdmittedDidDocument, measureDidDocument } from './did-document-walk.js';

export * from './did-resource-policy.js';
export { admitParsedDidDocument, isAdmittedDidDocument, measureDidDocument, type DidDocumentMeasure } from './did-document-walk.js';
export { DidDocumentCache, type LoadedDidDocument } from './did-document-cache.js';

/** One deadline that the steps of a resolution share, so together they take at most its length. */
export interface ResolutionDeadline {
  /** `work`, or a rejection with `DID resolution deadline exceeded` once the deadline has passed. */
  within<T>(work: Promise<T>): Promise<T>;
  /** Stop the timer, once the resolution has settled. */
  clear(): void;
}

/** A {@link ResolutionDeadline} of {@link DID_RESOLUTION_TIMEOUT_MS}, starting now. */
export function resolutionDeadline(): ResolutionDeadline {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const passed = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('DID resolution deadline exceeded')), DID_RESOLUTION_TIMEOUT_MS);
  });
  // A step that is not waiting when the deadline passes leaves no rejection unhandled.
  passed.catch(() => undefined);
  return {
    within: work => Promise.race([work, passed]),
    clear: () => clearTimeout(timer),
  };
}

/**
 * What a bounded resolution came to: a document within the limits, no document, or one the limits
 * refuse, which is not a missing document: a caller that falls back to another resolver after a
 * miss does not after a refusal.
 */
export type BoundedResolution =
  | { readonly status: 'found'; readonly document: DIDDocument }
  | { readonly status: 'not found' }
  | { readonly status: 'refused' };

const NOT_FOUND: BoundedResolution = { status: 'not found' };
const REFUSED: BoundedResolution = { status: 'refused' };

/**
 * Resolve `did` through an application-supplied resolver within the limits. A DID or `key` over
 * its limit is refused before the resolver is asked. A document a built-in resolver admitted is not
 * walked again; any other is walked on every resolution, and neither copied nor frozen. A missed
 * deadline rejects, apart from a resolver that found nothing. Without a `deadline` from the caller,
 * the resolution has one of its own.
 */
export async function resolveWithinLimits(
  resolver: DIDResolver, did: string, key?: unknown, deadline?: ResolutionDeadline,
): Promise<BoundedResolution> {
  if (!boundedIdentifiers(did, key)) return REFUSED;
  const bound = deadline ?? resolutionDeadline();
  let doc: DIDDocument | null | undefined;
  try {
    doc = await bound.within(resolver.resolve(did));
  } finally {
    if (bound !== deadline) bound.clear();
  }
  if (doc === null || doc === undefined) return NOT_FOUND;
  return isAdmittedDidDocument(doc) || measureDidDocument(doc).ok ? { status: 'found', document: doc } : REFUSED;
}

/** {@link resolveWithinLimits}'s document, or `null` when it found none or refused it. */
export async function resolveBoundedDid(
  resolver: DIDResolver, did: string, key?: unknown, deadline?: ResolutionDeadline,
): Promise<DIDDocument | null> {
  const resolution = await resolveWithinLimits(resolver, did, key, deadline);
  return resolution.status === 'found' ? resolution.document : null;
}
