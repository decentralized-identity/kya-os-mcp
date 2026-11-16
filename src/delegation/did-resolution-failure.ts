/**
 * Why a DID could not be resolved: how the library's resolvers record the cause of their last
 * failure for each DID, and how a verifier reads the cause a resolver reports and appends it to its
 * refusal. The causes are those of {@link DidResolutionFailureCause}. A read that failed carries its
 * kind on the error it threw (`utils/read-failure.ts`); an error of the transport's carries none,
 * and its words go to the log, not into the cause, since they may say more about the network than a
 * refusal should.
 */

import { describeTimeout } from '../utils/deadline.js';
import { describeValue } from '../utils/describe-value.js';
import { isRecord } from '../utils/guards.js';
import { sanitizeForMessage } from '../utils/message-text.js';
import { readFailureKind } from '../utils/read-failure.js';
import type { DIDDocument, DIDResolver, DidResolutionFailure, DidResolutionFailureCause } from './vc-verifier.types.js';
import { resolveWithinLimits, type ResolutionDeadline } from './did-resource-limits.js';

/** Every {@link DidResolutionFailureCause}, to check one a resolver of the host's reports. */
const CAUSES: ReadonlySet<string> = new Set<DidResolutionFailureCause>([
  'host_refused',
  'deadline_exceeded',
  'unavailable',
  'invalid_document',
]);

/** DIDs a resolver keeps a failure for, the least recently failed forgotten first, so naming many holds little. */
const MAX_RECORDED_FAILURES = 256;

/** The most UTF-16 code units of a failure's detail a refusal shows. */
const DETAIL_LENGTH = 256;

/** A resolver's record of the last failure for each DID, of at most {@link MAX_RECORDED_FAILURES} DIDs. */
export class DidResolutionFailures {
  private readonly byDid = new Map<string, DidResolutionFailure>();

  /** Record `failure` as the last for `did`, forgetting the least recent DID's when the record is full. */
  record(did: string, failure: DidResolutionFailure): void {
    this.byDid.delete(did);
    this.byDid.set(did, Object.freeze({ cause: failure.cause, detail: failure.detail }));
    if (this.byDid.size > MAX_RECORDED_FAILURES) this.byDid.delete(this.byDid.keys().next().value!);
  }

  /** Forget the failure for `did`, as when it has been resolved. */
  clear(did: string): void {
    this.byDid.delete(did);
  }

  /** The last failure recorded for `did`, if any. */
  get(did: string): DidResolutionFailure | undefined {
    return this.byDid.get(did);
  }
}

/**
 * The failure an error thrown while reading a DID document from `url` stands for, under a deadline
 * of `timeoutMs`. A transport's own error is `unavailable`, and its words are left to the log.
 */
export function readFailureOf(error: unknown, url: string, timeoutMs: number): DidResolutionFailure {
  const kind = readFailureKind(error);
  if (kind === undefined) {
    return { cause: 'unavailable', detail: `The fetch provider could not fetch ${describeValue(url)}; its error is logged` };
  }
  const { message } = error as Error;
  if (kind === 'deadline_exceeded') {
    return { cause: kind, detail: `${message}: no document arrived within ${describeTimeout(timeoutMs)}` };
  }
  return { cause: kind, detail: message };
}

/** An `invalid_document` failure: the document read from `url` is not a valid one of the DID, as `why` says. */
export function invalidDocument(url: string, why: string): DidResolutionFailure {
  return { cause: 'invalid_document', detail: `The document at ${describeValue(url)} ${why}` };
}

/**
 * The failure `resolver` reports for `did`, when it has `lastFailure` and that answers a failure
 * with a known cause and a detail. A resolver is the host's code, so one that throws, or answers
 * anything else, reports nothing.
 */
export function reportedFailure(resolver: DIDResolver, did: string): DidResolutionFailure | undefined {
  try {
    const failure: unknown = resolver.lastFailure?.(did);
    if (!isRecord(failure)) return undefined;
    const { cause, detail } = failure;
    if (typeof cause !== 'string' || !CAUSES.has(cause) || typeof detail !== 'string') return undefined;
    return { cause: cause as DidResolutionFailureCause, detail };
  } catch {
    return undefined;
  }
}

/**
 * What a refusal of `did` as unresolvable ends with: the detail of the failure `resolver` reports
 * for it, in parentheses after a space and sanitized for a message, or nothing.
 */
export function resolutionFailureSuffix(resolver: DIDResolver, did: string): string {
  const failure = reportedFailure(resolver, did);
  return failure === undefined ? '' : ` (${sanitizeForMessage(failure.detail, DETAIL_LENGTH)})`;
}

/** A document found within the limits, or none, with what a refusal of the DID as unresolvable ends with. */
export type ExplainedResolution = { readonly document: DIDDocument } | { readonly document: null; readonly why: string };

/**
 * Resolve `did` through `resolver` within the limits, as `resolveBoundedDid` does, and when no
 * document is found say why: the failure the resolver reports, as {@link resolutionFailureSuffix}
 * writes it, when it found nothing, and nothing when the limits refused the DID, its key or what
 * it returned, since the resolver's last failure is then not this one.
 */
export async function resolveExplained(
  resolver: DIDResolver, did: string, key?: unknown, within?: ResolutionDeadline | number,
): Promise<ExplainedResolution> {
  const resolution = await resolveWithinLimits(resolver, did, key, within);
  if (resolution.status === 'found') return { document: resolution.document };
  return { document: null, why: resolution.status === 'not found' ? resolutionFailureSuffix(resolver, did) : '' };
}
