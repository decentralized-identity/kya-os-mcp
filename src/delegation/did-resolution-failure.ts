/**
 * Why a DID could not be resolved: how the library's resolvers record the cause of their last
 * failure for each DID, and how a verifier reads the cause a resolver reports and codes its refusal
 * by it. The causes are those of {@link DidResolutionFailureCause}. A read that failed carries its
 * kind on the error it threw (`utils/read-failure.ts`); an error of the transport's carries none,
 * and its words go to the log, not into the cause, since they may say more about the network than a
 * refusal should.
 *
 * Whoever presents a credential chooses its issuer's DID, and a did:web host may be an internal one
 * behind split-horizon DNS, so a refusal shows a failure's detail only where it tells the presenter
 * nothing it does not already know: the host its DID names was refused, with how to admit it; the
 * deadline passed; or the document is not the DID's. A DID whose document could not be read is
 * refused as unresolvable alone, so that no HTTP status, byte cap or answer that is not JSON tells
 * the presenter what an internal name answered; the library's resolvers log that detail for the
 * operator.
 */

import type { RefusalCode } from '../refusal-codes.js';
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

/** The causes whose detail a refusal shows, since it tells the presenter of the DID nothing it does not know. */
const SHOWN_CAUSES: ReadonlySet<DidResolutionFailureCause> = new Set<DidResolutionFailureCause>([
  'host_refused',
  'deadline_exceeded',
  'invalid_document',
]);

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
 * The refusal code of each cause a resolver reports: a refused host and a passed deadline keep their
 * names, a document that could not be read leaves the DID unavailable for now, and an invalid one is
 * an invalid DID.
 */
const CAUSE_CODES: Readonly<Record<DidResolutionFailureCause, RefusalCode>> = Object.freeze({
  host_refused: 'host_refused',
  deadline_exceeded: 'deadline_exceeded',
  unavailable: 'did_unavailable',
  invalid_document: 'did_invalid',
});

/**
 * The refusal code of a DID the resolver found no document for: that of the cause of the failure it
 * reports, or `did_unavailable` when it reports none, since the verifier cannot tell a DID that has
 * no document from one whose document could not be read just now.
 */
export function unresolvedCode(failure: DidResolutionFailure | undefined): RefusalCode {
  return failure === undefined ? 'did_unavailable' : CAUSE_CODES[failure.cause];
}

/**
 * What a refusal of a DID as unresolvable ends with: the detail of `failure`, the failure the
 * resolver reports for it, in parentheses after a space and sanitized for a message, when its cause
 * is one of {@link SHOWN_CAUSES}, or nothing.
 */
function failureSuffix(failure: DidResolutionFailure | undefined): string {
  if (failure === undefined || !SHOWN_CAUSES.has(failure.cause)) return '';
  return ` (${sanitizeForMessage(failure.detail, DETAIL_LENGTH)})`;
}

/**
 * A document found within the limits, or none, with what a refusal of the DID as unresolvable ends
 * with and the code it is refused with.
 */
export type ExplainedResolution =
  | { readonly document: DIDDocument }
  | { readonly document: null; readonly why: string; readonly code: RefusalCode };

/**
 * Resolve `did` through `resolver` within the limits, as `resolveBoundedDid` does, and when no
 * document is found say why. When the resolver found nothing, that is the failure it reports, as a
 * suffix in parentheses where its cause is one a refusal shows ({@link failureSuffix}), with the code
 * of its cause ({@link unresolvedCode}). When the limits refused
 * the DID, its key or what the resolver returned, it is nothing, since the resolver's last failure
 * is then not this one, with `did_invalid`. A resolver that throws, or a deadline that passes,
 * rejects, as `resolveWithinLimits` does.
 */
export async function resolveExplained(
  resolver: DIDResolver, did: string, key?: unknown, within?: ResolutionDeadline | number,
): Promise<ExplainedResolution> {
  const resolution = await resolveWithinLimits(resolver, did, key, within);
  if (resolution.status === 'found') return { document: resolution.document };
  if (resolution.status === 'refused') return { document: null, why: '', code: 'did_invalid' };
  const failure = reportedFailure(resolver, did);
  return { document: null, why: failureSuffix(failure), code: unresolvedCode(failure) };
}
