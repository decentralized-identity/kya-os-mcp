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
 * nothing the verifier's network answered: where the library's own resolvers decided it from the
 * DID alone, before any request or DNS lookup (the private-network rule refusing an IP literal or a
 * local name the DID names, a DID of a method no resolver serves, a did:key that does not decode,
 * or a did:cheqd DID of no network the resolver asks), or where the resolution ran out of time,
 * which the presenter observes anyway. Anything else was learned from the network, or is reported
 * by a host's resolver that cannot say it was not: an HTTP status, a byte cap, an answer that is not
 * JSON, a redirect, a document that is not the DID's, or a name that resolves to a private address.
 * The refusal then says only that the DID could not be resolved, with the code of the cause, and
 * that the verifier's log says why: the library's resolvers log the detail as they fail, and the
 * library logs the detail a host's resolver reports.
 */

import { logger } from '../logging/index.js';
import type { RefusalCode } from '../refusal-codes.js';
import { describeTimeout } from '../utils/deadline.js';
import { describeValue } from '../utils/describe-value.js';
import { getDidMethod } from '../utils/did-helpers.js';
import { isRecord } from '../utils/guards.js';
import { sanitizeForMessage } from '../utils/message-text.js';
import { readFailureKind } from '../utils/read-failure.js';
import { presentable, WITHHELD_SUFFIX } from '../utils/thrown-words.js';
import type { DIDDocument, DIDResolver, DidResolutionFailure, DidResolutionFailureCause } from './vc-verifier.types.js';
import { resolveWithinLimits, type ResolutionDeadline } from './did-resource-limits.js';

/** Every {@link DidResolutionFailureCause}, to check one a resolver of the host's reports. */
const CAUSES: ReadonlySet<string> = new Set<DidResolutionFailureCause>([
  'host_refused',
  'deadline_exceeded',
  'unavailable',
  'too_large',
  'invalid_document',
]);

/** DIDs a resolver keeps a failure for, the least recently failed forgotten first, so naming many holds little. */
const MAX_RECORDED_FAILURES = 256;

/** The most UTF-16 code units of a failure's detail a refusal shows. */
const DETAIL_LENGTH = 256;

/**
 * How a refusal treats a failure of the library's own resolvers: `shown`, a detail a refusal may show
 * ({@link shownToPresenter}), decided from the DID alone, before any request or DNS lookup, or of a
 * read whose error is presentable by the rule thrown words follow (`utils/thrown-words.ts`); or
 * `logged`, a detail the operator's log was told as the resolver failed, so a refusal that withholds
 * it can say the log has it.
 */
type Disclosure = 'shown' | 'logged';

/**
 * The failures of the library's own resolvers, with how a refusal treats each. They are kept by
 * identity, so a host's resolver cannot claim one, and each is frozen, so none changes once marked.
 */
const DISCLOSURES = new WeakMap<object, Disclosure>();

/** A frozen copy of `failure`, marked with `disclosure` where there is one. */
function marked(failure: DidResolutionFailure, disclosure: Disclosure | undefined): DidResolutionFailure {
  const kept = Object.freeze({ cause: failure.cause, detail: failure.detail });
  if (disclosure !== undefined) DISCLOSURES.set(kept, disclosure);
  return kept;
}

/** A frozen copy of `failure`, marked as one whose detail a refusal may show. */
function shownFailure(failure: DidResolutionFailure): DidResolutionFailure {
  return marked(failure, 'shown');
}

/**
 * A frozen copy of `failure`, marked as one of the library's whose detail the operator's log was
 * told as it failed: its caller logs before recording it.
 */
export function loggedFailure(failure: DidResolutionFailure): DidResolutionFailure {
  return marked(failure, 'logged');
}

/** A frozen copy of `failure`, read from `from`, marked as `from` was. */
function keptAs(from: object, failure: DidResolutionFailure): DidResolutionFailure {
  return marked(failure, DISCLOSURES.get(from));
}

/** A resolver's record of the last failure for each DID, of at most {@link MAX_RECORDED_FAILURES} DIDs. */
export class DidResolutionFailures {
  private readonly byDid = new Map<string, DidResolutionFailure>();

  /** Record `failure` as the last for `did`, forgetting the least recent DID's when the record is full. */
  record(did: string, failure: DidResolutionFailure): void {
    this.byDid.delete(did);
    this.byDid.set(did, keptAs(failure, failure));
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
 * of `timeoutMs`: the kind of read failure it carries, shown where its error is presentable (a read
 * that refused its URL before any request, or a deadline), or `unavailable` for a transport's own
 * error, whose words are left to the log. The caller has logged the error's words.
 */
export function readFailureOf(error: unknown, url: string, timeoutMs: number): DidResolutionFailure {
  const kind = readFailureKind(error);
  if (kind === undefined) {
    return loggedFailure({ cause: 'unavailable', detail: `The fetch provider could not fetch ${describeValue(url)}; its error is logged` });
  }
  const { message } = error as Error;
  const failure: DidResolutionFailure = kind === 'deadline_exceeded'
    ? { cause: kind, detail: `${message}: no document arrived within ${describeTimeout(timeoutMs)}` }
    : { cause: kind, detail: message };
  return presentable(error) ? shownFailure(failure) : loggedFailure(failure);
}

/** An `invalid_document` failure decided from the DID alone: `detail` says what about it no resolution can change. */
export function invalidDid(detail: string): DidResolutionFailure {
  return shownFailure({ cause: 'invalid_document', detail });
}

/** An `invalid_document` failure decided from the DID alone: `resolver`, a resolver of some methods, resolves no DID of `did`'s method. */
export function unservedMethod(resolver: string, did: string): DidResolutionFailure {
  const method = /^did:([^:]*):/.exec(did)?.[1];
  return invalidDid(method === undefined ? `${resolver} resolves no such DID` : `${resolver} resolves no ${describeValue(method)} DID`);
}

/**
 * An `invalid_document` failure learned from the network: the document read from `url` is not a
 * valid one of the DID, as `why` says. The caller has logged why.
 */
export function invalidDocument(url: string, why: string): DidResolutionFailure {
  return loggedFailure({ cause: 'invalid_document', detail: `The document at ${describeValue(url)} ${why}` });
}

/**
 * The failure `resolver` reports for `did`, when it has `lastFailure` and that answers a failure
 * with a known cause and a detail, decided from the DID alone only where it is one of the library's
 * own failures that was. A resolver is the host's code, so one that throws, or answers anything
 * else, reports nothing.
 */
export function reportedFailure(resolver: DIDResolver, did: string): DidResolutionFailure | undefined {
  try {
    const failure: unknown = resolver.lastFailure?.(did);
    if (!isRecord(failure)) return undefined;
    const { cause, detail } = failure;
    if (typeof cause !== 'string' || !CAUSES.has(cause) || typeof detail !== 'string') return undefined;
    return keptAs(failure, { cause: cause as DidResolutionFailureCause, detail });
  } catch {
    return undefined;
  }
}

/**
 * The refusal code of each cause a resolver reports: a refused host and a passed deadline keep their
 * names, a document that could not be read leaves the DID unavailable for now, and one over the byte
 * cap, which no document of the DID may be, or an invalid one, is an invalid DID.
 */
const CAUSE_CODES: Readonly<Record<DidResolutionFailureCause, RefusalCode>> = Object.freeze({
  host_refused: 'host_refused',
  deadline_exceeded: 'deadline_exceeded',
  unavailable: 'did_unavailable',
  too_large: 'did_invalid',
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
 * Whether a refusal may show `failure`'s detail to whoever presented the DID: where the resolution
 * ran out of time, which the presenter observes anyway, or where the library decided it from the DID
 * alone, before any request or DNS lookup. Anything else was learned from the network, or is
 * reported by a host's resolver that cannot say it was not, and is for the operator alone.
 */
function shownToPresenter(failure: DidResolutionFailure): boolean {
  return failure.cause === 'deadline_exceeded' || DISCLOSURES.get(failure) === 'shown';
}

/**
 * What a refusal of `did` as unresolvable ends with, `failure` the failure the resolver reports for
 * it: its detail, in parentheses after a space and sanitized for a message, where it is
 * {@link shownToPresenter}; otherwise {@link WITHHELD_SUFFIX}, once the operator's log has why. The
 * library's own resolvers told the log as they failed; the log is told here the detail a host's
 * resolver reports, or that it reported none ({@link warnUncaused}).
 */
function refusalEnding(did: string, failure: DidResolutionFailure | undefined): string {
  if (failure === undefined) warnUncaused(did);
  else if (shownToPresenter(failure)) return ` (${sanitizeForMessage(failure.detail, DETAIL_LENGTH)})`;
  else if (DISCLOSURES.get(failure) !== 'logged') {
    logger.warn(`[kya-os] the DID resolver could not resolve ${describeValue(did)}: ${sanitizeForMessage(failure.detail, DETAIL_LENGTH)}`);
  }
  return WITHHELD_SUFFIX;
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
 * suffix in parentheses where a refusal may show it, or else a pointer to the operator's log
 * ({@link refusalEnding}), with the code of its cause ({@link unresolvedCode}). When the limits
 * refused the DID, its key or what the resolver returned, it is nothing, since the resolver's last
 * failure is then not this one, with `did_invalid`. A resolver that throws, or a deadline that
 * passes, rejects, as `resolveWithinLimits` does.
 */
export async function resolveExplained(
  resolver: DIDResolver, did: string, key?: unknown, within?: ResolutionDeadline | number,
): Promise<ExplainedResolution> {
  const resolution = await resolveWithinLimits(resolver, did, key, within);
  if (resolution.status === 'found') return { document: resolution.document };
  if (resolution.status === 'refused') return { document: null, why: '', code: 'did_invalid' };
  const failure = reportedFailure(resolver, did);
  return { document: null, why: refusalEnding(did, failure), code: unresolvedCode(failure) };
}

/**
 * Tell the operator that the resolver found no document for `did` and gave no cause, as a resolver
 * of the library's does for a DID of a method it does not serve. The refusal is then
 * `did_unavailable`, transient, and tells the presenter only that the log says why, so only this
 * line says the verifier may lack a resolver for the DID's method.
 */
function warnUncaused(did: string): void {
  const method = getDidMethod(did);
  const named = method === null ? "the DID's method" : `the ${sanitizeForMessage(`did:${method}`, DETAIL_LENGTH)} method`;
  logger.warn(
    `[kya-os] the DID resolver found no document for ${describeValue(did)} and gave no cause: it may not serve ${named}; ` +
      'if it does not, give the verifier a resolver that does',
  );
}

/**
 * What a refusal of the issuer DID `did` as unresolvable opens with, `Could not resolve issuer DID:`
 * and the DID as `describeValue` quotes it, before the {@link ExplainedResolution} `why` it may end
 * with; alone, it is the whole reason where nothing more may be shown, as for a resolver that threw.
 */
export function unresolvedIssuer(did: string): string {
  return `Could not resolve issuer DID: ${describeValue(did)}`;
}
