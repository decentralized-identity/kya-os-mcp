/**
 * Which thrown words may reach whoever presented a request. A refusal's reason goes back to the
 * party that presented the credential, and that party chooses the DIDs and the status-list URLs a
 * verifier reads, so a thrown message reaches a reason only where it tells that party nothing the
 * verifier learned from its network, nor what a dependency of the host's wrote: the library's own
 * refusal (a {@link RefusalError}); a read's refusal of a URL as given, before any request or DNS
 * lookup; or a deadline that passed, whose timing the presenter observes anyway. Any other thrown
 * message (a transport's error, an HTTP status, an answer that is not JSON, a byte cap, a redirect,
 * a refusal made after a DNS lookup) goes to the operator's log, and the reason says only what could
 * not be done, ending with {@link WITHHELD_SUFFIX} so whoever reads it knows where the detail went. A verdict about a document that was read, such as a status list, reaches the
 * presenter only once the document's proof verifies, since only then are its words its issuer's;
 * before that, its reason and any remedy go to the operator's log ({@link NetworkRefusalError}).
 * That refines, and does not replace, the rule above. The DID resolvers mark their failures by the
 * same rule (`delegation/did-resolution-failure.ts`).
 */

import { logger } from '../logging/index.js';
import { DeadlineExceededError } from './deadline.js';
import { describeValue } from './describe-value.js';
import { sanitizeForMessage } from './message-text.js';
import { readFailureKind, refusedBeforeRequest } from './read-failure.js';
import { RefusalError } from './refusal.js';

/** The most UTF-16 code units of a withheld message the operator's log line keeps. */
const LOGGED_LENGTH = 1024;

/**
 * What a reason ends with when the thrown words behind it went to the operator's log instead: that
 * the log has them. It names no cause, so it tells whoever presented the request only what the
 * reason's fixed words already did, that the library withheld something, and tells a developer who
 * reads the refusal where to look.
 */
export const WITHHELD_SUFFIX = "; the verifier's log says why";

/**
 * The library's verdict about what a host answered, decided before the answer's proof verified,
 * such as a fetched status list the acceptance rule refuses before its proof is checked. Its code
 * reaches the refusal as a {@link RefusalError}'s does. Its words, a remedy among them, quote
 * members of the answer, which whoever chose the URL may have pointed at any document the verifier
 * can reach, so until the proof verifies they go to the operator's log alone, and the reason says
 * only what could not be done.
 */
export class NetworkRefusalError extends RefusalError {}

/**
 * Whether `error`'s message may reach whoever presented the request: the library's own refusal, but
 * for one of what a host answered ({@link NetworkRefusalError}), a read's refusal of its URL before
 * any request or DNS lookup, or a deadline that passed.
 */
export function presentable(error: unknown): boolean {
  return (
    (error instanceof RefusalError && !(error instanceof NetworkRefusalError)) ||
    error instanceof DeadlineExceededError ||
    refusedBeforeRequest(error) ||
    readFailureKind(error) === 'deadline_exceeded'
  );
}

/**
 * The words of `error` a reason may hold, where it is {@link presentable}: its message, free of
 * control characters and at most `maxLength` UTF-16 code units as `sanitizeForMessage` leaves it.
 * `undefined` for any other error, whose words only the operator's log may be told.
 */
export function shownWords(error: unknown, maxLength = 256): string | undefined {
  return presentable(error) ? sanitizeForMessage((error as Error).message, maxLength) : undefined;
}

/** How a reason is written for a thrown error, by {@link thrownReason}. */
export interface ThrownReason {
  /** The reason where the error's words may not reach it, before {@link WITHHELD_SUFFIX}. */
  readonly withheld: string;
  /** The reason around the error's words where they may; by default the words alone. */
  readonly shown?: (words: string) => string;
  /** What the operator's log line for a withheld error opens with, such as `[kya-os]`. */
  readonly tag: string;
  /** The most UTF-16 code units of the error's words a reason keeps. Default 256. */
  readonly maxLength?: number;
}

/**
 * The reason for `error`: `shown` around its {@link shownWords} where it has some; otherwise
 * `withheld` and {@link WITHHELD_SUFFIX}, with the message logged for the operator as
 * `<tag> <withheld>: <message>`.
 */
export function thrownReason(error: unknown, { withheld, shown = (words) => words, tag, maxLength = 256 }: ThrownReason): string {
  const words = shownWords(error, maxLength);
  if (words !== undefined) return shown(words);
  logger.warn(`${tag} ${withheld}: ${loggedWords(error)}`);
  return `${withheld}${WITHHELD_SUFFIX}`;
}

/**
 * The words of `error` the operator's log is told: its message, free of control characters and at
 * most {@link LOGGED_LENGTH} UTF-16 code units, or what kind of value was thrown, where it is no `Error`.
 */
export function loggedWords(error: unknown): string {
  return sanitizeForMessage(error instanceof Error ? error.message : `a thrown ${typeof error}`, LOGGED_LENGTH);
}

/**
 * What a reason says of the status list at `url` when it may say no more: that it could not be read
 * or checked, since the step that failed may have come after the list was read, as decoding it,
 * checking its shape or a proof verifier of the host's that threw.
 */
export function unreadStatusList(url: unknown): string {
  return `the status list at ${describeValue(url)} could not be read or checked`;
}
