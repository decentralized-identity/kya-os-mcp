/**
 * Which thrown words may reach whoever presented a request. A refusal's reason goes back to the
 * party that presented the credential, and that party chooses the DIDs and the status-list URLs a
 * verifier reads, so a thrown message reaches a reason only where it tells that party nothing the
 * verifier learned from its network, nor what a dependency of the host's wrote: the library's own
 * refusal (a {@link RefusalError}); a read's refusal of a URL as given, before any request or DNS
 * lookup; or a deadline that passed, whose timing the presenter observes anyway. Any other thrown
 * message (a transport's error, an HTTP status, an answer that is not JSON, a byte cap, a redirect,
 * a refusal made after a DNS lookup) goes to the operator's log, and the reason says only what could
 * not be done. The DID resolvers mark their failures by the same rule (`delegation/did-resolution-failure.ts`).
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
 * Whether `error`'s message may reach whoever presented the request: the library's own refusal, a
 * read's refusal of its URL before any request or DNS lookup, or a deadline that passed.
 */
export function presentable(error: unknown): boolean {
  return (
    error instanceof RefusalError ||
    error instanceof DeadlineExceededError ||
    refusedBeforeRequest(error) ||
    readFailureKind(error) === 'deadline_exceeded'
  );
}

/**
 * What a reason says for `error`: its message, free of control characters and at most `maxLength`
 * UTF-16 code units as `sanitizeForMessage` leaves it, where it is {@link presentable}; otherwise
 * `withheld`, with the message logged for the operator as `<tag> <withheld>: <message>`.
 */
export function thrownWords(error: unknown, withheld: string, tag: string, maxLength = 256): string {
  if (presentable(error)) return sanitizeForMessage((error as Error).message, maxLength);
  const words = error instanceof Error ? error.message : `a thrown ${typeof error}`;
  logger.warn(`${tag} ${withheld}: ${sanitizeForMessage(words, LOGGED_LENGTH)}`);
  return withheld;
}

/** What a reason says of the status list at `url` that could not be read, when it may say no more. */
export function unreadStatusList(url: unknown): string {
  return `the status list at ${describeValue(url)} could not be read`;
}
