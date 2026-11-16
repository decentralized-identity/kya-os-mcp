/**
 * How the library builds a refusal: from a code of the catalog (`../refusal-codes.ts`), with the
 * `transient` that code fixes, so no refusal is built without both. The verifiers' internal result
 * types require the pair on every refusal, and a step that refuses by throwing, as a status-list
 * read does, throws a {@link RefusalError} that carries its code to whoever turns the throw into a
 * refusal. The code is chosen where the refusal is decided, never read back out of its reason.
 */

import { isTransientRefusal, type RefusalCode } from '../refusal-codes.js';
import { DeadlineExceededError } from './deadline.js';
import { readFailureKind } from './read-failure.js';

/** A refusal's code, and whether it is transient, as every refusal carries them. */
export interface Coded {
  readonly code: RefusalCode;
  readonly transient: boolean;
}

/** The {@link Coded} pair of `code`. */
export function coded(code: RefusalCode): Coded {
  return { code, transient: isTransientRefusal(code) };
}

/**
 * A refusal as a verifier's `{ valid, reason }` result states it, with its code. Its `reason` is
 * absent only where a dependency of the host's refused and gave none.
 */
export interface Refusal extends Coded {
  readonly valid: false;
  readonly reason?: string;
}

/** A check that passed. */
export interface Passed {
  readonly valid: true;
}

/** What a check comes to: it passed, or it refused with a code. */
export type Checked = Passed | Refusal;

/** The refusal of code `code` for the reason `reason`. */
export function refusal(code: RefusalCode, reason: string): Refusal & { readonly reason: string } {
  return { valid: false, reason, ...coded(code) };
}

/**
 * An error a step throws in its own words when it refuses, with the {@link RefusalCode} it refuses
 * with. The code is not enumerable, so the error compares, prints and serialises as a plain `Error`
 * with the same message does, and a reason taken from its message reads as it did.
 */
export class RefusalError extends Error {
  declare readonly code: RefusalCode;

  constructor(code: RefusalCode, message: string) {
    super(message);
    Object.defineProperty(this, 'code', { value: code, enumerable: false, writable: false, configurable: false });
  }
}

/**
 * The code a refusal for the thrown `error` carries: a {@link RefusalError}'s own code;
 * `deadline_exceeded` for a deadline that passed, the verifier's own or a read's; `host_refused`
 * for a read whose own rules refused its host; and `otherwise` for any other error, a read that
 * failed in its own words included, since what such a failure means depends on what was read.
 */
export function refusalCodeOf(error: unknown, otherwise: RefusalCode): RefusalCode {
  if (error instanceof RefusalError) return error.code;
  if (error instanceof DeadlineExceededError) return 'deadline_exceeded';
  const kind = readFailureKind(error);
  return kind === 'host_refused' || kind === 'deadline_exceeded' ? kind : otherwise;
}

/**
 * The refusal that speaks for a verdict refused for several reasons at once: the first that is not
 * transient, since asking again cannot lift it, else the first. `undefined` when there is none.
 */
export function decidingRefusal(refusals: readonly Coded[]): Coded | undefined {
  return refusals.find((refused) => !refused.transient) ?? refusals[0];
}
