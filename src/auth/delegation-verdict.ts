/**
 * How the handshake reads what the host's `DelegationVerifier` answers. The verifier decides
 * whether an agent is authorized, and one written in JavaScript, or one with a fault, can answer
 * anything, so its answer is read by the rule every verdict of the shape `{ valid, reason }` is
 * (`utils/verdict.ts`), and the delegation it names must be an object.
 */

import type { RefusalCoding } from '../delegation/vc-verifier.types.js';
import { isRecord } from '../utils/guards.js';
import type { Refusal } from '../utils/refusal.js';
import { readVerdict, verdictReadThrew } from '../utils/verdict.js';
import type { VerifyDelegationResult } from './types.js';

const WHO = 'the delegation verifier';

/** A `DelegationVerifier`'s answer as the handshake reads it: its code, when it has one, is one of the catalog's. */
export type DelegationVerdict = Omit<VerifyDelegationResult, 'code' | 'transient'> & RefusalCoding;

/** The handshake's refusal for `verdict`: its reason, when it has one, its code and whether that is transient. */
function handshakeRefusal(verdict: Refusal): DelegationVerdict {
  const { code, transient } = verdict;
  return verdict.reason === undefined ? { valid: false, code, transient } : { valid: false, reason: verdict.reason, code, transient };
}

/**
 * The result `answer` comes to. It is valid only when `answer` is an object whose `valid` is the
 * literal `true` and whose `delegation` is an object; its `credential` is kept when that is an
 * object too. A literal `false` is a refusal with the answer's `reason` and its `code`, else
 * `delegation_invalid`; a valid answer that names no delegation is a refusal with neither; and any
 * other answer is a `runtime_error` refusal whose reason says the verdict could not be read. Each
 * member is read once, and no answer makes this throw.
 */
export function readDelegationVerdict(answer: unknown): DelegationVerdict {
  const verdict = readVerdict(WHO, answer, 'delegation_invalid');
  if (!verdict.valid) return handshakeRefusal(verdict);
  let delegation: unknown;
  let credential: unknown;
  try {
    ({ delegation, credential } = answer as Record<string, unknown>);
  } catch {
    return handshakeRefusal(verdictReadThrew(WHO));
  }
  if (!isRecord(delegation)) return { valid: false };
  return {
    valid: true,
    delegation: delegation as unknown as VerifyDelegationResult['delegation'],
    ...(isRecord(credential) ? { credential: credential as VerifyDelegationResult['credential'] } : {}),
  };
}
