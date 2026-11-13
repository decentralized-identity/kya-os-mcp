/**
 * The shape a verification method must have before any key is read from it: a map with a non-empty
 * string `id`, `type` and `controller`, the members W3C Controlled Identifiers v1.0 §2.2 requires of
 * every verification method. It checks no more: not that `id` and `controller` are well-formed URLs,
 * nor any other member. The did:web and cheqd resolvers hold every `verificationMethod` entry of a
 * document they resolve to it, and the relationship retrieval (./verification-relationship) holds
 * every method it retrieves to it, referenced or embedded, as the part of §3.3 step 8 that SPEC.md
 * §6.2 requires. Whether the method carries a usable key is a separate question
 * (./verification-method-key).
 */

import { isRecord } from '../utils/guards.js';
import type { VerificationMethod } from './vc-verifier.types.js';

/** Whether `value` is a map whose `id`, `type` and `controller` are non-empty strings. */
export function hasIdTypeAndController(value: unknown): value is VerificationMethod {
  return isRecord(value) && isNonEmptyString(value.id) && isNonEmptyString(value.type) && isNonEmptyString(value.controller);
}

function isNonEmptyString(value: unknown): boolean {
  return typeof value === 'string' && value.length > 0;
}
