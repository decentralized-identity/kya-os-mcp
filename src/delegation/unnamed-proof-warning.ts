/**
 * The warning an enforcement point gives, once per process, when it accepts a request proof that
 * does not name the delegation its call is made under (SPEC.md §7.8): the acceptance `prefer`
 * allows, and `require` and version 2.0.0 refuse.
 */

import type { DelegatedCallProofResult } from './delegated-call-proof.js';
import { warnOncePerProcess } from '../utils/warn-once.js';

/** `Symbol.for` keys, so every copy of the package a process loads warns once between them. */
export const UNNAMED_PROOF_WARNED = Symbol.for('kya-os.warned.request-proof-names-no-delegation');
export const NONE_BESIDE_DELEGATION_WARNED = Symbol.for('kya-os.warned.request-proof-states-none-beside-delegation');
export const NONE_AMONG_GRANTS_WARNED = Symbol.for('kya-os.warned.request-proof-states-none-among-grants');
export const UNKNOWN_STATEMENT_WARNED = Symbol.for('kya-os.warned.request-proof-statement-unknown');

const REMEDY =
  'Set requestBinding to "require" to refuse such a call once every caller states its delegation; version 2.0.0 refuses it by default.';

/**
 * Warn, in fixed words, when `result` is a proof that bound without naming its delegation. Called
 * only where the call is about to be let through.
 */
export function warnOfUnnamedProof(result: Pick<DelegatedCallProofResult, 'status' | 'named' | 'claims'>): void {
  if (result.status !== 'bound' || result.named !== false) return;
  if (result.claims?.statement.kind === 'none') {
    warnOncePerProcess(
      NONE_BESIDE_DELEGATION_WARNED,
      '[kya-os] A request proof that states its call presents no delegation was accepted beside a presented delegation, ' +
        'so the proof is good beside any delegation of its subject. Its caller made the proof before it attached the delegation: ' +
        'it should make the proof from the arguments the call sends, or pass the credential as `delegation`. ' +
        REMEDY,
    );
    return;
  }
  warnOncePerProcess(
    UNNAMED_PROOF_WARNED,
    '[kya-os] A request proof that does not state the delegation its call is made under (SPEC.md §7.8) was accepted, ' +
      'so the proof is good beside any delegation of its subject. A current generateRequestProof or buildCardProof states it. ' +
      REMEDY,
  );
}

/**
 * Warn, in fixed words, that a card delegation check let a call through without knowing what its
 * request proof states: it was handed neither the statement nor the `_meta` that carried the proof.
 */
export function warnOfUnknownStatement(): void {
  warnOncePerProcess(
    UNKNOWN_STATEMENT_WARNED,
    '[kya-os] verifyRequestDelegation authorized a call without knowing which delegation its request proof states (SPEC.md §7.8), ' +
      'so the proof is good beside any delegation of its subject. Pass the `statedDelegation` requireProof returned, ' +
      'or the `_meta` that carried the proof. ' +
      REMEDY,
  );
}

/** Warn, in fixed words, that a call whose proof states `none` ran under one of several delegations retained for its subject. */
export function warnOfNoneAmongGrants(): void {
  warnOncePerProcess(
    NONE_AMONG_GRANTS_WARNED,
    '[kya-os] A call that presented no delegation, and whose request proof names none, ran under the first of the grants ' +
      'retained for its subject, which hold more than one delegation. Its caller should name the one it means by passing ' +
      'the credential to generateRequestProof as `delegation`. ' +
      REMEDY,
  );
}
