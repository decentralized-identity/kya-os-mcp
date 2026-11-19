/**
 * The delegation a request proof states (SPEC.md §7.8).
 *
 * A holder's request proof covers the tool name and the business arguments. The delegation rides
 * beside it, outside the request hash, so on its own the proof is good beside any delegation of its
 * subject, and a party on the path that holds another of them can put it in place of the one the
 * holder chose, or take the delegation away, without any key. The holder therefore states which
 * credential the call presents in the proof's JWS protected header, under
 * {@link DELEGATION_HEADER_PARAMETER}: the SPEC §7.8 digest of that credential, in the form it is
 * sent, or {@link NO_DELEGATION} when the call presents none. The header is part of the signing
 * input, so the statement cannot be changed or removed without the holder's key, and a verifier that
 * does not know the parameter ignores it (RFC 7515 §4), so a proof that carries it verifies wherever
 * one without it does.
 *
 * A statement names the presented credential alone. The ancestors of a re-delegation are fixed by
 * the parent digest each hop states (`./parent-commitment.ts`), which the presented credential's
 * digest covers, so a holder need not know them.
 *
 * Pure: no transport, no framework, no key material.
 */

import { delegationCredentialDigest, type ReceivedCredential, type Sha256 } from './chain-digest.js';
import { isDigest } from './digest-form.js';
import { NoSignedFormError } from './signed-form.js';
import { describeOptionValue } from '../utils/describe-value.js';
import type { Digest } from '../audit/types.js';

/** The JWS protected header parameter a request proof states its delegation in. */
export const DELEGATION_HEADER_PARAMETER = 'org.kya-os/delegation';

/** What a proof states for a call that presents no delegation. */
export const NO_DELEGATION = 'none';

/**
 * What a proof's protected header states of the delegation its call presents: the digest of one
 * credential, that the call presents none, nothing at all (a proof made before the parameter
 * existed), or a value that is neither a digest nor {@link NO_DELEGATION}.
 */
export type StatedDelegation =
  | { readonly kind: 'credential'; readonly digest: Digest }
  | { readonly kind: 'none' }
  | { readonly kind: 'absent' }
  | { readonly kind: 'malformed' };

/**
 * How a verifier takes a proof that does not name the credential presented beside it: `prefer`
 * accepts it, and `require` refuses it. A proof that names another credential, or states a
 * malformed value, is refused under both.
 */
export type RequestBindingMode = 'prefer' | 'require';

/** Why a proof's statement does not go with what a call presented. */
export interface StatementRefusal {
  readonly cause:
    | 'delegation_mismatch'
    | 'delegation_statement_malformed'
    | 'delegation_stated_none'
    | 'delegation_unnamed';
  readonly reason: string;
}

/**
 * The value a holder writes under {@link DELEGATION_HEADER_PARAMETER} for `delegation`: the
 * credential the call presents, as it is sent (an object, or a VC-JWT by its string), or
 * {@link NO_DELEGATION} for a call that presents none.
 *
 * @throws {NoSignedFormError} for a credential with no signed form (SPEC §7.8), which has no digest
 */
export async function delegationStatement(delegation: ReceivedCredential, hash: Sha256): Promise<string> {
  return delegation === NO_DELEGATION ? NO_DELEGATION : delegationCredentialDigest(delegation, hash);
}

/**
 * The protected header parameters a holder's proof states its delegation with.
 *
 * `delegation` is the holder's own word for what the call presents, a credential or
 * {@link NO_DELEGATION}: it is always stated, and one with no signed form throws. Left out, the
 * statement is made from `sent`, the delegation found in the request the proof is made for: its
 * digest, or {@link NO_DELEGATION} when the request sends none (`undefined` or `null`). A delegation
 * the request sends that has no signed form has no digest, and its verifier refuses it whatever the
 * proof says, so the proof then states nothing.
 *
 * @throws {NoSignedFormError} for a `delegation` with no signed form (SPEC §7.8)
 */
export async function statementParameters(
  delegation: ReceivedCredential | undefined,
  sent: unknown,
  hash: Sha256,
): Promise<Record<string, string>> {
  if (delegation !== undefined) return { [DELEGATION_HEADER_PARAMETER]: await delegationStatement(delegation, hash) };
  if (sent === undefined || sent === null) return { [DELEGATION_HEADER_PARAMETER]: NO_DELEGATION };
  try {
    return { [DELEGATION_HEADER_PARAMETER]: await delegationCredentialDigest(sent as ReceivedCredential, hash) };
  } catch (error) {
    if (error instanceof NoSignedFormError) return {};
    throw error;
  }
}

/**
 * What `protectedHeader` states. Give it the header a signature verified over, never one read from
 * a proof that has not verified: the statement binds nothing until the holder's signature covers it.
 * Only a member the header holds itself is read.
 */
export function statedDelegationOf(protectedHeader: Readonly<Record<string, unknown>> | undefined): StatedDelegation {
  if (protectedHeader === undefined || !Object.hasOwn(protectedHeader, DELEGATION_HEADER_PARAMETER)) {
    return { kind: 'absent' };
  }
  const value = protectedHeader[DELEGATION_HEADER_PARAMETER];
  if (value === NO_DELEGATION) return { kind: 'none' };
  return isDigest(value) ? { kind: 'credential', digest: value } : { kind: 'malformed' };
}

/** The refusal of a proof that names another credential than the one its call is decided under. */
export const DELEGATION_MISMATCH: StatementRefusal = {
  cause: 'delegation_mismatch',
  reason: 'Request proof names another delegation than the one presented',
};

/** A statement that names no credential: the only kinds whose standing turns on the mode. */
export type UnnamedStatement = Exclude<StatedDelegation, { kind: 'credential' }>;

/**
 * Why `stated`, which names no credential, does not go with a call that did or did not present one,
 * or `undefined` when it does. A malformed statement is refused. Beside a presented credential, one
 * that says "none", or says nothing, does not name it: `require` refuses it and `prefer` takes it,
 * since a holder that signed only its business arguments and attached its delegation afterwards
 * says "none" without meaning it, and one on an earlier release says nothing. Beside no credential,
 * "none" holds, and saying nothing is refused under `require`.
 */
export function unnamedStatementRefusal(
  stated: UnnamedStatement,
  presented: boolean,
  mode: RequestBindingMode,
): StatementRefusal | undefined {
  if (stated.kind === 'malformed') {
    return {
      cause: 'delegation_statement_malformed',
      reason: 'Request proof states its delegation as neither a credential digest nor "none"',
    };
  }
  if (mode === 'prefer') return undefined;
  if (stated.kind === 'absent') {
    return {
      cause: 'delegation_unnamed',
      reason: 'Request proof does not state the delegation the call is made under, which this server requires',
    };
  }
  return presented
    ? { cause: 'delegation_stated_none', reason: 'Request proof states that the call presents no delegation, but one was presented' }
    : undefined;
}

/**
 * Why `stated` does not go with a call that presented the credential digested as `presented`, or
 * `null` for one that presented none, or `undefined` when it does. A statement of another
 * credential than the one presented is refused under either mode, and one that names no credential
 * stands as {@link unnamedStatementRefusal} says. Beside no credential, a statement that names one
 * holds here, and the caller then authorizes the call only under authority it retains for that
 * credential.
 */
export function statementRefusal(
  stated: StatedDelegation,
  presented: Digest | null,
  mode: RequestBindingMode,
): StatementRefusal | undefined {
  if (stated.kind !== 'credential') return unnamedStatementRefusal(stated, presented !== null, mode);
  return presented === null || stated.digest === presented ? undefined : DELEGATION_MISMATCH;
}

/**
 * `value` as a {@link RequestBindingMode}, `prefer` when it is left out.
 *
 * @throws {TypeError} naming `option` for any other value, so a mistyped mode is never read as `prefer`
 */
export function requestBindingMode(value: unknown, option: string): RequestBindingMode {
  if (value === undefined) return 'prefer';
  if (value === 'prefer' || value === 'require') return value;
  throw new TypeError(`[kya-os] ${option} must be "prefer" or "require" (got ${describeOptionValue(value)})`);
}
