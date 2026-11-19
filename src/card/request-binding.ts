/**
 * KYA-OS Entity Card: the delegation a request proof states, held to the chain its call is
 * authorized under (SPEC.md §7.8, SPEC-ENTITY-CARD §8, §11.4).
 *
 * A card request proof covers `{ method, params }` without `_meta`, and the delegation chain rides in
 * `_meta`, outside `requestHash`. On its own the proof is therefore good beside any chain whose leaf
 * names its DID, and a party on the path that holds another such chain can put it in place of the
 * one the caller chose. So the proof states, in the JWS protected header its signature covers, the
 * SPEC §7.8 digest of the chain's leaf, or `none`, and the delegation check holds the chain it
 * verified to that statement. The leaf's digest covers the `parentCredentialDigest` it states, and
 * so on up, so a chain whose hops state their parents is fixed by its leaf alone.
 *
 * The statement comes from `verifyCardProof`, which reads it from the header that verified. A caller
 * that does not hand it over is read from the proof in the `_meta` it does hand over, which is the
 * same reading when that `_meta` is the one `requireProof` verified.
 */

import { delegationCredentialDigest } from '../delegation/chain-digest.js';
import { NoSignedFormError } from '../delegation/signed-form.js';
import {
  DELEGATION_MISMATCH,
  statedDelegationOf,
  unnamedStatementRefusal,
  type RequestBindingMode,
  type StatedDelegation,
  type StatementRefusal,
} from '../delegation/stated-delegation.js';
import { warnOfUnknownStatement, warnOfUnnamedProof } from '../delegation/unnamed-proof-warning.js';
import { jwsProtectedHeader } from '../utils/crypto-service.js';
import { webCryptoSha256 } from '../utils/domain-digest.js';
import { isRecord } from '../utils/guards.js';
import { readCardProof } from './middleware.js';
import { statedParentDigest } from './parent-digest.js';

/** What a request brings of its proof's statement: the statement itself, or the `_meta` that carried the proof. */
export interface RequestStatementSource {
  meta: unknown;
  proofDid: string;
  statedDelegation?: StatedDelegation;
}

/** A request proof's statement, and whether the request brought any source of it. */
export interface RequestStatement {
  readonly stated: StatedDelegation;
  /** False when neither a statement nor a proof of `proofDid` was handed over, so nothing is known of it. */
  readonly known: boolean;
}

const UNKNOWN: RequestStatement = { stated: { kind: 'absent' }, known: false };

/**
 * What the request proof of `source` states of its delegation: `statedDelegation` as handed over,
 * or else the protected header of the card proof in `meta`, when that proof is `proofDid`'s. A
 * `meta` with no such proof, or one whose header cannot be read, brings no statement.
 */
export function requestStatement(source: RequestStatementSource): RequestStatement {
  if (source.statedDelegation !== undefined) return { stated: source.statedDelegation, known: true };
  const proof = readCardProof(source.meta);
  if (!isRecord(proof) || proof.did !== source.proofDid || typeof proof.jws !== 'string') return UNKNOWN;
  try {
    return { stated: statedDelegationOf(jwsProtectedHeader(proof.jws)), known: true };
  } catch {
    return UNKNOWN;
  }
}

/** Whether `leaf` is the credential digested as `digest`. A leaf with no signed form has no digest, so it is none. */
async function isCredential(leaf: Record<string, unknown>, digest: string): Promise<boolean> {
  try {
    return (await delegationCredentialDigest(leaf, webCryptoSha256)) === digest;
  } catch (error) {
    if (error instanceof NoSignedFormError) return false;
    throw error;
  }
}

/**
 * Why `stated` does not go with the chain whose last credential is `leaf`, or `undefined` when it
 * does. A proof that names a credential goes only with a chain that ends in it, whether the request
 * carried the chain or the verifier resolved it. One that names none stands as
 * `unnamedStatementRefusal` says: beside a carried chain `require` refuses it, and beside a
 * resolved one a proof that says "none" holds.
 *
 * @throws what digesting `leaf` throws, other than for a leaf with no signed form
 */
export async function requestBindingRefusal(
  stated: StatedDelegation,
  leaf: Record<string, unknown>,
  carried: boolean,
  mode: RequestBindingMode,
): Promise<StatementRefusal | undefined> {
  if (stated.kind !== 'credential') return unnamedStatementRefusal(stated, carried, mode);
  return (await isCredential(leaf, stated.digest)) ? undefined : DELEGATION_MISMATCH;
}

/** What a verified chain's grant says of the statement it was held to. */
export interface RequestBinding {
  /** Whether the request proof named the chain's leaf credential. */
  delegationNamed: boolean;
  /** Whether every hop after the root states its parent's digest, so the leaf fixes the whole chain. */
  ancestorsPinned: boolean;
}

/**
 * The {@link RequestBinding} of a chain that was authorized under `statement`, with the warning, once
 * per process, that a call was let through whose proof did not name its delegation.
 */
export function requestBindingOf(statement: RequestStatement, credentials: readonly Record<string, unknown>[]): RequestBinding {
  const delegationNamed = statement.stated.kind === 'credential';
  if (!statement.known) warnOfUnknownStatement();
  else if (statement.stated.kind !== 'malformed') {
    warnOfUnnamedProof({ status: 'bound', named: delegationNamed, claims: { statement: statement.stated } });
  }
  return {
    delegationNamed,
    // Every digest a hop states was checked against the hop before it, so stating one is committing to it.
    ancestorsPinned: credentials.slice(1).every((hop) => statedParentDigest(hop) !== undefined),
  };
}
