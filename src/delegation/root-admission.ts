/**
 * Admission of a delegation chain's root by the issuer it names. The chain walk asks before it
 * verifies any credential, so a root whose issuer is not trusted costs no DID, signature or status
 * resolution. Admission is not authentication: verifying the root afterwards checks its proof with
 * a key from the document of this same issuer, so an admitted root is signed by a trusted issuer.
 */

import type { DelegationCredential } from '../types/protocol.js';
import { describeValue } from '../utils/describe-value.js';
import { credentialIssuerDid, credentialIssuerRefusal } from './credential-issuer.js';

/**
 * Why `root` is refused under `trustedRootIssuers`, or `undefined` when it is admitted or no list is
 * set. A list that {@link trustedRootIssuersRefusal} refuses refuses every root. The issuer is the
 * credential's own `issuer` ({@link credentialIssuerDid}), never the `issuerDid` its delegation
 * claims, and the reason quotes it as {@link describeValue} does, since nothing has authenticated
 * it yet; a root naming no issuer string gets the verifier's basic-stage reason, as it would when
 * verified.
 */
export function rootAdmissionRefusal(
  root: DelegationCredential,
  trustedRootIssuers: readonly string[] | undefined,
): string | undefined {
  if (trustedRootIssuers === undefined) return undefined;
  const invalidList = trustedRootIssuersRefusal(trustedRootIssuers);
  if (invalidList !== undefined) return invalidList;
  const issuer = credentialIssuerDid(root);
  const id = root.credentialSubject.delegation.id;
  if (issuer === undefined) return `Delegation ${id} invalid: ${credentialIssuerRefusal(root)}`;
  if (admitsRootIssuer(trustedRootIssuers, issuer)) return undefined;
  return `Root delegation ${id} is issued by ${describeValue(issuer)}, which is not a trusted root issuer`;
}

/**
 * Whether `trustedRootIssuers`, a list {@link trustedRootIssuersRefusal} accepts, admits a root
 * issued by `issuer`: no list admits every issuer, and a list only one of its entries, compared
 * whole. The gate's chain walk and the Card's request check both decide by it.
 */
export function admitsRootIssuer(trustedRootIssuers: readonly string[] | undefined, issuer: string): boolean {
  return trustedRootIssuers === undefined || trustedRootIssuers.includes(issuer);
}

/**
 * Why `value` cannot be a `trustedRootIssuers` list, or `undefined` when it is one: an array of
 * DIDs, each a string that starts with `did:` and has no white space around it, compared whole
 * against a root's issuer. `null` and a string are refused, not read as "no list" or as text to
 * search, so a configuration mistake never admits a root; an entry that could never equal an
 * issuer, such as one with a trailing space, is refused too, so it never refuses every root unseen.
 */
export function trustedRootIssuersRefusal(value: unknown): string | undefined {
  const got = listDefect(value);
  if (got === undefined) return undefined;
  return `trustedRootIssuers must be an array of DIDs, each a string that starts with "did:" and has no white space around it (got ${got})`;
}

/**
 * Throw a `TypeError` naming the option, as `[kya-os] <path>trustedRootIssuers ...`, for a value
 * {@link trustedRootIssuersRefusal} refuses, where an API receives the option. `undefined` sets no
 * list and passes.
 */
export function assertTrustedRootIssuers(value: unknown, path = ''): void {
  const refusal = value === undefined ? undefined : trustedRootIssuersRefusal(value);
  if (refusal !== undefined) throw new TypeError(`[kya-os] ${path}${refusal}`);
}

function listDefect(value: unknown): string | undefined {
  if (typeof value === 'string') return 'a string';
  if (!Array.isArray(value)) return `a value ${describeValue(value)}`;
  for (const entry of value as unknown[]) {
    if (!isListedDid(entry)) return `an array with an entry ${describeValue(entry)}`;
  }
  return undefined;
}

/** Whether `entry` names a DID as a list must: a string that starts with `did:`, with no white space around it. */
function isListedDid(entry: unknown): boolean {
  return typeof entry === 'string' && entry.startsWith('did:') && entry.trim() === entry;
}
