/**
 * The status-list ACCEPTANCE rule: whether a fetched status list may be read for a status entry.
 * It is the one implementation of the rule, so the readers cannot drift. The readers that verify a
 * list's proof apply all of it: the card revocation checker given `verifyStatusList`, the cheqd
 * status-list resolver and the conformance reference adapter. The readers that verify none, the card
 * checker without `verifyStatusList` and the delegation status-list manager, apply its purpose part
 * alone, since nothing else about the list is authenticated.
 *
 * A status list's proof shows only who signed it. W3C Bitstring Status List v1.0 lets that signer
 * differ from the credential's issuer (§2.2), and an informative note in its §3.2 has a verifier
 * trust the issuer of the credential as well as the issuer of the list. Without a check that ties
 * the list to the entry, whoever controls what a status-list URL returns can sign a list of their
 * own with the bit cleared, and its proof verifies. So a list is accepted for an entry only when:
 * - its `issuer` is the one keeper of the URL the entry names ({@link statusListKeeperFor}), which
 *   is decided from the verifier's configuration and the signed credentials, never from the list;
 * - its `statusPurpose` includes the entry's (§3.2 step 5), and is one string unless the list is
 *   typed as a Bitstring Status List in both places §2.2 names;
 * - it states, as its `id`, the URL it was fetched from, the entry's `statusListCredential`, byte for
 *   byte (§2.2), unless the reader does not require an `id` (`requireId`).
 *
 * The `id` binds a list to the URL it is served at, and the keeper binds that URL to one signer.
 * §2.2 makes the `id` optional, so the rule lets a list leave it out only where nobody but the
 * credential's own issuer keeps any URL: that issuer signed it, no other root is pinned and the
 * configuration names no issuer but, at most, that one for other URLs
 * ({@link statusListExpectationFor}). Such a list can be served in place of another
 * list its own issuer signed. Nor does the rule tell versions of one list apart: an earlier version,
 * signed before a credential was revoked, can be served in place of the current one.
 *
 * A reader that answers for one purpose alone first holds the entry to it
 * ({@link acceptEntryPurpose}), and a reader that reads one bit per entry first holds the entry to
 * that size ({@link acceptEntrySize}). Every reader, whether or not it verifies a proof, also holds
 * the list to the validity window it states, by the rule in `./statuslist-validity.ts`.
 *
 * The rule is pure and checks no proof. It means something only together with a proof verified under
 * a key the list's `issuer` lists under `assertionMethod`: until then, every field it reads, the
 * `issuer` it decides by included, is whatever the server wrote. A verdict about a list reaches the
 * presenter only once the list's proof verifies, so a reader that asks the rule before the proof
 * refuses with a `NetworkRefusalError` (`./thrown-words.ts`), and its reason goes to the operator's log.
 */

import { describeValue } from './describe-value.js';
import { isRecord, issuerOf } from './guards.js';
import {
  namesAnotherKeeper,
  statusListKeeperFor,
  type StatusCheckContext,
  type StatusListIssuers,
  type StatusListKeeper,
} from './statuslist-keeper.js';
import { statusListFormatOf } from './statuslist-format.js';

export {
  assertStatusListIssuers,
  statusListKeeperFor,
  type StatusCheckContext,
  type StatusListIssuers,
  type StatusListKeeper,
} from './statuslist-keeper.js';

/** What a status entry expects of the list it names. */
export interface StatusListExpectation {
  /** The entry's `statusListCredential`: the URL the list was fetched from. */
  statusListCredential: string;
  /** The entry's `statusPurpose`, which the list's `statusPurpose` must include. */
  statusPurpose: string;
  /** The one issuer whose list is read at that URL. */
  keeper: StatusListKeeper;
  /** Whether the list must state its `id`. */
  requireId: boolean;
}

/** Whether a status list may be read for an entry and, when it may not, why. */
export type StatusListVerdict = { valid: true } | { valid: false; reason: string };

/**
 * Apply the acceptance rule to `list`, a fetched status-list credential whose proof the caller
 * verifies as well. The list's `issuer` (a string, or an object's `id`) must be the keeper's DID,
 * and it and the list's stated `id` are compared exactly; its `statusPurpose` is one string, or a
 * non-empty array of strings on a list typed as a Bitstring Status List v1.0 list in both its `type`
 * and its subject's. A `reason` quotes each value it names as `describeValue` does, as a JSON string
 * of at most its first 64 characters, and names a value that is not a string by its type alone,
 * never converting it. It names the issuer first, with the keeper and why it keeps the URL, then
 * the purpose, then the `id`.
 */
export function acceptStatusList(list: unknown, expected: StatusListExpectation): StatusListVerdict {
  const fields: Record<string, unknown> = isRecord(list) ? list : {};
  return verdict(
    keeperRejection(issuerOf(fields.issuer), expected.keeper) ??
      purposeRejection(fields, expected.statusPurpose) ??
      idRejection(fields.id, !expected.requireId, expected.statusListCredential),
  );
}

/**
 * The expectation {@link acceptStatusList} holds the list `entry` names to, for the credential
 * `context` names, as each in-tree reader that holds a list to its credential derives it; a custom
 * `StatusListResolver` passes it the same way:
 * `acceptStatusList(list, statusListExpectationFor(status, context, statusListIssuers))`.
 *
 * The list must come from the keeper of the entry's URL ({@link statusListKeeperFor}). It may leave
 * out its `id` only when all of these hold: that keeper is the credential's own issuer, and not
 * because the configuration binds the URL to it, but as the issuer of the credential or as the
 * pinned root whose own credential this is; no root is pinned but that same issuer; and the
 * configuration names no other issuer. Then the credential's issuer is the only issuer whose list
 * the reader would take at any URL, so a list without an `id` can stand in for no list another
 * issuer keeps. A pinned root's list is thus read without an `id` for the root's own credential,
 * and for no credential below it, whose issuer the root is not.
 *
 * @throws TypeError when `statusListIssuers` is malformed, as {@link assertStatusListIssuers} words it.
 */
export function statusListExpectationFor(
  entry: { statusListCredential: string; statusPurpose: string },
  context: StatusCheckContext,
  statusListIssuers?: StatusListIssuers,
): StatusListExpectation {
  const keeper = statusListKeeperFor(entry.statusListCredential, context, statusListIssuers);
  const { credentialIssuer, trustedRootIssuer } = context;
  // No binding names the keeper: it is the credential's issuer or the pinned root. The next line
  // holds the root to being that same issuer, so the keeper is then the credential's own issuer.
  const unbound = keeper.why === 'credential-issuer' || keeper.why === 'root-credential';
  const aloneAsIssuer =
    unbound &&
    (trustedRootIssuer === undefined || trustedRootIssuer === credentialIssuer) &&
    !namesAnotherKeeper(statusListIssuers, credentialIssuer);
  return {
    statusListCredential: entry.statusListCredential,
    statusPurpose: entry.statusPurpose,
    keeper,
    requireId: !aloneAsIssuer,
  };
}

/**
 * Whether a checker that answers for `checkerPurpose` alone may read an entry that states
 * `statusPurpose`. An entry that states none, as a Card's `revocation` entry, is read for the
 * checker's purpose, and so is one that states that purpose. One that states another, or a value
 * that is not a string, `null` included (Bitstring Status List v1.0 §2.1 has it a string), says
 * nothing about the checker's purpose, so the checker refuses it before it fetches any list.
 */
export function acceptEntryPurpose(statusPurpose: unknown, checkerPurpose: string): StatusListVerdict {
  return verdict(
    statusPurpose === undefined || statusPurpose === checkerPurpose
      ? undefined
      : `the entry's statusPurpose is ${describeValue(statusPurpose)}, not the checker's ${describeValue(checkerPurpose)}`,
  );
}

/**
 * Whether a reader that reads one bit per entry may read an entry that states `statusSize`. W3C
 * Bitstring Status List v1.0 §2.1 has the member optional: "If present, statusSize MUST be an
 * integer greater than zero", and an entry that states none "MUST be processed as 1". Its §3.2
 * (Validate Algorithm, step 10) reads an entry's status as "the value in the bitstring at the
 * position indicated by the credentialIndex multiplied by the size", so the bit at the index of a
 * wider entry is another entry's. §2.1 describes the `revocation` and `suspension` purposes as one
 * status bit each and gives entries of several values to the `message` purpose, so a reader that
 * answers revoked or not for one of those purposes reads only an entry that states no size, or
 * states 1. Every other is refused before any list is fetched: one stating a value that is not an
 * integer greater than zero as malformed, with nothing converted, and one stating a greater integer
 * as wider than the reader reads. Every status-list reader in the library asks here, so the
 * decision is made once.
 */
export function acceptEntrySize(statusSize: unknown): StatusListVerdict {
  if (statusSize === undefined || statusSize === 1) return verdict(undefined);
  if (Number.isInteger(statusSize) && (statusSize as number) > 0) {
    return verdict(`the entry's statusSize is ${String(statusSize)}, and only an entry of one bit is read`);
  }
  const stated = typeof statusSize === 'number' ? String(statusSize) : describeValue(statusSize);
  return verdict(`the entry's statusSize (${stated}) is not an integer greater than zero`);
}

/**
 * The `statusPurpose` part of the rule alone, for a reader that verifies no proof and so cannot hold
 * the list to an issuer or an `id`. A list of a DIFFERENT kind (e.g. a `suspension` list read as
 * `revocation`) must not be accepted: its clear bit would otherwise report "not revoked" from the
 * wrong list, a fail-open bypass. The list's types decide, as in {@link acceptStatusList}, whether
 * it may state its purposes as an array.
 */
export function acceptStatusPurpose(list: unknown, statusPurpose: string): StatusListVerdict {
  return verdict(purposeRejection(isRecord(list) ? list : {}, statusPurpose));
}

function verdict(reason: string | undefined): StatusListVerdict {
  return reason === undefined ? { valid: true } : { valid: false, reason };
}

/** Why a keeper keeps a URL, as a refusal says it after "as". */
const KEEPS_AS: Record<StatusListKeeper['why'], string> = {
  'configured-url': 'the issuer statusListIssuers binds this URL to',
  'configured-origin': "the issuer statusListIssuers binds this URL's origin to",
  'root-credential': 'the pinned root whose own credential names it',
  'credential-issuer': 'the issuer of the credential',
  'resolver-issuer': 'the issuer this resolver is configured with',
};

/** Why a list `issuer` signed may not be read at a URL `keeper` keeps, if it may not. */
function keeperRejection(issuer: string | undefined, keeper: StatusListKeeper): string | undefined {
  if (!issuer) {
    return 'status list names no issuer';
  }
  if (issuer === keeper.did) {
    return undefined;
  }
  return (
    `status list issuer ${describeValue(issuer)} does not keep this list's URL: ` +
    `${describeValue(keeper.did)} does, as ${KEEPS_AS[keeper.why]}`
  );
}

/**
 * Why `list` may not be read for an entry whose purpose is `statusPurpose`, if it may not. A list
 * states its `statusPurpose` in the form the data model its types name allows, so the rule reads
 * those types from the list itself. Bitstring Status List v1.0 §2.2 names its lists by two types,
 * "The verifiable credential that contains the status list MUST express a type property that
 * includes the BitstringStatusListCredential value." and "The type of the credential subject, which
 * is the status list, MUST be BitstringStatusList.", and lets such a list state several purposes:
 * "The value of the purpose property of the status entry, statusPurpose, MUST be one or more
 * strings." Verifiable Credentials Status List v2021 §2.2 has its lists state one: "The purpose of
 * the status entry MUST be a string." So a list may state an array only when it is typed as a
 * Bitstring Status List in both places, as {@link statusListFormatOf} reads them; any other list, a
 * StatusList2021 list or one typed as a Bitstring Status List in one place alone, is in no data
 * model that gives an array a meaning, and is refused whatever its array holds.
 */
function purposeRejection(list: Record<string, unknown>, statusPurpose: string): string | undefined {
  const subject: Record<string, unknown> = isRecord(list.credentialSubject) ? list.credentialSubject : {};
  const declared = subject.statusPurpose;
  if (Array.isArray(declared) && statusListFormatOf(list) !== 'BitstringStatusList') {
    return (
      'status list statusPurpose is an array, which only a BitstringStatusListCredential with a ' +
      `BitstringStatusList subject may state (the entry's is ${describeValue(statusPurpose)})`
    );
  }
  const purposes: unknown = typeof declared === 'string' ? [declared] : declared;
  if (!Array.isArray(purposes) || purposes.length === 0 || !purposes.every((p) => typeof p === 'string')) {
    return `status list has no statusPurpose (the entry's is ${describeValue(statusPurpose)})`;
  }
  if (!purposes.includes(statusPurpose)) {
    return (
      `status list statusPurpose mismatch: the list's is ${describeValue(declared)} ` +
      `and the entry's is ${describeValue(statusPurpose)}`
    );
  }
  return undefined;
}

/**
 * `mayOmit`: whether the list may leave its `id` out, which is when the reader does not require
 * one. When the `id` and the URL quote the same once cut, the reason says where they first differ,
 * so it still shows that they do.
 */
function idRejection(listId: unknown, mayOmit: boolean, statusListCredential: string): string | undefined {
  if (listId === undefined ? mayOmit : listId === statusListCredential) {
    return undefined;
  }
  const fetchedFrom = describeValue(statusListCredential);
  if (listId === undefined) {
    return `status list states no id, but must state the URL it was fetched from (${fetchedFrom})`;
  }
  const stated = describeValue(listId);
  const where =
    typeof listId === 'string' && stated === fetchedFrom
      ? `; they first differ at character ${firstDifference(listId, statusListCredential)}`
      : '';
  return `status list id ${stated} is not the URL it was fetched from (${fetchedFrom})${where}`;
}

/**
 * The position, counted in code points from 1 as `describeValue` counts them, of the first character
 * at which two different strings differ, or at which the shorter one ends.
 */
function firstDifference(a: string, b: string): number {
  const other = b[Symbol.iterator]();
  let position = 1;
  for (const character of a) {
    if (character !== other.next().value) return position;
    position += 1;
  }
  return position;
}
