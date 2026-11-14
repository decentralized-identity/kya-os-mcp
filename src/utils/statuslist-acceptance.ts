/**
 * The status-list ACCEPTANCE rule: whether a fetched status list may be read for a status entry.
 * It is the one implementation of the rule, so the readers cannot drift. The readers that verify a
 * list's proof apply all of it: the card revocation checker given `verifyStatusList`, the cheqd
 * status-list resolver and the conformance reference adapter. The readers that verify none, the card
 * checker without `verifyStatusList` and the delegation status-list manager, apply its purpose part
 * alone, since nothing else about the list is authenticated. Each reader decides only whom it trusts.
 *
 * A status list's proof shows only who signed it. W3C Bitstring Status List v1.0 lets that signer
 * differ from the credential's issuer (§2.2), and expects a verifier to trust "the issuer of a
 * verifiable credential, as well as the issuer of the associated BitstringStatusListCredential"
 * (§3.2). Without a check that ties the two together, whoever controls what a status-list URL
 * returns can sign a list of their own with the bit cleared, and its proof verifies. So a list is
 * accepted for an entry only when:
 * - its `issuer` is one the reader accepts for the entry;
 * - its `statusPurpose` includes the entry's (§3.2 step 5), and is one string unless the list is
 *   typed as a Bitstring Status List in both places §2.2 names;
 * - it states, as its `id`, the URL it was fetched from, the entry's `statusListCredential`, byte for
 *   byte (§2.2), unless its issuer is the one issuer the reader accepts and the reader does not
 *   require an `id` (`requireId`).
 *
 * Only the `id` binds a list to the URL it is served at. §2.2 makes it optional, so the rule lets a
 * list leave it out only where its issuer is the only issuer accepted for the entry, and such a list
 * can be served in place of another list its own issuer signed. Where the reader accepts more than
 * one issuer, a pinned root or a configured status issuer, every list must state it: a list of any of
 * them, with the bit clear, could otherwise be served at the URL of a list another of them keeps.
 * Nor does the rule tell versions of one list apart: an earlier version, signed before a credential
 * was revoked, can be served in place of the current one.
 *
 * A reader that holds a list to the credential it covers expects what
 * {@link statusListExpectationFor} names: an issuer {@link acceptedStatusListIssuers} names (the
 * credential's issuer, its chain's root issuer when the verifier pins that root, and any it is
 * configured to accept for the credential's issuer), so a list may leave its `id` out only when the
 * credential's issuer is the one it names. A reader that answers for one purpose alone first holds
 * the entry to it ({@link acceptEntryPurpose}).
 *
 * The rule is pure and checks no proof. It means something only together with a proof verified under
 * a key the list's `issuer` lists under `assertionMethod`: until then, every field it reads, the
 * `issuer` it decides by included, is whatever the server wrote.
 */

import { describeValue } from './describe-value.js';
import { isRecord, issuerOf } from './guards.js';

/**
 * Status-list issuers a verifier accepts for another issuer's credentials, keyed by the credential
 * issuer's DID: `{ 'did:web:acme.example': ['did:web:status.example'] }`. A credential issuer's own
 * lists need no entry. Off by default: with no map, no other issuer is accepted. A deployment whose
 * lists one status service signs names that service for each credential issuer.
 */
export type StatusListIssuers = Readonly<Record<string, readonly string[]>>;

/** The credential whose status a status-list reader checks. */
export interface StatusCheckContext {
  /** The DID of the credential's issuer: its `issuer`, or `issuer.id`. */
  credentialIssuer: string;
  /**
   * The issuer of the first credential of the credential's delegation chain, named only when the
   * verifier pins it (`trustedRootIssuers` or `resourceOwner`), or, for an Entity Card, the Card's
   * responsible party once the Card's accountability check has verified it as that root. The root
   * can revoke its own credential, which revokes every credential below it, so its lists speak for
   * every credential of its chains, each stating its `id`. The issuers between the root and the
   * credential are not named: a credential commits to its parent only by an id the parent's issuer
   * chose, so whoever presents a chain decides who stands between them, while the root is held to
   * the verifier's own configuration.
   */
  trustedRootIssuer?: string;
}

/** What a status entry expects of the list it names. */
export interface StatusListExpectation {
  /** The entry's `statusListCredential`: the URL the list was fetched from. */
  statusListCredential: string;
  /** The entry's `statusPurpose`, which the list's `statusPurpose` must include. */
  statusPurpose: string;
  /** The issuers whose lists may be read for the entry. */
  acceptedIssuers: readonly string[];
  /**
   * Whether every list must state its `id`. Omitted or `false`, a list may leave it out only when its
   * signer is the one issuer accepted.
   */
  requireId?: boolean;
}

/** Whether a status list may be read for an entry and, when it may not, why. */
export type StatusListVerdict = { valid: true } | { valid: false; reason: string };

/**
 * Apply the acceptance rule to `list`, a fetched status-list credential whose proof the caller
 * verifies as well. The list's `issuer` (a string, or an object's `id`) and its stated `id` are
 * compared exactly; its `statusPurpose` is one string, or a non-empty array of strings on a list
 * typed as a Bitstring Status List v1.0 list in both its `type` and its subject's. A `reason`
 * quotes each value it names as `describeValue` does, as a JSON string of at most its first 64
 * characters, and names a value that is not a string by its type alone, never converting it. It
 * names the issuer first, then the purpose, then the `id`.
 */
export function acceptStatusList(list: unknown, expected: StatusListExpectation): StatusListVerdict {
  const fields: Record<string, unknown> = isRecord(list) ? list : {};
  const issuer = issuerOf(fields.issuer);
  return verdict(
    issuerRejection(issuer, expected.acceptedIssuers) ??
      purposeRejection(fields, expected.statusPurpose) ??
      idRejection(fields.id, mayOmitId(issuer, expected), expected.statusListCredential),
  );
}

/**
 * The status-list issuers accepted for the credential `context` names, each once: its issuer, its
 * chain's pinned root issuer, and those `statusListIssuers` lists for its issuer. Only an entry the
 * map owns counts, so an inherited key such as `constructor` adds nobody.
 *
 * @throws TypeError when `statusListIssuers` is malformed, as {@link assertStatusListIssuers} words it.
 */
export function acceptedStatusListIssuers(
  context: StatusCheckContext,
  statusListIssuers?: StatusListIssuers,
): string[] {
  assertStatusListIssuers(statusListIssuers);
  const { credentialIssuer, trustedRootIssuer } = context;
  const configured =
    statusListIssuers !== undefined && Object.prototype.hasOwnProperty.call(statusListIssuers, credentialIssuer)
      ? statusListIssuers[credentialIssuer]
      : undefined;
  return distinct([
    credentialIssuer,
    ...(trustedRootIssuer === undefined ? [] : [trustedRootIssuer]),
    ...(configured ?? []),
  ]);
}

/**
 * The expectation {@link acceptStatusList} holds the list `entry` names to, for the credential
 * `context` names, as each in-tree reader that holds a list to its credential derives it; a custom
 * `StatusListResolver` passes it the same way:
 * `acceptStatusList(list, statusListExpectationFor(status, context, statusListIssuers))`.
 */
export function statusListExpectationFor(
  entry: { statusListCredential: string; statusPurpose: string },
  context: StatusCheckContext,
  statusListIssuers?: StatusListIssuers,
): StatusListExpectation {
  return {
    statusListCredential: entry.statusListCredential,
    statusPurpose: entry.statusPurpose,
    acceptedIssuers: acceptedStatusListIssuers(context, statusListIssuers),
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
 * Throw a `TypeError` unless `statusListIssuers` is absent or a plain object whose own values are
 * arrays of strings. A reader checks it when it is configured: a map it could not apply is a
 * configuration error, never a refusal of each list it reads. {@link acceptedStatusListIssuers}
 * checks it as well, so a reader that skips that check meets this error, not another.
 */
export function assertStatusListIssuers(value: unknown): asserts value is StatusListIssuers | undefined {
  if (value === undefined) return;
  if (!isPlainObject(value)) {
    throw new TypeError(
      'statusListIssuers must be a plain object mapping credential issuer DIDs to arrays of status-list issuer DIDs',
    );
  }
  for (const [credentialIssuer, accepted] of Object.entries(value)) {
    if (!Array.isArray(accepted) || !accepted.every((did) => typeof did === 'string')) {
      throw new TypeError(`statusListIssuers[${describeValue(credentialIssuer)}] must be an array of status-list issuer DIDs`);
    }
  }
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

/** An object literal, `Object.create(null)`, or a frozen one: not an array, a class instance or a `Map`. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!isRecord(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function verdict(reason: string | undefined): StatusListVerdict {
  return reason === undefined ? { valid: true } : { valid: false, reason };
}

/** `values` without repeats, each where it first comes. */
function distinct(values: readonly string[]): string[] {
  return [...new Set(values)];
}

/**
 * How many accepted issuers a refusal names before it counts the rest, so its length does not grow
 * with the verifier's configuration, which the reason would otherwise echo whole.
 */
const NAMED_ISSUERS = 3;

function issuerRejection(issuer: string | undefined, acceptedIssuers: readonly string[]): string | undefined {
  if (!issuer) {
    return 'status list names no issuer';
  }
  if (acceptedIssuers.includes(issuer)) {
    return undefined;
  }
  const accepted = distinct(acceptedIssuers);
  const named = accepted.slice(0, NAMED_ISSUERS).map(describeValue).join(' or ');
  const more = accepted.length > NAMED_ISSUERS ? ` and ${accepted.length - NAMED_ISSUERS} more` : '';
  return `status list issuer ${describeValue(issuer)} is not the expected issuer (${named}${more})`;
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
 * Bitstring Status List in both places; any other list, a StatusList2021 list or one typed as a
 * Bitstring Status List in one place alone, is in no data model that gives an array a meaning, and
 * is refused whatever its array holds.
 */
function purposeRejection(list: Record<string, unknown>, statusPurpose: string): string | undefined {
  const subject: Record<string, unknown> = isRecord(list.credentialSubject) ? list.credentialSubject : {};
  const declared = subject.statusPurpose;
  if (Array.isArray(declared) && !isBitstringStatusList(list.type, subject.type)) {
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
 * Whether a list is typed as a Bitstring Status List v1.0 list in both places its §2.2 names, each
 * as that section states it: a `type` array that includes `BitstringStatusListCredential`, and a
 * subject whose `type` is the string `BitstringStatusList`.
 */
function isBitstringStatusList(type: unknown, subjectType: unknown): boolean {
  return Array.isArray(type) && type.includes('BitstringStatusListCredential') && subjectType === 'BitstringStatusList';
}

/**
 * Whether a list `issuer` signed may leave out its `id`: only when the reader does not require one and
 * every accepted issuer is that signer, so the list can stand in for no list another accepted issuer
 * keeps. The rule reaches this only for an accepted issuer, so it then accepts that issuer alone.
 */
function mayOmitId(issuer: string | undefined, expected: StatusListExpectation): boolean {
  return !expected.requireId && expected.acceptedIssuers.every((accepted) => accepted === issuer);
}

/**
 * `mayOmit`: whether the list may leave its `id` out ({@link mayOmitId}). When the `id` and the URL
 * quote the same once cut, the reason says where they first differ, so it still shows that they do.
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
