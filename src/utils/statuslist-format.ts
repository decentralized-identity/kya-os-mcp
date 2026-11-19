/**
 * The two STATUS-LIST FORMATS, each in the terms of its own specification, in one place for the
 * issuer that writes them and the readers that tell them apart.
 *
 * `BitstringStatusList` is W3C Bitstring Status List v1.0, a Recommendation: a
 * `BitstringStatusListCredential`, a Verifiable Credentials Data Model 2.0 document whose subject is
 * a `BitstringStatusList`, named by `BitstringStatusListEntry` entries (its §2.1 and §2.2).
 * `StatusList2021` is its predecessor, Verifiable Credentials Status List v2021: a
 * `StatusList2021Credential` of the Data Model 1.1 whose subject is a `StatusList2021`, named by
 * `StatusList2021Entry` entries. A format is named by its subject's `type`; its credential's type is
 * that name followed by `Credential`, and its entry's is that name followed by `Entry`.
 *
 * Both state one window, the 2.0 model as `validFrom` and `validUntil` and the 1.1 model as
 * `issuanceDate` and `expirationDate`. Only a `BitstringStatusList` has a `ttl`.
 */

import type { CredentialStatus, StatusListCredential } from '../types/protocol.js';
import { isRecord } from './guards.js';

/** A status-list format, by the `type` of its list's subject. */
export type StatusListFormat = 'StatusList2021' | 'BitstringStatusList';

/**
 * The status entry of a list of format `F`: a `CredentialStatus` whose `type` names that format, so
 * an entry of a `BitstringStatusList` is one a card delegation credential may state, as written.
 */
export interface StatusListEntryOf<F extends StatusListFormat> extends CredentialStatus {
  type: `${F}Entry`;
}

/**
 * The fewest entries a `BitstringStatusList` may hold: "The uncompressed bitstring MUST be at least
 * 16KB in size." (Bitstring Status List v1.0 §2.2).
 */
export const MIN_BITSTRING_ENTRIES = 131_072;

/** What one format writes where the other writes something else. */
interface FormatTerms {
  /** The `@context` of a list. */
  readonly context: readonly string[];
  /** The member a list states the start of its window in. */
  readonly validFrom: 'issuanceDate' | 'validFrom';
  /** The member a list states the end of its window in. */
  readonly validUntil: 'expirationDate' | 'validUntil';
}

const TERMS: Readonly<Record<StatusListFormat, FormatTerms>> = {
  StatusList2021: {
    context: ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'],
    validFrom: 'issuanceDate',
    validUntil: 'expirationDate',
  },
  BitstringStatusList: {
    context: ['https://www.w3.org/ns/credentials/v2'],
    validFrom: 'validFrom',
    validUntil: 'validUntil',
  },
};

/** Every format, the one the 1.x line writes by default first. */
export const STATUS_LIST_FORMATS = Object.keys(TERMS) as readonly StatusListFormat[];

/**
 * The format `document` is typed as in both places its specification names, each as that
 * specification states it: a `type` array that includes the credential's type, and a subject whose
 * `type` is the string that names the list. `undefined` for a document typed as neither, or as one
 * in one place alone, which is in no data model.
 */
export function statusListFormatOf(document: unknown): StatusListFormat | undefined {
  if (!isRecord(document) || !Array.isArray(document.type) || !isRecord(document.credentialSubject)) return undefined;
  const { type, credentialSubject } = document;
  return STATUS_LIST_FORMATS.find((format) => credentialSubject.type === format && type.includes(`${format}Credential`));
}

/** The member a list of `format` states the end of its window in. */
export function validUntilMemberOf(format: StatusListFormat): FormatTerms['validUntil'] {
  return TERMS[format].validUntil;
}

/** What a new list states, whatever its format. */
export interface NewStatusList {
  /** The URL the list is served at, which it states as its `id`. */
  readonly id: string;
  /** The DID of the issuer that signs it. */
  readonly issuer: string;
  readonly statusPurpose: 'revocation' | 'suspension';
  readonly encodedList: string;
  /** When the list is first valid, an RFC 3339 date-time. */
  readonly validFrom: string;
}

/**
 * A list of `format`, not yet signed: its context, its types, its one purpose, and the start of its
 * window in the member its data model has. Bitstring Status List v1.0 §2.2 lets a list state "one or
 * more strings" as its purpose, and each list here has one.
 */
export function unsignedStatusList(format: StatusListFormat, list: NewStatusList): StatusListCredential {
  const terms = TERMS[format];
  // The compiler cannot tie a member named by `terms` to `format`; the format tests pin each list whole.
  return {
    '@context': [...terms.context],
    id: list.id,
    type: ['VerifiableCredential', `${format}Credential`],
    issuer: list.issuer,
    [terms.validFrom]: list.validFrom,
    credentialSubject: {
      id: `${list.id}#list`,
      type: format,
      statusPurpose: list.statusPurpose,
      encodedList: list.encodedList,
    },
  } as StatusListCredential;
}

/**
 * The entry at `index` of the list at `statusListCredential`, as a credential of `format` states
 * it. Its `id` is the list's URL with the index as its fragment, so it is never "the URL for the
 * status list" (Bitstring Status List v1.0 §2.1), and its purpose is one string, the list's.
 */
export function statusListEntry<F extends StatusListFormat>(
  format: F,
  statusListCredential: string,
  index: number,
  statusPurpose: 'revocation' | 'suspension',
): StatusListEntryOf<F> {
  return {
    id: `${statusListCredential}#${index}`,
    type: `${format}Entry` as const,
    statusPurpose,
    statusListIndex: index.toString(),
    statusListCredential,
  };
}
