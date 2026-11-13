/**
 * The status-list acceptance rule over this finite partition: every combination of who signed a
 * list, how the list names its issuer, the `id` it states, how it is typed, the `statusPurpose` it
 * states, and the one its entry states, for a list fetched from a URL with a query and from one
 * without. Each runs through the rule as the card revocation checker applies it
 * ({@link acceptEntryPurpose}, then {@link acceptStatusList} with the expectation
 * {@link statusListExpectationFor} builds), and its verdict is compared with the decision table
 * below, which is written from the specifications and never asks the rule:
 * - who may sign the list: SPEC.md §6.6, and SPEC-ENTITY-CARD.md §10.3 for a Card's responsible
 *   party, which counts once the Card's accountability check has verified it;
 * - the `id`: it binds a list to the URL it is fetched from, byte for byte, and only the
 *   credential's own issuer's list may leave it out, and only when that issuer is the one issuer
 *   accepted for the credential (SPEC.md §6.6, Bitstring Status List v1.0 §2.2);
 * - the list's `statusPurpose`: it includes the purpose checked (Bitstring Status List v1.0 §3.2),
 *   in a form the list's data model allows. Verifiable Credentials Status List v2021 §2.2 has a
 *   StatusList2021Credential's be one string: "The purpose of the status entry MUST be a string."
 *   Bitstring Status List v1.0 §2.2 has it be "one or more strings" on a list typed as one in both
 *   places it names: "The verifiable credential that contains the status list MUST express a type
 *   property that includes the BitstringStatusListCredential value." and "The type of the credential
 *   subject, which is the status list, MUST be BitstringStatusList." A list typed so in one place
 *   alone, or in neither, is in neither data model, and states one string as well;
 * - the entry's `statusPurpose`: a string (§2.1), which must be the checker's purpose, or absent, as
 *   on a Card's `revocation` entry, when the checker's applies (SPEC.md §6.10).
 */

import { describe, it, expect } from 'vitest';
import {
  acceptEntryPurpose,
  acceptStatusList,
  statusListExpectationFor,
  type StatusCheckContext,
  type StatusListIssuers,
  type StatusListVerdict,
} from '../statuslist-acceptance.js';

/** A member a list or an entry leaves out. */
const ABSENT = Symbol('absent');

const CHECKED = 'revocation';
const OTHER_PURPOSE = 'suspension';

const CREDENTIAL_ISSUER = 'did:web:issuer.example';
const CARD = 'did:web:example.com:agents:acme-pay';
const ROOT = 'did:web:root.example';
const SERVICE = 'did:web:status.example';
const RESPONSIBLE_PARTY = 'did:web:api.example';
const STRANGER = 'did:web:stranger.example';

interface SignerRow {
  /** Whether the specification lets a list this signer signed speak for the credential. */
  accepted: boolean;
  /**
   * Whether this signer's list may leave out its `id`: only the credential's own issuer's may, and
   * only when no other issuer is accepted for the credential.
   */
  mayOmitId: boolean;
  did: string;
  /** The context, and the configuration, the verifier checks the list with. */
  context: StatusCheckContext;
  statusListIssuers?: StatusListIssuers;
}

const SIGNERS: Record<string, SignerRow> = {
  "the credential's own issuer, the one issuer accepted for it": {
    accepted: true,
    mayOmitId: true,
    did: CREDENTIAL_ISSUER,
    context: { credentialIssuer: CREDENTIAL_ISSUER },
  },
  "the credential's own issuer, while the verifier pins a root": {
    accepted: true,
    mayOmitId: false,
    did: CREDENTIAL_ISSUER,
    context: { credentialIssuer: CREDENTIAL_ISSUER, trustedRootIssuer: ROOT },
  },
  "the credential's own issuer, while the verifier accepts a status service for it": {
    accepted: true,
    mayOmitId: false,
    did: CREDENTIAL_ISSUER,
    context: { credentialIssuer: CREDENTIAL_ISSUER },
    statusListIssuers: { [CREDENTIAL_ISSUER]: [SERVICE] },
  },
  'the pinned root': {
    accepted: true,
    mayOmitId: false,
    did: ROOT,
    context: { credentialIssuer: CREDENTIAL_ISSUER, trustedRootIssuer: ROOT },
  },
  'a root that is not pinned': {
    accepted: false,
    mayOmitId: false,
    did: ROOT,
    context: { credentialIssuer: CREDENTIAL_ISSUER },
  },
  'a status service configured for the credential issuer': {
    accepted: true,
    mayOmitId: false,
    did: SERVICE,
    context: { credentialIssuer: CREDENTIAL_ISSUER },
    statusListIssuers: { [CREDENTIAL_ISSUER]: [SERVICE] },
  },
  "a Card's verified responsible party": {
    accepted: true,
    mayOmitId: false,
    did: RESPONSIBLE_PARTY,
    context: { credentialIssuer: CARD, trustedRootIssuer: RESPONSIBLE_PARTY },
  },
  "a Card's responsible party that did not verify": {
    accepted: false,
    mayOmitId: false,
    did: RESPONSIBLE_PARTY,
    context: { credentialIssuer: CARD },
  },
  'a stranger, while the verifier pins a root and accepts a status service': {
    accepted: false,
    mayOmitId: false,
    did: STRANGER,
    context: { credentialIssuer: CREDENTIAL_ISSUER, trustedRootIssuer: ROOT },
    statusListIssuers: { [CREDENTIAL_ISSUER]: [SERVICE], [STRANGER]: [STRANGER] },
  },
};

const ISSUER_FORMS: Record<string, (did: string) => unknown> = {
  'as a string': (did) => did,
  "as an object's id": (did) => ({ id: did, name: 'Status' }),
};

const URLS: Record<string, string> = {
  'a URL': 'https://status.example/lists/1',
  'a URL with a query': 'https://resolver.example/1.0/identifiers/did:example:acme?resourceName=revocation-a&resourceType=StatusList',
};

interface IdRow {
  /** Whether the `id` names the URL the list was fetched from, or is absent. */
  binds: 'the URL' | 'absent' | 'another';
  of: (url: string) => unknown;
}

const IDS: Record<string, IdRow> = {
  'no id': { binds: 'absent', of: () => ABSENT },
  'the URL': { binds: 'the URL', of: (url) => url },
  'a prefix of the URL': {
    binds: 'another',
    of: (url) => (url.includes('?') ? url.slice(0, url.indexOf('?')) : url.slice(0, url.lastIndexOf('/') + 1)),
  },
  'the URL with another query': {
    binds: 'another',
    of: (url) => (url.includes('?') ? url.replace('revocation-a', 'revocation-b') : `${url}?resourceName=revocation-b`),
  },
  'another URL': { binds: 'another', of: () => 'https://status.example/lists/2' },
  'null': { binds: 'another', of: () => null },
  'the URL in an array': { binds: 'another', of: (url) => [url] },
};

interface ListTypeRow {
  /** Whether the list is typed as a Bitstring Status List in both places §2.2 names. */
  bitstring: boolean;
  type: unknown;
  subjectType: unknown;
}

const LIST_TYPES: Record<string, ListTypeRow> = {
  'a StatusList2021Credential': {
    bitstring: false,
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    subjectType: 'StatusList2021',
  },
  'a BitstringStatusListCredential': {
    bitstring: true,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    subjectType: 'BitstringStatusList',
  },
  'typed as a Bitstring Status List in its type alone': {
    bitstring: false,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    subjectType: 'StatusList2021',
  },
  "typed as a Bitstring Status List in its subject's type alone": {
    bitstring: false,
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    subjectType: 'BitstringStatusList',
  },
  'typed as neither': { bitstring: false, type: ['VerifiableCredential'], subjectType: ABSENT },
};

interface PurposeRow {
  /** The form of the list's `statusPurpose`: one string, one or more strings in an array, or neither. */
  form: 'a string' | 'an array of strings' | 'neither';
  /** Whether the purposes it states include the purpose checked. */
  includes: boolean;
  value: unknown;
}

const LIST_PURPOSES: Record<string, PurposeRow> = {
  "the checker's": { form: 'a string', includes: true, value: CHECKED },
  another: { form: 'a string', includes: false, value: OTHER_PURPOSE },
  "an array holding the checker's": { form: 'an array of strings', includes: true, value: [OTHER_PURPOSE, CHECKED] },
  "an array of the checker's alone": { form: 'an array of strings', includes: true, value: [CHECKED] },
  'an array without it': { form: 'an array of strings', includes: false, value: [OTHER_PURPOSE, 'message'] },
  'an empty array': { form: 'neither', includes: false, value: [] },
  "an array holding the checker's and a number": { form: 'neither', includes: false, value: [CHECKED, 7] },
  'null': { form: 'neither', includes: false, value: null },
  none: { form: 'neither', includes: false, value: ABSENT },
};

interface EntryPurposeRow {
  /** Whether a checker for `revocation` may read the entry. */
  readable: boolean;
  value: unknown;
}

const ENTRY_PURPOSES: Record<string, EntryPurposeRow> = {
  none: { readable: true, value: ABSENT },
  "the checker's": { readable: true, value: CHECKED },
  another: { readable: false, value: OTHER_PURPOSE },
  'null': { readable: false, value: null },
  'a number': { readable: false, value: 7 },
};

type Check = 'entry purpose' | 'issuer' | 'purpose' | 'id';

interface Case {
  label: string;
  url: string;
  signer: SignerRow;
  issuer: unknown;
  id: IdRow & { value: unknown };
  listType: ListTypeRow;
  listPurpose: PurposeRow;
  entryPurpose: EntryPurposeRow;
}

function* cases(): Generator<Case> {
  for (const [urlLabel, url] of Object.entries(URLS))
    for (const [signerLabel, signer] of Object.entries(SIGNERS))
      for (const [formLabel, form] of Object.entries(ISSUER_FORMS))
        for (const [idLabel, id] of Object.entries(IDS))
          for (const [typeLabel, listType] of Object.entries(LIST_TYPES))
            for (const [listLabel, listPurpose] of Object.entries(LIST_PURPOSES))
              for (const [entryLabel, entryPurpose] of Object.entries(ENTRY_PURPOSES))
                yield {
                  label: `${signerLabel}, issuer ${formLabel}, id: ${idLabel}, ${typeLabel}, list purpose: ${listLabel}, entry purpose: ${entryLabel}, at ${urlLabel}`,
                  url,
                  signer,
                  issuer: form(signer.did),
                  id: { ...id, value: id.of(url) },
                  listType,
                  listPurpose,
                  entryPurpose,
                };
}

/** Whether the list states the purpose checked, in a form its data model allows. */
function purposeHolds(c: Case): boolean {
  if (c.listPurpose.form === 'a string') return c.listPurpose.includes;
  if (c.listPurpose.form === 'an array of strings') return c.listType.bitstring && c.listPurpose.includes;
  return false;
}

/** The decision table: the checks a case fails, none when the list is read. */
function failedChecks(c: Case): Check[] {
  const failed: Check[] = [];
  if (!c.entryPurpose.readable) failed.push('entry purpose');
  if (!c.signer.accepted) failed.push('issuer');
  if (!purposeHolds(c)) failed.push('purpose');
  if (!(c.id.binds === 'the URL' || (c.id.binds === 'absent' && c.signer.mayOmitId))) failed.push('id');
  return failed;
}

const present = (member: string, value: unknown) => (value === ABSENT ? {} : { [member]: value });

/** The case through the rule, as the card revocation checker applies it. */
function verdictOf(c: Case): StatusListVerdict {
  const entry = acceptEntryPurpose(c.entryPurpose.value === ABSENT ? undefined : c.entryPurpose.value, CHECKED);
  if (!entry.valid) return entry;
  const list = {
    ...present('id', c.id.value),
    type: c.listType.type,
    issuer: c.issuer,
    credentialSubject: {
      ...present('type', c.listType.subjectType),
      ...present('statusPurpose', c.listPurpose.value),
      encodedList: 'uH4sIAAAAAAAAA',
    },
  };
  const expectation = statusListExpectationFor(
    { statusListCredential: c.url, statusPurpose: CHECKED },
    c.signer.context,
    c.signer.statusListIssuers,
  );
  return acceptStatusList(list, expectation);
}

/** The check a refusal reason names. */
function checkNamed(reason: string | undefined): Check | 'none' {
  if (reason === undefined) return 'none';
  if (reason.startsWith("the entry's statusPurpose ")) return 'entry purpose';
  if (/^status list (names no issuer|issuer )/.test(reason)) return 'issuer';
  if (/^status list (has no statusPurpose|statusPurpose )/.test(reason)) return 'purpose';
  if (/^status list (states no id|id )/.test(reason)) return 'id';
  return 'none';
}

describe('the acceptance rule, over every combination of its inputs', () => {
  it('reads a list exactly when the decision table does, and names a check the case fails when it refuses one', () => {
    const all = [...cases()];
    const mismatches = all.flatMap((c) => {
      const failed = failedChecks(c);
      const verdict = verdictOf(c);
      const agrees = verdict.valid ? failed.length === 0 : failed.includes(checkNamed(verdict.reason) as Check);
      return agrees ? [] : [`${c.label}: expected ${failed.length === 0 ? 'read' : `refused on ${failed.join(', ')}`}, got ${verdict.valid ? 'read' : verdict.reason}`];
    });
    expect({ cases: all.length, mismatches: mismatches.length, first: mismatches.slice(0, 5) }).toEqual({
      cases: 2 * 9 * 2 * 7 * 5 * 9 * 5,
      mismatches: 0,
      first: [],
    });
    // The table reads a list for 392 of the cases. Under an entry the checker may read, in both URL
    // and issuer forms, the credential's own issuer's list with its URL as its id or, while it is the
    // one issuer accepted, none, and each other row of an accepted signer with its URL as its id, make
    // 56; each is read with the checker's purpose as one string on every list type, and in either
    // array that holds it only on a BitstringStatusListCredential, so 7 times.
    expect(all.filter((c) => failedChecks(c).length === 0)).toHaveLength(392);
  });
});
