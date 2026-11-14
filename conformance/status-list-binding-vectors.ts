/**
 * The status-list vectors that hold a verifier to the list a credential's status may be read from
 * (suite ≥ 1.4.0; SPEC.md §6.6).
 *
 * A list's proof shows only who signed it. Each negative vector carries a revoked delegation and, at
 * its `statusListCredential` URL, the issuer's list with no bit set, re-issued with one thing
 * changed and validly signed. Its proof verifies and the credential's bit reads as unset, so a
 * verifier that checks only the proof reports the credential active. Each must fail on that one
 * change:
 * - `status-list/foreign-issuer-list`: another DID issued the list, and the vector supplies that
 *   DID's document;
 * - `status-list/purpose-mismatch-list`: the list is a `suspension` list, so it says nothing of the
 *   credential's revocation (W3C Bitstring Status List v1.0 §3.2);
 * - `status-list/purpose-array-2021-list`: the StatusList2021 list states the purposes `suspension`
 *   and `revocation` in an array, where Verifiable Credentials Status List v2021 §2.2 has it state
 *   one string, so it is in no data model that says what its bits mean;
 * - `status-list/id-mismatch-list`: the list states another URL as its `id`, so it is not the list
 *   the credential names (§2.2).
 *
 * Two more negative vectors carry a list, with the bit unset, from an issuer other than the
 * credential's that the vector has the verifier accept for the credential, re-issued without its
 * `id`. Only the `id` binds a list to the URL it is served at, so only a list the credential's own
 * issuer signed, where it is the only issuer accepted, may leave it out:
 * - `status-list/root-no-id-list`: a delegate of the issuer issued the credential, and the issuer,
 *   whose list it is, is the chain's root, which the vector pins as `trustedRootIssuer`;
 * - `status-list/configured-issuer-no-id-list`: the vector's `statusListIssuers` accepts the DID of
 *   `status-list/foreign-issuer-list`, which signed the list, for the credential's issuer.
 *
 * Each positive vector carries an active delegation and a list of its issuer in a form the
 * specification allows, so a verifier that refuses that form fails closed and fails the vector:
 * - `status-list/no-id-list`: the issuer's list re-issued without its `id`, which §2.2 makes
 *   optional, and which the credential's own issuer, the only one accepted, may leave out;
 * - `status-list/purpose-array-list`: the issuer's BitstringStatusListCredential, which declares the
 *   purposes `suspension` and `revocation` (§2.2), read for a `BitstringStatusListEntry`.
 */

import type { NodeCryptoProvider } from '../src/providers/node-crypto.js';
import type { DelegationCredential, StatusList2021Credential } from '../src/index.js';
import { signVC } from './crypto-kit.js';
import type { ConformanceVector, StatusListInput } from './types.js';

/** The URL of another list of the same issuer, which `status-list/id-mismatch-list` states as its `id`. */
const OTHER_LIST_URL = 'https://status.example.com/revocation/v2';

/** A party that signs: its DID, the verification method it signs with, and that method's private key. */
export interface Signer {
  did: string;
  kid: string;
  privateKey: string;
}

export interface StatusListBindingInput<P extends Signer> {
  crypto: NodeCryptoProvider;
  /** The credentials' issuer, who issued and signed `signedList`, `clearedList` and `bitstringList`. */
  issuer: P;
  /** A DID outside the credentials' chain. */
  outsider: P;
  /** A DID the issuer delegated to, which issued `redelegatedCredential`. */
  delegate: P;
  /** The DID document a vector supplies for a party. */
  didDocumentFor: (party: P) => Record<string, unknown>;
  /** The active delegation the positive vectors carry, on `signedList`. */
  activeCredential: DelegationCredential;
  /** The revoked delegation the negative vectors carry, on `signedList`. */
  revokedCredential: DelegationCredential;
  /** A revoked delegation `delegate` issued, on `signedList`. */
  redelegatedCredential: DelegationCredential;
  /** An active delegation whose `credentialStatus` is a `BitstringStatusListEntry` on `bitstringList`. */
  bitstringCredential: DelegationCredential;
  /** The issuer's signed list at the credentials' `statusListCredential` URL, with the revoked bits set. */
  signedList: StatusList2021Credential;
  /** The same list with no bit set. */
  clearedList: StatusList2021Credential;
  /** The issuer's signed BitstringStatusListCredential for `suspension` and `revocation`. */
  bitstringList: Record<string, unknown>;
  serverDid: string;
}

type Fields = Record<string, unknown>;

export async function statusListBindingVectors<P extends Signer>(
  input: StatusListBindingInput<P>,
): Promise<ConformanceVector[]> {
  const { crypto, issuer, outsider, delegate, didDocumentFor, activeCredential, revokedCredential, serverDid } = input;
  const withSubject = (fields: Fields, changes: Fields): Fields => ({
    ...fields,
    credentialSubject: { ...(fields.credentialSubject as Fields), ...changes },
  });

  /** `list` with `change` made, signed by `signer` in place of its own proof. */
  async function reissued(
    list: StatusList2021Credential,
    change: (fields: Fields) => Fields,
    signer: P,
  ): Promise<StatusList2021Credential> {
    const { proof: _proof, ...fields } = list;
    const changed = change(fields);
    const proof = await signVC(crypto, changed, signer.privateKey, signer.kid);
    return { ...changed, proof } as unknown as StatusList2021Credential;
  }

  /** A vector checking `credential` against `list`, at its URL, with the DID documents of `signers` and `configuration`. */
  function vector(
    name: string,
    expected: ConformanceVector['expected'],
    text: { description: string; reason: string },
    credential: DelegationCredential,
    list: Fields,
    signers: P[],
    configuration: Pick<StatusListInput, 'trustedRootIssuer' | 'statusListIssuers'> = {},
  ): ConformanceVector {
    return {
      id: `status-list/${name}`,
      category: 'status-list',
      description: text.description,
      expected,
      reason: text.reason,
      input: {
        credential,
        statusLists: { [statusListUrlOf(credential)]: list },
        didDocuments: Object.fromEntries(signers.map((party) => [party.did, didDocumentFor(party)])),
        serverDid,
        ...configuration,
      },
    };
  }

  const refused = (name: string, text: { description: string; reason: string }, list: StatusList2021Credential, signers: P[]) =>
    vector(name, 'fail', text, revokedCredential, list, signers);
  const read = (name: string, text: { description: string; reason: string }, credential: DelegationCredential, list: Fields) =>
    vector(name, 'pass', text, credential, list, [issuer]);
  const withoutId = ({ id: _id, ...fields }: Fields): Fields => fields;

  return [
    refused(
      'foreign-issuer-list',
      {
        description: 'Revoked delegation checked against a list with the bit unset, validly signed by another DID',
        reason: "Another DID's list cannot speak for the credential, so it cannot clear the revocation and the check fails closed",
      },
      await reissued(input.clearedList, (fields) => ({ ...fields, issuer: outsider.did }), outsider),
      [issuer, outsider],
    ),
    refused(
      'purpose-mismatch-list',
      {
        description: "Revoked delegation checked against its issuer's suspension list with the bit unset",
        reason: 'A list of another statusPurpose says nothing of revocation, so the check fails closed',
      },
      await reissued(input.clearedList, (fields) => withSubject(fields, { statusPurpose: 'suspension' }), issuer),
      [issuer],
    ),
    refused(
      'purpose-array-2021-list',
      {
        description: "Revoked delegation checked against its issuer's StatusList2021 list with the bit unset, stating its purposes as an array",
        reason: 'A StatusList2021 list states one statusPurpose, and only a Bitstring Status List v1.0 list may state several, so the check fails closed',
      },
      await reissued(input.clearedList, (fields) => withSubject(fields, { statusPurpose: ['suspension', 'revocation'] }), issuer),
      [issuer],
    ),
    refused(
      'id-mismatch-list',
      {
        description: "Revoked delegation checked against its issuer's list for another URL, with the bit unset",
        reason: 'A list that states another URL as its id is not the list the credential names, so the check fails closed',
      },
      await reissued(
        input.clearedList,
        (fields) => withSubject({ ...fields, id: OTHER_LIST_URL }, { id: `${OTHER_LIST_URL}#list` }),
        issuer,
      ),
      [issuer],
    ),
    vector(
      'root-no-id-list',
      'fail',
      {
        description: "Revoked delegation a delegate of the pinned root issued, checked against the root's list with the bit unset, re-issued without an id",
        reason: "Only the credential's own issuer may leave out a list's id; the pinned root's list must state the URL it is read from, so the check fails closed",
      },
      input.redelegatedCredential,
      await reissued(input.clearedList, withoutId, issuer),
      [delegate, issuer],
      { trustedRootIssuer: issuer.did },
    ),
    vector(
      'configured-issuer-no-id-list',
      'fail',
      {
        description: 'Revoked delegation checked against a list with the bit unset, signed by a DID the verifier accepts for its issuer and stating no id',
        reason: "A list from an issuer other than the credential's must state the URL it is read from as its id, so the check fails closed",
      },
      revokedCredential,
      await reissued(input.clearedList, (fields) => withoutId({ ...fields, issuer: outsider.did }), outsider),
      [issuer, outsider],
      { statusListIssuers: { [issuer.did]: [outsider.did] } },
    ),
    read(
      'no-id-list',
      {
        description: "Active delegation checked against its issuer's list, re-issued without an id",
        reason: "The credential's own issuer's list need not state an id, so it is read and the unset bit means the credential is active",
      },
      activeCredential,
      await reissued(input.signedList, withoutId, issuer),
    ),
    read(
      'purpose-array-list',
      {
        description: "Active delegation checked against its issuer's Bitstring Status List v1.0 list for suspension and revocation",
        reason: 'A BitstringStatusListCredential may declare several purposes; one that includes revocation is read, and the unset bit means the credential is active',
      },
      input.bitstringCredential,
      input.bitstringList,
    ),
  ];
}

function statusListUrlOf(credential: DelegationCredential): string {
  const url = credential.credentialStatus?.statusListCredential;
  if (url === undefined) throw new Error('the credential names no status list');
  return url;
}
