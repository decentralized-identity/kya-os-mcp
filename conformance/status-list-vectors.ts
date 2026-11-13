/**
 * The status-list category, `conformance/vectors/status-list.json`: a delegation's revocation read
 * from a signed StatusList2021Credential (SPEC.md §6.6), or from its successor, a W3C Bitstring
 * Status List v1.0 BitstringStatusListCredential. `generate-vectors.ts` runs it with its own party
 * minting and delegation signing, so every category it writes makes them one way.
 *
 * One run mints the signing parties for this file: regenerate the file whole, never in part.
 * Supplementary authority vectors have their own cohesive generation in status-list-authority-vectors.ts.
 */

import {
  BitstringManager,
  statusListGzipCodec,
  type CredentialStatus,
  type DelegationCredential,
  type Proof,
  type StatusList2021Credential,
} from '../src/index.js';
import type { NodeCryptoProvider } from '../src/providers/node-crypto.js';
import { signVC } from './crypto-kit.js';
import { statusListBindingVectors, type Signer } from './status-list-binding-vectors.js';
import { SUITE_VERSION } from './vector-files.js';
import type { ConformanceVector, VectorFile } from './types.js';

export interface StatusListVectorDeps<P extends Signer> {
  crypto: NodeCryptoProvider;
  /** A new party with its own key pair. */
  mintParty: () => Promise<P>;
  /** The DID document a vector supplies for a party. */
  didDocumentFor: (party: P) => Record<string, unknown>;
  /** A delegation from `issuer` to `subjectDid` that carries `credentialStatus`, signed by `issuer`. */
  signDelegation: (
    issuer: P,
    subjectDid: string,
    id: string,
    credentialStatus: CredentialStatus,
  ) => Promise<DelegationCredential>;
  serverDid: string;
}

export async function statusListVectors<P extends Signer>(deps: StatusListVectorDeps<P>): Promise<VectorFile> {
  const { crypto, serverDid } = deps;
  const issuer = await deps.mintParty();
  const agent = await deps.mintParty();
  const didDocuments = { [issuer.did]: deps.didDocumentFor(issuer) };

  const listId = 'https://status.example.com/revocation/v1';
  const bitstringListId = 'https://status.example.com/status/v1';
  const listSize = 131072;

  async function encodedListOf(revokedIndices: number[]): Promise<string> {
    const bitstring = new BitstringManager(listSize, statusListGzipCodec, statusListGzipCodec);
    for (const i of revokedIndices) bitstring.setBit(i, true);
    return bitstring.encode();
  }

  async function signedByIssuer<T extends Record<string, unknown>>(unsigned: T): Promise<T & { proof: Proof }> {
    return { ...unsigned, proof: await signVC(crypto, unsigned, issuer.privateKey, issuer.kid) };
  }

  async function buildStatusList(revokedIndices: number[]): Promise<StatusList2021Credential> {
    const list = await signedByIssuer({
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/vc/status-list/2021/v1',
      ],
      id: listId,
      type: ['VerifiableCredential', 'StatusList2021Credential'],
      issuer: issuer.did,
      issuanceDate: '2026-01-01T00:00:00.000Z',
      credentialSubject: {
        id: `${listId}#list`,
        type: 'StatusList2021' as const,
        statusPurpose: 'revocation' as const,
        encodedList: await encodedListOf(revokedIndices),
      },
    });
    return list as StatusList2021Credential;
  }

  /** The issuer's W3C Bitstring Status List v1.0 list for both purposes, which may name them in an array (§2.2). */
  async function buildBitstringStatusList(revokedIndices: number[]): Promise<Record<string, unknown>> {
    return signedByIssuer({
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: bitstringListId,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: issuer.did,
      validFrom: '2026-01-01T00:00:00.000Z',
      credentialSubject: {
        id: `${bitstringListId}#list`,
        type: 'BitstringStatusList',
        statusPurpose: ['suspension', 'revocation'],
        encodedList: await encodedListOf(revokedIndices),
      },
    });
  }

  const activeIndex = 7;
  const revokedIndex = 42;
  /** The index of a revoked delegation a delegate of the issuer issued, on the issuer's list. */
  const redelegatedIndex = 21;
  const statusFor = (index: number): CredentialStatus => ({
    id: `${listId}#${index}`,
    type: 'StatusList2021Entry',
    statusPurpose: 'revocation',
    statusListIndex: index.toString(),
    statusListCredential: listId,
  });

  const activeCred = await deps.signDelegation(issuer, agent.did, 'del-active', statusFor(activeIndex));
  const revokedCred = await deps.signDelegation(issuer, agent.did, 'del-revoked', statusFor(revokedIndex));
  const delegate = await deps.mintParty();
  const redelegatedCred = await deps.signDelegation(delegate, agent.did, 'del-redelegated', statusFor(redelegatedIndex));
  const bitstringCred = await deps.signDelegation(issuer, agent.did, 'del-bitstring', {
    id: `${bitstringListId}#${activeIndex}`,
    type: 'BitstringStatusListEntry',
    statusPurpose: 'revocation',
    statusListIndex: activeIndex.toString(),
    statusListCredential: bitstringListId,
  });
  const signedList = await buildStatusList([revokedIndex, redelegatedIndex]);
  const statusLists = { [listId]: signedList };

  // The signed list with the revoked bit cleared and the proof left as signed:
  // read without its proof checked, it reports the revoked credential active.
  const clearedList = await buildStatusList([]);
  const tamperedLists = {
    [listId]: {
      ...signedList,
      credentialSubject: {
        ...signedList.credentialSubject,
        encodedList: clearedList.credentialSubject.encodedList,
      },
    },
  };

  const vectors: ConformanceVector[] = [
    {
      id: 'status-list/active-credential',
      category: 'status-list',
      description: 'Delegation whose StatusList2021 bit is 0 (not revoked)',
      expected: 'pass',
      reason: 'An unset revocation bit means the credential is active',
      input: { credential: activeCred, statusLists, didDocuments, serverDid },
    },
    {
      id: 'status-list/revoked-credential',
      category: 'status-list',
      description: 'Delegation whose StatusList2021 bit is 1 (revoked)',
      expected: 'fail',
      reason: 'A set revocation bit must reject the credential',
      input: { credential: revokedCred, statusLists, didDocuments, serverDid },
    },
    {
      id: 'status-list/tampered-list',
      category: 'status-list',
      description: 'Revoked delegation checked against its list with the bit cleared after signing',
      expected: 'fail',
      reason: "The list's proof no longer verifies, so its bits cannot be read and the check fails closed",
      input: { credential: revokedCred, statusLists: tamperedLists, didDocuments, serverDid },
    },
    ...(await statusListBindingVectors({
      crypto,
      issuer,
      outsider: await deps.mintParty(),
      delegate,
      didDocumentFor: deps.didDocumentFor,
      activeCredential: activeCred,
      revokedCredential: revokedCred,
      redelegatedCredential: redelegatedCred,
      bitstringCredential: bitstringCred,
      signedList,
      clearedList,
      bitstringList: await buildBitstringStatusList([revokedIndex]),
      serverDid,
    })),
  ];

  return { version: SUITE_VERSION, category: 'status-list', vectors };
}
