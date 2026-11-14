#!/usr/bin/env node
/**
 * Generator for the key-relationship conformance vectors (suite ≥ 1.3.0),
 * `conformance/vectors/delegation-chain-key-relationship.json` and
 * `conformance/vectors/status-list-key-relationship.json`.
 *
 * SPEC.md §6.2 verifies a delegation credential, and the status list it points
 * at, only with a key that the issuer's own DID document lists under
 * `assertionMethod` and whose method names the issuer as its `controller`, and
 * rejects a proof that states another `proofPurpose`. The issuer here is a
 * did:web whose document publishes two keys: `#login-1` under `authentication`
 * and `#assert-1` under `assertionMethod`. Each file holds one vector that
 * verifies and five that fail, each for one thing: the credential, or its
 * list, signed with `#login-1`; its proof stating
 * `proofPurpose: "authentication"`; the document supplied for the issuer
 * naming another DID as its `id`; naming another DID as the controller of the
 * key that signs; or defining that key's method twice, in
 * `verificationMethod` and again embedded in `assertionMethod`. That key is
 * `#assert-1` for the delegation. For the list it is `#login-1`, which the
 * document then also lists under `assertionMethod`, so that the credential's
 * proof still verifies and it is the list's that fails.
 *
 * The delegation file also fails a delegation whose key is published under
 * another DID's id, under no relationship, or with no `type` or no
 * `controller`. It also holds the delegation as a VC-JWT: with no `kid`, it
 * verifies with the key the first `assertionMethod` entry names; with a `kid`
 * naming `#login-1`, or an empty `kid`, it fails.
 *
 * Like `generate-vectors.ts`, it mints fresh keys on every run, so its output
 * must never be committed over an existing suiteVersion.
 *
 *   run:  tsx conformance/key-relationship-vectors.ts   (npm run conformance:generate:key-relationship)
 */

import { pathToFileURL } from 'node:url';
import { NodeCryptoProvider } from '../src/providers/node-crypto.js';
import { base64ToBytes } from '../src/utils/base64.js';
import {
  BitstringManager,
  completeVCJWT,
  createUnsignedVCJWT,
  statusListGzipCodec,
  wrapDelegationAsVC,
  type CredentialStatus,
  type Proof,
} from '../src/index.js';
import { ed25519VerificationMethod, signVC } from './crypto-kit.js';
import { SUITE_VERSION, writeVectorFile } from './vector-files.js';
import type { ConformanceVector, VectorFile } from './types.js';

const crypto = new NodeCryptoProvider();
const SERVER_DID = 'did:web:server.example.com';
const ISSUER_DID = 'did:web:issuer.example.com';
const AGENT_DID = 'did:web:agent.example.com';
const OTHER_DID = 'did:web:other.example.com';
const LIST_URL = 'https://issuer.example.com/status/revocation/1';
const LIST_SIZE = 131072;
const ISSUED_AT = '2026-01-01T00:00:00.000Z';

interface IssuerKey {
  id: string;
  privateKey: string;
  publicKey: string;
}

/** The issuer's keys: one it signs in with, one it issues credentials with, one it lists for neither. */
export interface IssuerKeys {
  login: IssuerKey;
  assert: IssuerKey;
  unlisted: IssuerKey;
}

type Signed<T> = T & { proof: Proof };

async function mintKey(fragment: string): Promise<IssuerKey> {
  const { privateKey, publicKey } = await crypto.generateKeyPair();
  return { id: `${ISSUER_DID}#${fragment}`, privateKey, publicKey };
}

export async function mintIssuerKeys(): Promise<IssuerKeys> {
  return { login: await mintKey('login-1'), assert: await mintKey('assert-1'), unlisted: await mintKey('unlisted-1') };
}

/** The method that publishes the issuer's `key`, controlled by `controller` (default: the issuer). */
function issuerMethod(key: IssuerKey, controller = ISSUER_DID): Record<string, unknown> {
  return ed25519VerificationMethod(key.id, controller, base64ToBytes(key.publicKey));
}

/** The method that publishes the issuer's `key` without its `member`. */
function issuerMethodWithout(key: IssuerKey, member: 'type' | 'controller'): Record<string, unknown> {
  const { [member]: _dropped, ...method } = issuerMethod(key);
  return method;
}

/** The DID documents a vector supplies: the issuer's, with the members in `change` replaced. */
function didDocumentsFor(keys: IssuerKeys, change: Record<string, unknown> = {}): Record<string, Record<string, unknown>> {
  return {
    [ISSUER_DID]: {
      id: ISSUER_DID,
      verificationMethod: [issuerMethod(keys.login), issuerMethod(keys.assert)],
      authentication: [keys.login.id],
      assertionMethod: [keys.assert.id],
      ...change,
    },
  };
}

async function signedWith<T extends Record<string, unknown>>(unsigned: T, key: IssuerKey): Promise<Signed<T>> {
  return { ...unsigned, proof: await signVC(crypto, unsigned, key.privateKey, key.id) };
}

/** `credential` as a VC-JWT signed with `key`, its JOSE header naming `kid` when one is given. */
async function vcJwtSignedWith(credential: Record<string, unknown>, key: IssuerKey, kid?: string): Promise<string> {
  const header = { alg: 'EdDSA', typ: 'JWT', ...(kid === undefined ? {} : { kid }) };
  const signingInput = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${createUnsignedVCJWT(credential).encodedPayload}`;
  const signature = await crypto.sign(new TextEncoder().encode(signingInput), key.privateKey);
  return completeVCJWT(signingInput, Buffer.from(signature).toString('base64url'));
}

/** The same signature under a proof that states `proofPurpose: "authentication"`. */
function statingAuthentication<T>(signed: Signed<T>): Signed<T> {
  return { ...signed, proof: { ...signed.proof, proofPurpose: 'authentication' } };
}

function delegation(credentialStatus?: CredentialStatus): Record<string, unknown> {
  return wrapDelegationAsVC(
    {
      id: 'del-issuer-agent',
      issuerDid: ISSUER_DID,
      subjectDid: AGENT_DID,
      vcId: 'urn:uuid:del-issuer-agent',
      constraints: { scopes: ['greeting:read'], audience: SERVER_DID },
      signature: '',
      status: 'active',
      createdAt: 1_750_000_000_000,
    },
    { issuanceDate: ISSUED_AT, ...(credentialStatus ? { credentialStatus } : {}) },
  );
}

/** An unsigned StatusList2021Credential from the issuer, with no bit set. */
async function clearList(): Promise<Record<string, unknown>> {
  const encodedList = await new BitstringManager(LIST_SIZE, statusListGzipCodec, statusListGzipCodec).encode();
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'],
    id: LIST_URL,
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    issuer: ISSUER_DID,
    issuanceDate: ISSUED_AT,
    credentialSubject: { id: `${LIST_URL}#list`, type: 'StatusList2021', statusPurpose: 'revocation', encodedList },
  };
}

export async function delegationChainKeyRelationshipFile(keys: IssuerKeys): Promise<VectorFile> {
  const credential = delegation();
  const leaf = await signedWith(credential, keys.assert);
  const input = (over: { leaf?: unknown; didDocuments?: unknown } = {}) => ({
    leaf: over.leaf ?? leaf,
    serverDid: SERVER_DID,
    didDocuments: over.didDocuments ?? didDocumentsFor(keys),
  });

  const vectors: ConformanceVector[] = [
    {
      id: 'delegation-chain/assertion-method-key',
      category: 'delegation-chain',
      description: "A delegation signed with the key its issuer's DID document lists under assertionMethod",
      expected: 'pass',
      reason: "The issuer's own document lists the signing key under assertionMethod, and the proof states that purpose",
      input: input(),
    },
    {
      id: 'delegation-chain/authentication-key',
      category: 'delegation-chain',
      description: "The same delegation signed with the key its issuer's DID document lists only under authentication",
      expected: 'fail',
      reason: 'A key listed only under authentication signs the issuer in and does not verify its credentials (SPEC.md §6.2)',
      input: input({ leaf: await signedWith(credential, keys.login) }),
    },
    {
      id: 'delegation-chain/proof-purpose-authentication',
      category: 'delegation-chain',
      description: 'The verifying delegation with its proof stating proofPurpose "authentication"',
      expected: 'fail',
      reason: 'A proof that states a purpose other than assertionMethod is rejected, although the member is outside the signature (SPEC.md §6.2)',
      input: input({ leaf: statingAuthentication(leaf) }),
    },
    {
      id: 'delegation-chain/issuer-document-id-mismatch',
      category: 'delegation-chain',
      description: 'The verifying delegation, with the DID document supplied for its issuer naming another DID as its id',
      expected: 'fail',
      reason: "Only the issuer's own DID document, whose id is the issuer's DID, lists the issuer's keys (SPEC.md §6.2)",
      input: input({ didDocuments: didDocumentsFor(keys, { id: OTHER_DID }) }),
    },
    {
      id: 'delegation-chain/assertion-key-other-controller',
      category: 'delegation-chain',
      description: "The verifying delegation, with the issuer's DID document naming another DID as the controller of #assert-1, the key it lists under assertionMethod",
      expected: 'fail',
      reason: "A verification method whose controller is another DID is not the issuer's (CID §3.3 step 10, SPEC.md §6.2), so no key the issuer lists under assertionMethod verifies the delegation",
      input: input({ didDocuments: didDocumentsFor(keys, { verificationMethod: [issuerMethod(keys.login), issuerMethod(keys.assert, OTHER_DID)] }) }),
    },
    {
      id: 'delegation-chain/assertion-key-defined-twice',
      category: 'delegation-chain',
      description: "The verifying delegation, with the issuer's DID document defining #assert-1 twice: in verificationMethod, and again embedded in assertionMethod",
      expected: 'fail',
      reason: 'A method id the document defines more than once, among verificationMethod and the methods assertionMethod embeds, names no method, even when every definition holds the same key (SPEC.md §6.2)',
      input: input({ didDocuments: didDocumentsFor(keys, { assertionMethod: [issuerMethod(keys.assert)] }) }),
    },
    {
      id: 'delegation-chain/assertion-entry-other-did',
      category: 'delegation-chain',
      description: "The verifying delegation, its key and the issuer's DID document naming #assert-1 under another DID, though the issuer's document defines it under the issuer's control and lists it under assertionMethod",
      expected: 'fail',
      reason: "Only a method whose id is under the issuer's DID is the issuer's, so an assertionMethod entry naming a key under another DID names none of its keys (SPEC.md §6.2)",
      input: input({
        leaf: { ...leaf, proof: { ...leaf.proof, verificationMethod: `${OTHER_DID}#assert-1` } },
        didDocuments: didDocumentsFor(keys, {
          verificationMethod: [issuerMethod(keys.login), issuerMethod({ ...keys.assert, id: `${OTHER_DID}#assert-1` })],
          assertionMethod: [`${OTHER_DID}#assert-1`],
        }),
      }),
    },
    {
      id: 'delegation-chain/unlisted-key',
      category: 'delegation-chain',
      description: "The same delegation signed with #unlisted-1, which the issuer's DID document publishes in verificationMethod and lists under no relationship",
      expected: 'fail',
      reason: 'A key the issuer publishes but does not list under assertionMethod does not verify its credentials (SPEC.md §6.2)',
      input: input({
        leaf: await signedWith(credential, keys.unlisted),
        didDocuments: didDocumentsFor(keys, { verificationMethod: [issuerMethod(keys.login), issuerMethod(keys.assert), issuerMethod(keys.unlisted)] }),
      }),
    },
    ...(['type', 'controller'] as const).map(
      (member): ConformanceVector => ({
        id: `delegation-chain/assertion-key-without-${member}`,
        category: 'delegation-chain',
        description: `The verifying delegation, with the issuer's DID document publishing #assert-1, the key it lists under assertionMethod, with no ${member}`,
        expected: 'fail',
        reason: `A verification method without a non-empty string ${member} is no method (CID §3.3 step 8, SPEC.md §6.2), so no key the issuer lists under assertionMethod verifies the delegation`,
        input: input({ didDocuments: didDocumentsFor(keys, { verificationMethod: [issuerMethod(keys.login), issuerMethodWithout(keys.assert, member)] }) }),
      }),
    ),
    {
      id: 'delegation-chain/vc-jwt-no-kid-first-entry',
      category: 'delegation-chain',
      description: "The delegation as a VC-JWT signed with #assert-1, its JOSE header naming no kid; the issuer's DID document publishes #login-1 first and lists #assert-1 first under assertionMethod",
      expected: 'pass',
      reason: 'A VC-JWT with no kid is checked with the method the first assertionMethod entry names (SPEC.md §6.2), which made its signature',
      input: input({ leaf: await vcJwtSignedWith(credential, keys.assert) }),
    },
    {
      id: 'delegation-chain/vc-jwt-kid-authentication-key',
      category: 'delegation-chain',
      description: "The same VC-JWT signed with #login-1, which its kid names and the issuer's DID document lists only under authentication",
      expected: 'fail',
      reason: 'A key listed only under authentication signs the issuer in and does not verify its credentials, whatever the kid names (SPEC.md §6.2)',
      input: input({ leaf: await vcJwtSignedWith(credential, keys.login, keys.login.id) }),
    },
    {
      id: 'delegation-chain/vc-jwt-empty-kid',
      category: 'delegation-chain',
      description: 'The verifying VC-JWT with an empty kid in its JOSE header, still signed with #assert-1, the key the first assertionMethod entry names',
      expected: 'fail',
      reason: 'An empty kid names no key and is never read as naming none (SPEC.md §6.2), so the VC-JWT is rejected although the key it would otherwise be checked with made its signature',
      input: input({ leaf: await vcJwtSignedWith(credential, keys.assert, '') }),
    },
  ];
  return { version: SUITE_VERSION, category: 'delegation-chain', vectors };
}

export async function statusListKeyRelationshipFile(keys: IssuerKeys): Promise<VectorFile> {
  const status: CredentialStatus = {
    id: `${LIST_URL}#7`,
    type: 'StatusList2021Entry',
    statusPurpose: 'revocation',
    statusListIndex: '7',
    statusListCredential: LIST_URL,
  };
  const credential = await signedWith(delegation(status), keys.assert);
  const unsignedList = await clearList();
  const list = await signedWith(unsignedList, keys.assert);
  const input = (over: { list?: unknown; didDocuments?: unknown } = {}) => ({
    credential,
    statusLists: { [LIST_URL]: over.list ?? list },
    didDocuments: over.didDocuments ?? didDocumentsFor(keys),
    serverDid: SERVER_DID,
  });

  const vectors: ConformanceVector[] = [
    {
      id: 'status-list/assertion-method-key-list',
      category: 'status-list',
      description: "Active delegation whose status list is signed with the key its issuer's DID document lists under assertionMethod",
      expected: 'pass',
      reason: "The list's proof verifies with a key listed under assertionMethod, and the credential's bit is unset",
      input: input(),
    },
    {
      id: 'status-list/authentication-key-list',
      category: 'status-list',
      description: "The same active delegation, its list signed with the key the issuer's DID document lists only under authentication",
      expected: 'fail',
      reason: "A key listed only under authentication does not verify the list (SPEC.md §6.2), so its bits cannot be read and the check fails closed",
      input: input({ list: await signedWith(unsignedList, keys.login) }),
    },
    {
      id: 'status-list/proof-purpose-authentication-list',
      category: 'status-list',
      description: 'The same active delegation, its list\'s proof stating proofPurpose "authentication"',
      expected: 'fail',
      reason: "A list's proof that states a purpose other than assertionMethod is rejected (SPEC.md §6.2), so the check fails closed",
      input: input({ list: statingAuthentication(list) }),
    },
    {
      id: 'status-list/issuer-document-id-mismatch',
      category: 'status-list',
      description: 'The same active delegation and list, with the DID document supplied for their issuer naming another DID as its id',
      expected: 'fail',
      reason: "Only the issuer's own DID document lists the issuer's keys (SPEC.md §6.2); one document serves the credential's proof and its list's, so the credential's proof is rejected before any bit is read",
      input: input({ didDocuments: didDocumentsFor(keys, { id: OTHER_DID }) }),
    },
    {
      id: 'status-list/assertion-key-other-controller-list',
      category: 'status-list',
      description: "The same active delegation, its list signed with #login-1, which the issuer's DID document also lists under assertionMethod but names another DID as the controller of",
      expected: 'fail',
      reason: "A verification method whose controller is another DID is not the issuer's (CID §3.3 step 10, SPEC.md §6.2), so the list's key is not one the issuer lists under assertionMethod, its bits cannot be read, and the check fails closed",
      input: input({
        list: await signedWith(unsignedList, keys.login),
        didDocuments: didDocumentsFor(keys, {
          verificationMethod: [issuerMethod(keys.login, OTHER_DID), issuerMethod(keys.assert)],
          assertionMethod: [keys.assert.id, keys.login.id],
        }),
      }),
    },
    {
      id: 'status-list/assertion-key-defined-twice-list',
      category: 'status-list',
      description: "The same active delegation, its list signed with #login-1, which the issuer's DID document defines in verificationMethod and again embedded in assertionMethod",
      expected: 'fail',
      reason: "A method id the document defines more than once, among verificationMethod and the methods assertionMethod embeds, names no method (SPEC.md §6.2), so the list's key is not found, its bits cannot be read, and the check fails closed",
      input: input({
        list: await signedWith(unsignedList, keys.login),
        didDocuments: didDocumentsFor(keys, { assertionMethod: [keys.assert.id, issuerMethod(keys.login)] }),
      }),
    },
  ];
  return { version: SUITE_VERSION, category: 'status-list', vectors };
}

export async function generateKeyRelationshipVectors(): Promise<void> {
  const keys = await mintIssuerKeys();
  writeVectorFile(await delegationChainKeyRelationshipFile(keys), 'delegation-chain-key-relationship.json');
  writeVectorFile(await statusListKeyRelationshipFile(keys), 'status-list-key-relationship.json');
  console.log('Key-relationship conformance vectors generated.');
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  generateKeyRelationshipVectors().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
