/**
 * Delegation credentials for the tests of the delegation verifier and the delegation gate: an
 * issuer's key, and a delegation it signs with a Data Integrity proof or as a VC-JWT. Every one is
 * signed with a real Ed25519 key.
 */

import { NodeCryptoProvider } from './node-crypto-provider.js';
import { createRealSigningFunction } from '../audit/helpers/crypto-helpers.js';
import { DelegationCredentialIssuer } from '../../delegation/vc-issuer.js';
import { canonicalizeJSON, completeVCJWT, createUnsignedVCJWT } from '../../delegation/utils.js';
import { wrapDelegationAsVC, type DelegationCredential, type DelegationRecord } from '../../types/protocol.js';
import type { AgentIdentity } from '../../providers/base.js';

const crypto = new NodeCryptoProvider();

/** A fresh Ed25519 key of `did`'s, with the id `did#fragment`. */
export async function keyOf(did: string, fragment: string): Promise<AgentIdentity> {
  const { privateKey, publicKey } = await crypto.generateKeyPair();
  return { did, kid: `${did}#${fragment}`, privateKey, publicKey, type: 'development', createdAt: new Date().toISOString() };
}

const unique = (): string => Math.random().toString(16).slice(2);

/**
 * A delegation by `issuerDid` to `did:web:agent.example` for `orders:place`, valid for an hour, with
 * an id of its own unless `overrides` gives one, and any other member `overrides` gives.
 */
export function delegationRecord(issuerDid: string, overrides: Partial<DelegationRecord> = {}): DelegationRecord {
  return {
    id: `del-${unique()}`,
    issuerDid,
    subjectDid: 'did:web:agent.example',
    vcId: `urn:uuid:${unique()}`,
    constraints: { scopes: ['orders:place'], notAfter: Math.floor(Date.now() / 1000) + 3600 },
    signature: '',
    status: 'active',
    createdAt: Date.now(),
    ...overrides,
  };
}

/** How a test signs a delegation: the delegation (default: one by the key's DID), and the key id it names. */
export interface Signing {
  readonly record?: DelegationRecord;
  readonly kid?: string;
}

/** `record` as a credential with a Data Integrity proof `key` makes, naming `kid` (default: `key`'s own id). */
export function signedCredential(
  key: AgentIdentity,
  { record = delegationRecord(key.did), kid = key.kid }: Signing = {},
): Promise<DelegationCredential> {
  return new DelegationCredentialIssuer(
    { getDid: () => record.issuerDid, getKeyId: () => kid, getPrivateKey: () => key.privateKey },
    createRealSigningFunction(crypto, key),
  ).issueDelegationCredential(record);
}

/** A VC-JWT whose envelope `key` signs over `encodedPayload`, with `kid` in its header if given, even empty or not a string. */
export async function envelope(key: AgentIdentity, encodedPayload: string, kid?: unknown): Promise<string> {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT', ...(kid === undefined ? {} : { kid }) }));
  const signingInput = `${header.toString('base64url')}.${encodedPayload}`;
  const signature = await crypto.sign(new TextEncoder().encode(signingInput), key.privateKey);
  return completeVCJWT(signingInput, Buffer.from(signature).toString('base64url'));
}

/**
 * `record` (default: one by `key`'s DID) as a VC-JWT whose envelope `key` signs, with `kid` in its
 * header if given, even empty or not a string, over its payload's JSON text as `edit` rewrites it.
 */
export function signedJwt(
  key: AgentIdentity,
  { record = delegationRecord(key.did), kid, edit = (json) => json }:
    { record?: DelegationRecord; kid?: unknown; edit?: (json: string) => string } = {},
): Promise<string> {
  const { payload } = createUnsignedVCJWT(wrapDelegationAsVC(record) as unknown as Record<string, unknown>);
  return envelope(key, Buffer.from(edit(JSON.stringify(payload))).toString('base64url'), kid);
}

/** A delegation by `key`'s DID with `issuer` as its issuer, as written, and a Data Integrity proof `key` makes over it naming `kid`. */
export async function credentialNaming(key: AgentIdentity, issuer: unknown, kid: string = key.kid): Promise<DelegationCredential> {
  const unsigned = { ...wrapDelegationAsVC(delegationRecord(key.did)), issuer };
  const proof = await createRealSigningFunction(crypto, key)(canonicalizeJSON(unsigned), key.did, kid);
  return { ...unsigned, proof } as unknown as DelegationCredential;
}

/** A VC-JWT `key` signs whose claims are `claims` and a delegation by `key`'s DID with `issuer` as its issuer, as written. */
export function jwtClaiming(key: AgentIdentity, claims: Record<string, unknown>, issuer: unknown, kid?: string): Promise<string> {
  const vc = { ...wrapDelegationAsVC(delegationRecord(key.did)), issuer };
  return envelope(key, Buffer.from(JSON.stringify({ ...claims, vc })).toString('base64url'), kid);
}
