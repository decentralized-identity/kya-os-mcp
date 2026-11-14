/**
 * Delegation credentials for the tests of the delegation verifier and the delegation gate: an
 * issuer's key, a delegation it signs with a Data Integrity proof or as a VC-JWT, and a credential
 * signed again, changed or by another key. Every one is signed with a real Ed25519 key.
 */

import { NodeCryptoProvider } from './node-crypto-provider.js';
import { createRealSigningFunction } from '../audit/helpers/crypto-helpers.js';
import { DelegationCredentialIssuer } from '../../delegation/vc-issuer.js';
import { canonicalizeJSON, completeVCJWT, createUnsignedVCJWT } from '../../delegation/utils.js';
import { wrapDelegationAsVC, type CredentialStatus, type DelegationCredential, type DelegationRecord } from '../../types/protocol.js';
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

/**
 * How a test signs a delegation: the delegation (default: one by the key's DID), the key id it
 * names, and the credential's `credentialStatus`, if any.
 */
export interface Signing {
  readonly record?: DelegationRecord;
  readonly kid?: string;
  readonly credentialStatus?: CredentialStatus;
}

/** `record` as a credential with a Data Integrity proof `key` makes, naming `kid` (default: `key`'s own id). */
export function signedCredential(
  key: AgentIdentity,
  { record = delegationRecord(key.did), kid = key.kid, credentialStatus }: Signing = {},
): Promise<DelegationCredential> {
  return new DelegationCredentialIssuer(
    { getDid: () => record.issuerDid, getKeyId: () => kid, getPrivateKey: () => key.privateKey },
    createRealSigningFunction(crypto, key),
  ).issueDelegationCredential(record, { credentialStatus });
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
  { record = delegationRecord(key.did), kid, credentialStatus, edit = (json) => json }:
    { kid?: unknown; edit?: (json: string) => string } & Omit<Signing, 'kid'> = {},
): Promise<string> {
  const vc = wrapDelegationAsVC(record, { credentialStatus });
  const { payload } = createUnsignedVCJWT(vc as unknown as Record<string, unknown>);
  return envelope(key, Buffer.from(edit(JSON.stringify(payload))).toString('base64url'), kid);
}

/**
 * `credential` with `changes` made to it, and a Data Integrity proof `key` makes over the result
 * naming `kid` (default: `key`'s own id). The proof verifies only under a key of the issuer the
 * result names, so a test forges a credential by signing one that names another issuer, or another's
 * key id.
 */
export async function resignedCredential(
  credential: Omit<DelegationCredential, 'proof'>,
  changes: Partial<Record<keyof DelegationCredential, unknown>>,
  key: AgentIdentity,
  kid: string = key.kid,
): Promise<DelegationCredential> {
  const { proof: _proof, ...unsigned } = credential as DelegationCredential;
  const changed = { ...unsigned, ...changes };
  const proof = await createRealSigningFunction(crypto, key)(canonicalizeJSON(changed), key.did, kid);
  return { ...changed, proof } as unknown as DelegationCredential;
}

/** A delegation by `key`'s DID with `issuer` as its issuer, as written, and a Data Integrity proof `key` makes over it naming `kid`. */
export function credentialNaming(key: AgentIdentity, issuer: unknown, kid: string = key.kid): Promise<DelegationCredential> {
  return resignedCredential(wrapDelegationAsVC(delegationRecord(key.did)), { issuer }, key, kid);
}

/**
 * `credential`, without its proof, as a VC-JWT whose envelope `key` signs, with `kid` (default:
 * `key`'s own id) in its header and `claims` set over its payload's.
 */
export function credentialJwt(
  credential: DelegationCredential,
  key: AgentIdentity,
  { kid = key.kid, claims = {} }: { kid?: string; claims?: Record<string, unknown> } = {},
): Promise<string> {
  const { proof: _proof, ...unsigned } = credential;
  const { payload } = createUnsignedVCJWT(unsigned);
  return envelope(key, Buffer.from(JSON.stringify({ ...payload, ...claims })).toString('base64url'), kid);
}

/** A VC-JWT `key` signs whose claims are `claims` and a delegation by `key`'s DID with `issuer` as its issuer, as written. */
export function jwtClaiming(key: AgentIdentity, claims: Record<string, unknown>, issuer: unknown, kid?: string): Promise<string> {
  const vc = { ...wrapDelegationAsVC(delegationRecord(key.did)), issuer };
  return envelope(key, Buffer.from(JSON.stringify({ ...claims, vc })).toString('base64url'), kid);
}
