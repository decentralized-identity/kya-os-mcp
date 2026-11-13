/**
 * DID documents for the tests of verifiers that take an issuer's key from its DID document. Acme,
 * `did:web:acme.example`, is the issuer most of them use: it signs in with one key, listed under
 * `authentication`, and issues with another, listed under `assertionMethod`.
 */

import type { DIDDocument, VerificationMethod } from '../../delegation/vc-verifier.types.js';
import { base58Encode } from '../../utils/base58.js';

/** Acme's DID. */
export const ACME = 'did:web:acme.example';
/** A DID that is not Acme's. */
export const OTHER = 'did:web:other.example';

/** A key a DID document publishes: its DID, its id, and its raw Ed25519 public key in base64. */
export interface PublishedKey {
  readonly did: string;
  readonly kid: string;
  readonly publicKey: string;
}

/**
 * The DID document of `method.controller`, the issuer: it publishes `method` and `others` in
 * `verificationMethod`, and lists `method`, by its id, under `assertionMethod`, the relationship a
 * delegation credential's or a status list's key must be listed under.
 */
export function issuerDidDocument(method: VerificationMethod, ...others: VerificationMethod[]): DIDDocument {
  return { id: method.controller, verificationMethod: [method, ...others], assertionMethod: [method.id] };
}

/**
 * How a method publishes a key: its `id` as written (default: the key's absolute id), its
 * `controller` (default: the key's DID), and its key as a JWK or, as cheqd publishes it, as a
 * multibase Ed25519 public key.
 */
export interface MethodOptions {
  readonly id?: string;
  readonly controller?: string;
  readonly form?: 'jwk' | 'multibase';
}

/** The verification method that publishes `key`, as `options` say. */
export function methodOf(key: PublishedKey, { id = key.kid, controller = key.did, form = 'jwk' }: MethodOptions = {}): VerificationMethod {
  const raw = Buffer.from(key.publicKey, 'base64');
  return form === 'jwk'
    ? { id, type: 'JsonWebKey2020', controller, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') } }
    : { id, type: 'Ed25519VerificationKey2020', controller, publicKeyMultibase: `z${base58Encode(new Uint8Array([0xed, 0x01, ...raw]))}` };
}

/** A method with no key, for a test of which method a lookup finds: its `id` as written, and its `controller` (default: Acme). */
export function keylessMethod(id: string, controller: string = ACME): VerificationMethod {
  return { id, type: 'JsonWebKey', controller };
}

/** A DID document with `members` beside its `id` (default: Acme's), written as given. */
export function documentOf(members: Record<string, unknown>, id: string = ACME): DIDDocument {
  return { id, ...members } as DIDDocument;
}

/** Acme's document: `login` published and listed under `authentication`, `assert` under `assertionMethod`. */
export function acmeDocument(login: PublishedKey, assert: PublishedKey): DIDDocument {
  return documentOf({
    verificationMethod: [methodOf(login), methodOf(assert)],
    authentication: [login.kid],
    assertionMethod: [assert.kid],
  });
}

/**
 * Why the method `name` names, which `did`'s document lists under `assertionMethod`, is refused for
 * naming `other` as its `member`, as a verifier quotes each value.
 */
export function anotherDidReason(
  name: string,
  member: 'controller' | "document's id",
  { did = ACME, other = OTHER }: { did?: string; other?: string } = {},
): string {
  const [quotedName, quotedDid, quotedOther] = [name, did, other].map((value) => JSON.stringify(value));
  return `Verification method ${quotedName} under assertionMethod of ${quotedDid} has another DID as its ${member}: ${quotedOther}`;
}
