/**
 * What the delegation gate must be able to encode of a delegation it verified, and the bytes it
 * takes the delegation's digest over. A credential sent with a Data Integrity proof is digested in
 * RFC 8785 form, so all of it must encode. A VC-JWT is digested as the JWT, so only the members
 * whose values the gate hands on, into its audit record, the authorization context a tool and a
 * policy gate receive, and its grant, must: the credential's `id` and its delegation's `id`, from
 * which the delegation reference is taken, its subject's `id`, its delegation's `controller` and
 * `parentId`, and both lists of its scopes. RFC 8785 refuses a lone surrogate, an integer beyond
 * 2^53 and a number beyond the double range, which `JSON.parse` reads as `Infinity`. A session
 * grant makes the same check without taking the bytes, and every case here checks that it decides
 * as the gate does.
 */
import { describe, it, expect } from 'vitest';
import { encodableDelegationBytes, isEncodableDelegation } from '../with-kya-os.delegation-encoding.js';
import { canonicalizeJsonBytes } from '../../utils/canonical-json.js';
import { wrapDelegationAsVC, type DelegationCredential } from '../../types/protocol.js';

const JWT = 'header.payload.signature';

/** A delegation credential with a parent and a controller, every member of which encodes. */
const encodableCredential = (): DelegationCredential => ({
  ...wrapDelegationAsVC({
    id: 'del-1',
    issuerDid: 'did:web:acme.example',
    subjectDid: 'did:web:agent.example',
    vcId: 'urn:uuid:1',
    controller: 'did:web:user.example',
    parentId: 'del-0',
    constraints: { scopes: ['orders:place'] },
    signature: '',
    status: 'active',
    createdAt: 1_750_000_000_000,
  }),
  proof: { type: 'Ed25519Signature2020', proofValue: 'z', verificationMethod: 'did:web:acme.example#k' },
}) as DelegationCredential;

/** `encodableCredential()` with `value` written at `path`, as a parsed JSON value would hold it. */
function holding(path: string[], value: unknown): DelegationCredential {
  const vc = encodableCredential() as unknown as Record<string, unknown>;
  let parent = vc;
  for (const key of path.slice(0, -1)) parent = parent[key] as Record<string, unknown>;
  parent[path.at(-1)!] = value;
  return vc as unknown as DelegationCredential;
}

const HANDED_ON: [string, string[]][] = [
  ['the credential id', ['id']],
  ['the subject id', ['credentialSubject', 'id']],
  ['the delegation id', ['credentialSubject', 'delegation', 'id']],
  ['the controller', ['credentialSubject', 'delegation', 'controller']],
  ['the parent id', ['credentialSubject', 'delegation', 'parentId']],
  ['the scopes', ['credentialSubject', 'delegation', 'scopes']],
  ['the scopes of its constraints', ['credentialSubject', 'delegation', 'constraints', 'scopes']],
];
const UNENCODABLE: [string, unknown][] = [
  ['a lone surrogate', 'x\uD800'],
  ['an integer beyond 2^53', 9_007_199_254_740_995],
  ['a number beyond the double range', JSON.parse('1e400')],
];

/**
 * The bytes `encodableDelegationBytes` takes the digest over, once `isEncodableDelegation`, the
 * check a session grant makes, has decided the same: whether there are any.
 */
function bytesOf(vc: DelegationCredential, jwt: string | undefined): Uint8Array | undefined {
  const bytes = encodableDelegationBytes(vc, jwt);
  expect(isEncodableDelegation(vc, jwt)).toBe(bytes !== undefined);
  return bytes;
}

describe('encodableDelegationBytes and isEncodableDelegation', () => {
  it('takes the digest of a credential with a Data Integrity proof over its RFC 8785 bytes', () => {
    const vc = encodableCredential();
    expect(bytesOf(vc, undefined)).toEqual(canonicalizeJsonBytes(vc));
  });

  it('takes the digest of a VC-JWT over the JWT as it arrived', () => {
    expect(bytesOf(encodableCredential(), JWT)).toEqual(new TextEncoder().encode(JWT));
  });

  it.each(UNENCODABLE)('refuses a credential with a Data Integrity proof holding %s anywhere', (_, value) => {
    for (const path of [['proof', 'extra'], ['credentialSubject', 'delegation', 'metadata'], ...HANDED_ON.map(([, at]) => at)]) {
      expect(bytesOf(holding(path, value), undefined)).toBeUndefined();
    }
  });

  it.each(UNENCODABLE)('takes a VC-JWT whose members it does not hand on hold %s', (_, value) => {
    for (const path of [['credentialSubject', 'delegation', 'createdAt'], ['credentialSubject', 'delegation', 'metadata'], ['expirationDate']]) {
      expect(bytesOf(holding(path, value), JWT)).toEqual(new TextEncoder().encode(JWT));
    }
  });

  it.each(HANDED_ON)('refuses a VC-JWT whose value of %s does not encode', (_, path) => {
    for (const [, value] of UNENCODABLE) {
      expect(bytesOf(holding(path, value), JWT)).toBeUndefined();
    }
    expect(bytesOf(holding(path, { nested: ['x\uDC00'] }), JWT)).toBeUndefined();
  });

  it('takes a VC-JWT whose optional members it hands on are absent or hold any value that encodes', () => {
    const vc = encodableCredential() as unknown as { id?: unknown; credentialSubject: { delegation: Record<string, unknown> & { constraints: Record<string, unknown> } } };
    delete vc.id;
    delete vc.credentialSubject.delegation.controller;
    delete vc.credentialSubject.delegation.parentId;
    delete vc.credentialSubject.delegation.scopes;
    delete vc.credentialSubject.delegation.constraints.scopes;
    expect(bytesOf(vc as unknown as DelegationCredential, JWT)).toEqual(new TextEncoder().encode(JWT));
    for (const value of [null, 7, '\u{1F600}', { id: 'x' }, ['y']]) {
      expect(bytesOf(holding(['credentialSubject', 'delegation', 'parentId'], value), JWT)).toEqual(new TextEncoder().encode(JWT));
    }
  });

  it('refuses a VC-JWT holding one scope it cannot encode among others, in either list of scopes', () => {
    for (const path of [['credentialSubject', 'delegation', 'scopes'], ['credentialSubject', 'delegation', 'constraints', 'scopes']]) {
      expect(bytesOf(holding(path, ['orders:place', 'x\uD800']), JWT)).toBeUndefined();
      expect(bytesOf(holding(path, ['orders:place', 'x\u{1F600}']), JWT)).toEqual(new TextEncoder().encode(JWT));
    }
  });
});
