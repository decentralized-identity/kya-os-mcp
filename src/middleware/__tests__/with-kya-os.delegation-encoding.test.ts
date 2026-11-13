/**
 * What the delegation gate, and a session grant, must be able to encode of a delegation it
 * verified. A credential sent with a Data Integrity proof must encode whole. Of a VC-JWT only the
 * members whose values the gate hands on, into its audit record, the authorization context a tool
 * and a policy gate receive, and its grant, must: the credential's `id` and its delegation's `id`,
 * from which the delegation reference is taken, its subject's `id`, its delegation's `controller`
 * and `parentId`, and both lists of its scopes. RFC 8785 refuses a lone surrogate, an integer
 * beyond 2^53 and a number beyond the double range, which `JSON.parse` reads as `Infinity`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { isEncodableDelegation } from '../with-kya-os.delegation-encoding.js';
import type { DelegationCredential } from '../../types/protocol.js';
import { delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';

/** Three segments that are no base64url of anything: the check hands a VC-JWT on without reading it. */
const JWT = 'header.payload.signature';

let signed: DelegationCredential;
beforeAll(async () => {
  const record = delegationRecord('did:web:acme.example', { controller: 'did:web:user.example', parentId: 'del-0' });
  signed = await signedCredential(await keyOf('did:web:acme.example', 'k'), { record });
});

/** A delegation credential with a parent and a controller, every member of which encodes: a copy a test may write to. */
const encodableCredential = (): DelegationCredential => structuredClone(signed);

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

describe('isEncodableDelegation', () => {
  it('takes a credential every member of which encodes, with a Data Integrity proof or as a VC-JWT', () => {
    expect(isEncodableDelegation(encodableCredential(), undefined)).toBe(true);
    expect(isEncodableDelegation(encodableCredential(), JWT)).toBe(true);
  });

  it.each(UNENCODABLE)('refuses a credential with a Data Integrity proof holding %s anywhere', (_, value) => {
    for (const path of [['proof', 'extra'], ['credentialSubject', 'delegation', 'metadata'], ...HANDED_ON.map(([, at]) => at)]) {
      expect(isEncodableDelegation(holding(path, value), undefined)).toBe(false);
    }
  });

  it.each(UNENCODABLE)('takes a VC-JWT whose members it does not hand on hold %s', (_, value) => {
    for (const path of [['credentialSubject', 'delegation', 'createdAt'], ['credentialSubject', 'delegation', 'metadata'], ['expirationDate']]) {
      expect(isEncodableDelegation(holding(path, value), JWT)).toBe(true);
    }
  });

  it.each(HANDED_ON)('refuses a VC-JWT whose value of %s does not encode', (_, path) => {
    for (const [, value] of UNENCODABLE) {
      expect(isEncodableDelegation(holding(path, value), JWT)).toBe(false);
    }
    expect(isEncodableDelegation(holding(path, { nested: ['x\uDC00'] }), JWT)).toBe(false);
  });

  it('takes a VC-JWT whose optional members it hands on are absent or hold any value that encodes', () => {
    const vc = encodableCredential() as unknown as { id?: unknown; credentialSubject: { delegation: Record<string, unknown> & { constraints: Record<string, unknown> } } };
    delete vc.id;
    delete vc.credentialSubject.delegation.controller;
    delete vc.credentialSubject.delegation.parentId;
    delete vc.credentialSubject.delegation.scopes;
    delete vc.credentialSubject.delegation.constraints.scopes;
    expect(isEncodableDelegation(vc as unknown as DelegationCredential, JWT)).toBe(true);
    for (const value of [null, 7, '\u{1F600}', { id: 'x' }, ['y']]) {
      expect(isEncodableDelegation(holding(['credentialSubject', 'delegation', 'parentId'], value), JWT)).toBe(true);
    }
  });

  it('refuses a VC-JWT holding one scope it cannot encode among others, in either list of scopes', () => {
    for (const path of [['credentialSubject', 'delegation', 'scopes'], ['credentialSubject', 'delegation', 'constraints', 'scopes']]) {
      expect(isEncodableDelegation(holding(path, ['orders:place', 'x\uD800']), JWT)).toBe(false);
      expect(isEncodableDelegation(holding(path, ['orders:place', 'x\u{1F600}']), JWT)).toBe(true);
    }
  });
});
