/**
 * Slow reference for the package's own-issuer profile of CID §3.3. Deliberately constructs absolute
 * ids and filters whole arrays; shares no lookup, normalization or method-shape code with production.
 * This is not a general URL/media-type dereferencer: the profile is the one the lookup's module
 * comment states, and SPEC.md §6.2 for a delegation credential's key.
 */
import { describe, it, expect } from 'vitest';
import {
  retrieveVerificationMethod,
  selectAssertionMethod,
  type AssertionMethodSelection,
  type VerificationRelationship,
} from '../verification-relationship.js';
import type { DIDDocument, VerificationMethod } from '../vc-verifier.types.js';

const ownMap = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

/**
 * The method `key` names for `did` under `relationship`. With `owned` false, the document's id and
 * the method's controller may name any DID, so that what that alone refuses can be told apart.
 */
function reference(doc: DIDDocument, did: string, key: string, relationship: VerificationRelationship, owned = true): VerificationMethod | undefined {
  // Steps 1 to 4: issuer-local, literal identifier profile; the caller already resolved its document.
  if (did.includes('#')) return undefined;
  const absolute = (id: unknown): string | undefined => {
    if (typeof id !== 'string') return undefined;
    if (id[0] === '#') return did + id;
    return id === did || id.startsWith(did + '#') ? id : undefined;
  };
  const url = absolute(key);
  // Steps 5 and 6: document identity / expected relationship shape.
  if (url === undefined || (owned && doc.id !== did)) return undefined;
  const entries: unknown = doc[relationship];
  if (!Array.isArray(entries)) return undefined;
  // Step 7: the profile searches published methods and values in the selected relationship.
  // Undefined duplicate resolution in CID is tightened to an unconditional rejection here.
  const definitions: unknown[] = [...(Array.isArray(doc.verificationMethod) ? doc.verificationMethod : []),
    ...entries.filter(ownMap)];
  const matches = definitions.filter(value => ownMap(value) && absolute(value.id) === url);
  if (matches.length !== 1) return undefined;
  const vm = matches[0];
  // Steps 8 to 10: shape, id equality (above), own controller.
  if (!ownMap(vm) || !['id', 'type', 'controller'].every(name => typeof vm[name] === 'string' && vm[name] !== '')) return undefined;
  if (owned && vm.controller !== did) return undefined;
  // Step 11: relationship association by reference or value; step 12 returns that exact object.
  return entries.some(entry => absolute(ownMap(entry) ? entry.id : entry) === url) ? vm as unknown as VerificationMethod : undefined;
}

/**
 * The SPEC.md §6.2 selection by `named`, or by the first assertionMethod entry when it is undefined;
 * a method that only its document's id or its controller keeps from being selected belongs to that DID.
 */
function referenceSelection(doc: DIDDocument, did: string, named: unknown): AssertionMethodSelection {
  if (named !== undefined && (typeof named !== 'string' || named === '')) return { refused: 'not a name' };
  const refused = named === undefined ? 'no usable first entry' : 'not listed';
  const entries: unknown = doc.assertionMethod;
  const first: unknown = Array.isArray(entries) ? entries[0] : undefined;
  const name = named ?? (ownMap(first) ? first.id : first);
  if (typeof name !== 'string') return { refused };
  const method = reference(doc, did, name, 'assertionMethod');
  if (method !== undefined) return { method };
  const unowned = reference(doc, did, name, 'assertionMethod', false);
  if (unowned === undefined || (doc.id !== did && typeof doc.id !== 'string')) return { refused };
  const [member, other] = doc.id !== did ? ["document's id", doc.id] : ['controller', unowned.controller];
  const reason = `Verification method ${JSON.stringify(name)} under assertionMethod of ${JSON.stringify(did)} has another DID as its ${member}: ${JSON.stringify(other)}`;
  return { refused: 'another DID', reason };
}

/** Whether two selections agree: the very same method, or the same refusal and reason. */
const sameSelection = (a: AssertionMethodSelection, b: AssertionMethodSelection): boolean =>
  'method' in a ? 'method' in b && a.method === b.method : !('method' in b) && JSON.stringify(a) === JSON.stringify(b);

const did = 'did:web:reference.example';
/** Another DID exactly as long as `did`, so that only its characters tell the two apart. */
const sameLength = 'did:web:elsewhere.example';
const vm = (id: string, controller = did) => ({ id, type: 'JsonWebKey', controller });
const entries: unknown[] = [null, 7, [], { id: 7 }, '#a', `${did}#a`, '#missing', did, 'bad',
  vm('#a'), vm(`${did}#a`), vm('#a', 'did:web:other.example'), { id: '#a' }, vm('#b'), vm(did),
  vm(`${did}/path#a`), vm('did:web:other.example#a')];
/** What the generator draws from: every entry, and a reference and a method under `sameLength`. */
const generated: unknown[] = [...entries, `${sameLength}#a`, vm(`${sameLength}#a`)];
const names = ['#a', `${did}#a`, '#b', '#missing', did, `${did}/path#a`, 'bad', `${sameLength}#a`];
/** What a proof may name its key by: each name, no name, and values that name none. */
const named: unknown[] = [...names, undefined, '', 7, null];
const relationships: VerificationRelationship[] = ['assertionMethod', 'authentication', 'keyAgreement', 'capabilityInvocation', 'capabilityDelegation'];

/**
 * Every lookup on which the two disagree, as `relationship name` (or `selection name`) with the
 * document. Compared without `expect` and asserted once per test, since an `expect` per lookup costs
 * more than the lookups themselves across the hundreds of thousands these tests make.
 */
function disagreements(doc: DIDDocument, requestedDid = did): string[] {
  const found: string[] = [];
  for (const relationship of relationships) {
    for (const name of names) {
      if (retrieveVerificationMethod(doc, requestedDid, name, relationship) !== reference(doc, requestedDid, name, relationship)) {
        found.push(`${relationship} ${name} in ${JSON.stringify(doc)} for ${requestedDid}`);
      }
    }
  }
  for (const name of named) {
    if (!sameSelection(selectAssertionMethod(doc, requestedDid, name), referenceSelection(doc, requestedDid, name))) {
      found.push(`selection ${String(name)} in ${JSON.stringify(doc)} for ${requestedDid}`);
    }
  }
  return found;
}

describe('lookup agrees with an independent reference', () => {
  it('exhausts every pair of malformed, duplicate, embedded and referenced entries', () => {
    const found: string[] = [];
    for (const published of entries) for (const first of entries) for (const second of entries) {
      found.push(...disagreements({ id: did, verificationMethod: [published], assertionMethod: [first, second],
        authentication: [vm('#b')] } as DIDDocument));
    }
    expect(found.slice(0, 5)).toEqual([]);
  });

  it('agrees on generated mixed relationships, different document identities and definitions', () => {
    expect(sameLength).toHaveLength(did.length);
    let seed = 17429;
    const random = (length: number) => { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return (seed >>> 0) % length; };
    const list = () => Array.from({ length: random(7) }, () => generated[random(generated.length)]);
    const found: string[] = [];
    for (let i = 0; i < 2_000; i++) {
      const doc = JSON.parse(JSON.stringify({
        id: i % 11 === 0 ? 'did:web:other.example' : did,
        verificationMethod: list(),
        ...Object.fromEntries(relationships.map(name => [name, random(5) === 0 ? null : list()])),
      })) as DIDDocument;
      found.push(...disagreements(doc, i % 13 === 0 ? `${did}#fragment` : did));
    }
    expect(found.slice(0, 5)).toEqual([]);
  });
});
