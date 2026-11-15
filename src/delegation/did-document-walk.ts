/**
 * The walk that measures a DID document as JSON data against SPEC §4.4.2, without serializing it,
 * and hands back the document a verifier reads.
 *
 * A document a built-in resolver parsed is walked once: the walk freezes each container as it
 * leaves it and brands the document, so no later check walks it again and nobody can change it
 * after it was measured. A document from a custom resolver is walked strictly on each resolution,
 * and the walk builds a copy as it goes: a plain object of this realm for each object, holding its
 * own enumerable data members, and a plain array of this realm for each array, holding the
 * elements read by index, each value read once. The copy is frozen and branded like a parsed
 * document, and it is what a verifier reads, so a verifier reads exactly what was measured,
 * whatever the resolver's object does afterwards or answers a second time: a replaced or inherited
 * `Symbol.iterator` or array method, a getter on an index, a `Proxy`, a member that is not
 * enumerable, or a change made after the walk. The application keeps the object it returned, which
 * is neither frozen nor changed. The strict walk refuses accessors on object members and anything
 * else JSON could not have produced, and it never calls an object member's getter or `toJSON`. An
 * accessor on an array index, like a Proxy trap, runs once, and the value it gives is the one
 * measured and copied.
 */

import {
  boundedDid, boundedKeyId, MAX_DID_DOCUMENT_BYTES, MAX_DID_LENGTH, MAX_JSON_DEPTH,
  MAX_JSON_MEMBERS, MAX_JSON_MEMBER_LENGTH, MAX_VERIFICATION_ENTRIES,
} from './did-resource-policy.js';
import { isValidDid } from '../utils/did-helpers.js';
import { isRecord } from '../utils/guards.js';
import type { DIDDocument } from './vc-verifier.types.js';

/**
 * A document's compact JSON size in UTF-8 bytes and the document a verifier may read, which is
 * frozen and branded, or why it is refused.
 */
export type DidDocumentMeasure =
  | { readonly ok: true; readonly bytes: number; readonly document: DIDDocument }
  | { readonly ok: false; readonly reason: string };

const RELATIONSHIPS = ['verificationMethod', 'authentication', 'assertionMethod', 'keyAgreement',
  'capabilityInvocation', 'capabilityDelegation'] as const;

/** UTF-8 bytes `JSON.stringify` writes for each code unit below 128. */
const ASCII_WIDTH = new Uint8Array(128).map((_, code) => code < 0x20 ? 6 : 1);
for (const code of [0x08, 0x09, 0x0a, 0x0c, 0x0d, 0x22, 0x5c]) ASCII_WIDTH[code] = 2;

/** Documents the walk measured and froze: one a built-in resolver parsed, or the walk's copy of any other. */
const admitted = new WeakSet<object>();

/** Ends a walk with the reason a document is refused. */
class Refusal extends Error {}

/** Whether `value` is a document a walk handed back, measured and frozen, so it needs no walk. */
export function isAdmittedDidDocument(value: unknown): boolean {
  return typeof value === 'object' && value !== null && admitted.has(value);
}

/**
 * Measure a document a built-in resolver produced with `JSON.parse`, freeze it deeply and brand it.
 * Parsed JSON holds only plain data, so members are read as values too.
 */
export function admitParsedDidDocument(value: unknown): DidDocumentMeasure {
  return measureWith(value, true);
}

/**
 * Measure a document from a custom resolver, strictly, as it is now. Its `document` is the walk's
 * frozen copy of what it measured, and `value` itself is left as it was.
 */
export function measureDidDocument(value: unknown): DidDocumentMeasure {
  return measureWith(value, false);
}

function measureWith(value: unknown, parsed: boolean): DidDocumentMeasure {
  try {
    const walk = new Walk(parsed);
    const document = walk.document(value);
    admitted.add(document);
    return { ok: true, bytes: walk.bytes, document };
  } catch (error) {
    if (error instanceof Refusal) return { ok: false, reason: error.message };
    // A Proxy trap or an accessor on an array index threw: the value is not JSON data.
    return { ok: false, reason: 'document could not be read as JSON data' };
  }
}

class Walk {
  bytes = 0;
  private members = 0;
  /** The containers enclosing the one being walked: at most 64, so a scan is cheaper than a set. */
  private readonly ancestors: object[] = [];

  constructor(private readonly parsed: boolean) {}

  /** The document a verifier may read: `value` itself when it was parsed, else the copy of it. */
  document(value: unknown): DIDDocument {
    if (!isRecord(value)) throw new Refusal('document is not a JSON object');
    const held = this.value(value, 1) as Record<string, unknown>;
    checkIdentifiers(held);
    return held as unknown as DIDDocument;
  }

  private charge(bytes: number): void {
    this.bytes += bytes;
    if (this.bytes > MAX_DID_DOCUMENT_BYTES) throw new Refusal('document byte limit exceeded');
  }

  /** Measures `item` and returns it as a verifier may hold it: a container frozen, or copied and frozen. */
  private value(item: unknown, depth: number): unknown {
    switch (typeof item) {
      case 'string': this.string(item); return item;
      case 'boolean': this.charge(item ? 4 : 5); return item;
      case 'number':
        if (!Number.isFinite(item)) throw new Refusal('number JSON cannot hold');
        this.charge(String(item).length);
        return item;
      case 'object':
        if (item === null) { this.charge(4); return item; }
        return this.container(item, depth);
      default: throw new Refusal(`${typeof item} JSON cannot hold`);
    }
  }

  private string(text: string): void {
    let width = 2;
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i);
      if (code < 0x80) width += ASCII_WIDTH[code]!;
      else if (code < 0x800) width += 2;
      else if (code < 0xd800 || code > 0xdfff) width += 3;
      else if (code <= 0xdbff && isLowSurrogate(text.charCodeAt(i + 1))) { width += 4; i++; }
      else width += 6;
    }
    this.charge(width);
  }

  private container(item: object, depth: number): object {
    if (depth > MAX_JSON_DEPTH) throw new Refusal('nesting limit exceeded');
    // Parsed JSON is a tree; only a custom resolver's document can hold a cycle.
    if (!this.parsed && this.ancestors.includes(item)) throw new Refusal('document has a cycle');
    this.ancestors.push(item);
    this.charge(2);
    let held: object;
    if (Array.isArray(item)) held = this.array(item, depth);
    else if (isPlainObjectOfAnyRealm(item)) held = this.object(item, depth);
    else throw new Refusal('value is neither an array nor a plain object');
    this.ancestors.pop();
    return Object.freeze(held);
  }

  /**
   * Every element costs at least one byte and every comma one more, so the byte limit ends a long
   * array. The length and each element are read once, by index, and no method or iterator of the
   * array is called; a parsed array is kept, and any other is copied into an array of this realm.
   */
  private array(item: unknown[], depth: number): unknown[] {
    const held: unknown[] = this.parsed ? item : [];
    const length = item.length;
    for (let i = 0; i < length; i++) {
      if (!Object.hasOwn(item, i)) throw new Refusal('array is sparse');
      if (i > 0) this.charge(1);
      const element = this.value(item[i], depth + 1);
      if (!this.parsed) held[i] = element;
    }
    return held;
  }

  /** A parsed object is kept; any other is copied, member by member, into a plain object of this realm. */
  private object(item: object, depth: number): object {
    const held: object = this.parsed ? item : {};
    let written = 0;
    const keys = this.parsed ? Object.keys(item) : Reflect.ownKeys(item);
    for (const key of keys) {
      const member = this.parsed ? (item as Record<string, unknown>)[key as string] : dataMember(item, key);
      if (member === undefined) continue;
      if (typeof key !== 'string') throw new Refusal('object has an enumerable symbol key');
      this.members++;
      if (key.length > MAX_JSON_MEMBER_LENGTH || this.members > MAX_JSON_MEMBERS) {
        throw new Refusal('member limit exceeded');
      }
      if (written > 0) this.charge(1);
      written++;
      this.string(key);
      this.charge(1);
      const value = this.value(member, depth + 1);
      // Defined, not assigned: assigning a member named `__proto__` would set the copy's prototype.
      if (!this.parsed) Object.defineProperty(held, key, { value, enumerable: true });
    }
    return held;
  }
}

/**
 * The value of `item`'s own member `key` as `JSON.stringify` would write it: `undefined` for a
 * member it skips, a member that is not enumerable. Refuses an accessor, so no getter runs.
 */
function dataMember(item: object, key: string | symbol): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(item, key)!;
  if (!('value' in descriptor)) throw new Refusal('object has an accessor');
  return descriptor.enumerable ? descriptor.value : undefined;
}

/**
 * The document's `id`, a DID (a string that starts with `did:`) within the limit, and the
 * identifiers its methods and relationships carry, within limits.
 */
function checkIdentifiers(doc: Record<string, unknown>): void {
  const id = ownValue(doc, 'id');
  if (!boundedDid(id) || !isValidDid(id)) throw new Refusal('document id is not a DID within the limit');
  let entries = 0;
  for (const name of RELATIONSHIPS) {
    const list = ownValue(doc, name);
    if (!Array.isArray(list)) continue;
    entries += list.length;
    if (entries > MAX_VERIFICATION_ENTRIES) throw new Refusal('verification entry limit exceeded');
    for (const entry of list as unknown[]) checkEntry(entry);
  }
}

function checkEntry(entry: unknown): void {
  if (typeof entry === 'string') {
    if (!boundedKeyId(entry)) throw new Refusal('key identifier limit exceeded');
    return;
  }
  if (!isRecord(entry)) return;
  const id = ownValue(entry, 'id');
  const controller = ownValue(entry, 'controller');
  if (typeof id === 'string' && !boundedKeyId(id)) throw new Refusal('key identifier limit exceeded');
  if (typeof controller === 'string' && controller.length > MAX_DID_LENGTH) {
    throw new Refusal('controller DID limit exceeded');
  }
}

/** An own data member's value, read without running a getter; the walk has refused accessors. */
function ownValue(object: object, key: string): unknown {
  return Object.getOwnPropertyDescriptor(object, key)?.value;
}

function isLowSurrogate(code: number): boolean {
  return code >= 0xdc00 && code <= 0xdfff;
}

/**
 * Whether `item` is a plain object of any realm, the only kind of object, beside an array, that
 * JSON data holds. It admits a prototype that is:
 * - `null`, or this realm's `Object.prototype`; or
 * - the `Object.prototype` of another realm, since a resolver may parse a document in a `vm`
 *   context or a frame: an object with no prototype of its own, whose `constructor` is a function
 *   named `Object` that points back to it, and whose every own member name, getters and symbols
 *   included, is one this realm's `Object.prototype` has too.
 *
 * So a class instance, a `Date`, a `Map` and a prototype built by hand to carry a document's
 * members are refused, and whatever an admitted object inherits has a name such as `toString` or
 * `hasOwnProperty`, never a name of the DID data model. The walk copies own members only, so a
 * verifier, which reads the copy, reads nothing an object inherits either way; the rule refuses
 * what is not data, and does so without running a getter, reading the constructor's members from
 * their descriptors. `isPlainObjectOfThisRealm` (`utils/guards.ts`) is the stricter rule: it holds
 * configuration to this realm's `Object.prototype` alone.
 */
function isPlainObjectOfAnyRealm(item: object): boolean {
  const proto = Object.getPrototypeOf(item) as object | null;
  if (proto === null || proto === Object.prototype) return true;
  if (Object.getPrototypeOf(proto) !== null) return false;
  const constructor = ownValue(proto, 'constructor');
  return typeof constructor === 'function' && ownValue(constructor, 'name') === 'Object' &&
    ownValue(constructor, 'prototype') === proto &&
    Reflect.ownKeys(proto).every((name) => Object.hasOwn(Object.prototype, name));
}
