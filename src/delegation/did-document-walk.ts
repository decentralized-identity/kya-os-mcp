/**
 * The walk that measures a DID document as JSON data against SPEC §4.4.2, without serializing it.
 *
 * A document a built-in resolver parsed is walked once: the walk freezes each container as it
 * leaves it and brands the document, so no later check walks it again and nobody can change it
 * after it was measured. A document from a custom resolver is walked strictly on each resolution,
 * and neither copied nor frozen, so the application keeps the object it returned: the walk refuses
 * accessors on object members and anything else JSON could not have produced, and it never calls a
 * getter or `toJSON`. Array elements are read as values in both walks: a descriptor
 * read per index costs about eight times as much, and an accessor on an array index, like a Proxy
 * trap, can only come from application code.
 */

import {
  boundedDid, boundedKeyId, MAX_DID_DOCUMENT_BYTES, MAX_DID_LENGTH, MAX_JSON_DEPTH,
  MAX_JSON_MEMBERS, MAX_JSON_MEMBER_LENGTH, MAX_VERIFICATION_ENTRIES,
} from './did-resource-policy.js';
import { isValidDid } from '../utils/did-helpers.js';

/** A document's compact JSON size in UTF-8 bytes, or why it is refused. */
export type DidDocumentMeasure =
  | { readonly ok: true; readonly bytes: number }
  | { readonly ok: false; readonly reason: string };

const RELATIONSHIPS = ['verificationMethod', 'authentication', 'assertionMethod', 'keyAgreement',
  'capabilityInvocation', 'capabilityDelegation'] as const;

/** UTF-8 bytes `JSON.stringify` writes for each code unit below 128. */
const ASCII_WIDTH = new Uint8Array(128).map((_, code) => code < 0x20 ? 6 : 1);
for (const code of [0x08, 0x09, 0x0a, 0x0c, 0x0d, 0x22, 0x5c]) ASCII_WIDTH[code] = 2;

/** Documents a built-in resolver parsed, measured and froze. */
const admitted = new WeakSet<object>();

/** Ends a walk with the reason a document is refused. */
class Refusal extends Error {}

/** Whether `value` is a document {@link admitParsedDidDocument} admitted, so it needs no walk. */
export function isAdmittedDidDocument(value: unknown): boolean {
  return typeof value === 'object' && value !== null && admitted.has(value);
}

/**
 * Measure a document a built-in resolver produced with `JSON.parse`, freeze it deeply and brand it.
 * Parsed JSON holds only plain data, so members are read as values too.
 */
export function admitParsedDidDocument(value: unknown): DidDocumentMeasure {
  const measure = measureWith(value, true);
  if (measure.ok) admitted.add(value as object);
  return measure;
}

/** Measure a document from a custom resolver, strictly, as it is now. */
export function measureDidDocument(value: unknown): DidDocumentMeasure {
  return measureWith(value, false);
}

function measureWith(value: unknown, parsed: boolean): DidDocumentMeasure {
  try {
    const bytes = new Walk(parsed).document(value);
    return { ok: true, bytes };
  } catch (error) {
    if (error instanceof Refusal) return { ok: false, reason: error.message };
    // A Proxy trap or an accessor on an array index threw: the value is not JSON data.
    return { ok: false, reason: 'document could not be read as JSON data' };
  }
}

class Walk {
  private bytes = 0;
  private members = 0;
  /** The containers enclosing the one being walked: at most 64, so a scan is cheaper than a set. */
  private readonly ancestors: object[] = [];

  constructor(private readonly parsed: boolean) {}

  document(value: unknown): number {
    if (!isObjectRecord(value)) throw new Refusal('document is not a JSON object');
    this.value(value, 1);
    checkIdentifiers(value);
    return this.bytes;
  }

  private charge(bytes: number): void {
    this.bytes += bytes;
    if (this.bytes > MAX_DID_DOCUMENT_BYTES) throw new Refusal('document byte limit exceeded');
  }

  private value(item: unknown, depth: number): void {
    switch (typeof item) {
      case 'string': this.string(item); return;
      case 'boolean': this.charge(item ? 4 : 5); return;
      case 'number':
        if (!Number.isFinite(item)) throw new Refusal('number JSON cannot hold');
        this.charge(String(item).length);
        return;
      case 'object':
        if (item === null) { this.charge(4); return; }
        this.container(item, depth);
        return;
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

  private container(item: object, depth: number): void {
    if (depth > MAX_JSON_DEPTH) throw new Refusal('nesting limit exceeded');
    // Parsed JSON is a tree; only a custom resolver's document can hold a cycle.
    if (!this.parsed && this.ancestors.includes(item)) throw new Refusal('document has a cycle');
    this.ancestors.push(item);
    this.charge(2);
    if (Array.isArray(item)) this.array(item, depth);
    else if (isPlainObject(item)) this.object(item, depth);
    else throw new Refusal('value is neither an array nor a plain object');
    this.ancestors.pop();
    if (this.parsed) Object.freeze(item);
  }

  /** Every element costs at least one byte and every comma one more, so the byte limit ends a long array. */
  private array(item: unknown[], depth: number): void {
    for (let i = 0; i < item.length; i++) {
      if (!Object.hasOwn(item, i)) throw new Refusal('array is sparse');
      if (i > 0) this.charge(1);
      this.value(item[i], depth + 1);
    }
  }

  private object(item: object, depth: number): void {
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
      this.value(member, depth + 1);
    }
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
  if (!isObjectRecord(entry)) return;
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

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isLowSurrogate(code: number): boolean {
  return code >= 0xdc00 && code <= 0xdfff;
}

/**
 * Whether `item` is a plain object: its prototype is `null` or some realm's `Object.prototype`,
 * which is the prototype of no other object and has a `constructor` named `Object` that points
 * back to it. A class instance, a `Date` or a `Map` is refused.
 */
function isPlainObject(item: object): boolean {
  const proto = Object.getPrototypeOf(item) as object | null;
  if (proto === null || proto === Object.prototype) return true;
  if (Object.getPrototypeOf(proto) !== null) return false;
  const constructor = ownValue(proto, 'constructor');
  return typeof constructor === 'function' && constructor.name === 'Object' &&
    ownValue(constructor, 'prototype') === proto;
}
