/**
 * The walk measures a document as `JSON.stringify` would write it, compact and in UTF-8, without
 * serializing it; refuses what JSON could not hold; accepts a plain object from any realm; and
 * freezes and brands a document a built-in resolver parsed, so nothing walks it again. The token
 * preflight before `JSON.parse` counts members and nesting as the parsed document will have them.
 */

import vm from 'node:vm';
import { describe, expect, it, vi } from 'vitest';
import { admitParsedDidDocument, isAdmittedDidDocument, measureDidDocument } from '../did-document-walk.js';
import { DID_DOCUMENT_JSON, MAX_JSON_MEMBERS, MAX_JSON_MEMBER_LENGTH } from '../did-resource-policy.js';
import { resolveBoundedDid } from '../did-resource-limits.js';
import { fetchDidJson } from '../read-did-json.js';
import { checkJsonTokens } from '../../utils/json-preflight.js';
import type { DIDDocument } from '../vc-verifier.types.js';
import type { FetchProvider } from '../../providers/base.js';
import { documentOf } from '../../__tests__/utils/did-documents.js';

const did = 'did:web:walk.example';
const utf8 = (value: unknown) => new TextEncoder().encode(JSON.stringify(value)).length;

/** A deterministic generator of JSON values: null, booleans, numbers, strings, arrays and objects. */
function generator(seed: number) {
  let state = seed;
  const next = (n: number) => { state = (state * 1_103_515_245 + 12_345) % 2 ** 31; return state % n; };
  const units = [0x00, 0x08, 0x1f, 0x22, 0x41, 0x5c, 0x7f, 0x80, 0x7ff, 0x800, 0xd800, 0xdbff, 0xdc00, 0xfffd, 0xffff];
  const text = () => Array.from({ length: next(6) }, () => String.fromCharCode(units[next(units.length)]!)).join('');
  const value = (depth: number): unknown => {
    switch (next(depth > 4 ? 4 : 6)) {
      case 0: return null;
      case 1: return next(2) === 0;
      case 2: return [0, -1, 1.5, 1e21, -2.5e-7, 123_456_789][next(6)];
      case 3: return text();
      case 4: return Array.from({ length: next(4) }, () => value(depth + 1));
      default: return Object.fromEntries(Array.from({ length: next(4) }, (_, i) => [`${text()}${i}`, value(depth + 1)]));
    }
  };
  return () => documentOf({ value: value(1), list: [value(2), null, value(2)] }, did);
}

describe('the walk measures compact JSON in UTF-8', () => {
  it('agrees with JSON.stringify on 500 generated documents, nulls and array commas included', () => {
    const generate = generator(7);
    for (let i = 0; i < 500; i++) {
      const document = generate();
      expect(measureDidDocument(document)).toMatchObject({ ok: true, bytes: utf8(document) });
      expect(admitParsedDidDocument(JSON.parse(JSON.stringify(document)))).toMatchObject({ ok: true, bytes: utf8(document) });
    }
  });

  it('counts a surrogate pair as four bytes and a lone surrogate as the six of its escape', () => {
    const strings = ['\ud83d\ude00', '\ud800', '\ud800a', '\ud800\ud800', '\udc00\ud800', 'a\udfff', '\ud800\u00e9'];
    for (const value of strings) {
      expect(measureDidDocument(documentOf({ value }, did)), JSON.stringify(value)).toMatchObject({ ok: true, bytes: utf8({ id: did, value }) });
    }
  });

  it('counts a null as four bytes and each array comma as one', () => {
    for (const value of [null, [null], [null, null, null], [[], [], []], [{}, {}]]) {
      expect(measureDidDocument(documentOf({ value }, did))).toMatchObject({ ok: true, bytes: utf8({ id: did, value }) });
    }
  });

  it('skips a member that is not enumerable, or whose value is undefined, as JSON.stringify does', () => {
    // Each hidden member is set through `Object.defineProperty`, since a literal writes only enumerable string keys.
    const document = Object.defineProperty({ id: did, kept: 1, gone: undefined }, 'hidden', { value: 'x'.repeat(2_000_000) });
    expect(measureDidDocument(document)).toMatchObject({ ok: true, bytes: utf8({ id: did, kept: 1 }) });
    const hiddenSymbol = Object.defineProperty({ id: did }, Symbol('hidden'), { value: 1 });
    expect(measureDidDocument(hiddenSymbol)).toMatchObject({ ok: true, bytes: utf8({ id: did }) });
  });
});

describe('the walk refuses what JSON could not hold', () => {
  class Instance { id = did; }
  // The rows `documentOf` does not build are objects no helper returns: a class instance, a symbol
  // key, an accessor, an array. Each is refused for the shape its label names.
  it.each([
    ['NaN', documentOf({ value: Number.NaN }, did)],
    ['Infinity', documentOf({ value: Number.POSITIVE_INFINITY }, did)],
    ['a class instance', new Instance()],
    ['a class instance inside', documentOf({ value: new Instance() }, did)],
    ['a Date', documentOf({ value: new Date(0) }, did)],
    ['a Map', documentOf({ value: new Map() }, did)],
    ['an enumerable symbol key', { id: did, [Symbol('key')]: 1 }],
    ['an accessor', Object.defineProperty({ id: did }, 'value', { get: () => 1, enumerable: true })],
    ['an accessor that is not enumerable', Object.defineProperty({ id: did }, 'value', { get: () => 1 })],
    ['a sparse array', documentOf({ value: [1, , 3] }, did)],
    ['an array with an id, whose named members the walk would not measure', Object.assign([], { id: did })],
    ['a function', documentOf({ value: () => 1 }, did)],
  ])('refuses %s', (_name, document) => {
    expect(measureDidDocument(document).ok).toBe(false);
  });

  it('refuses a sparse array as sparse, rather than reading its hole', () => {
    expect(measureDidDocument(documentOf({ value: [1, , 3] }, did))).toEqual({ ok: false, reason: 'array is sparse' });
  });

  it('refuses a document whose Proxy trap throws, with a reason', () => {
    // A Proxy stands for the document, so that reading its own keys throws.
    const throwing = new Proxy({ id: did }, { ownKeys: () => { throw new Error('trap'); } });
    expect(measureDidDocument(throwing)).toEqual({ ok: false, reason: 'document could not be read as JSON data' });
  });

  it('runs a getter on an array index, as application code, and measures what it returns, or refuses when it throws', () => {
    const value = Object.defineProperty([0], 0, { get: () => 'returned', enumerable: true });
    expect(measureDidDocument(documentOf({ value }, did))).toMatchObject({ ok: true, bytes: utf8({ id: did, value: ['returned'] }) });
    const throwing = Object.defineProperty([0], 0, { get: () => { throw new Error('getter'); }, enumerable: true });
    expect(measureDidDocument(documentOf({ value: throwing }, did)))
      .toEqual({ ok: false, reason: 'document could not be read as JSON data' });
  });
});

describe("a document's id", () => {
  it('is a DID: a string that starts with did: and is within the DID limit', () => {
    // Written out as `{ id }`: the id is the case, and `documentOf` writes Acme's for one that is undefined.
    for (const id of ['did:x', 'did:web:walk.example']) expect(measureDidDocument({ id })).toMatchObject({ ok: true });
    for (const id of [undefined, '', 'x', 'urn:uuid:1', 'DID:web:walk.example', ' did:web:walk.example', 'did', 7]) {
      expect(measureDidDocument({ id })).toEqual({ ok: false, reason: 'document id is not a DID within the limit' });
    }
  });
});

// The documents written inside `vm.runInNewContext` are made in the other realm, which is the case:
// one this realm's helper built would have this realm's prototypes.
describe('a plain object from another realm', () => {
  it('is accepted, written as a literal there or parsed by that realm', () => {
    const literal = vm.runInNewContext(`({ id: '${did}', value: [1, { nested: null }], empty: Object.create(null) })`) as object;
    expect(Object.getPrototypeOf(literal)).not.toBe(Object.prototype);
    expect(measureDidDocument(literal)).toMatchObject({ ok: true, bytes: utf8(literal) });
    const parsed = vm.runInNewContext('JSON.parse(text)', { text: JSON.stringify(documentOf({ value: [{ a: 1 }] }, did)) }) as object;
    expect(measureDidDocument(parsed)).toMatchObject({ ok: true, bytes: utf8(parsed) });
  });

  it('is refused when it is a class instance there', () => {
    expect(measureDidDocument(vm.runInNewContext(`new (class Document { id = '${did}' })()`)).ok).toBe(false);
    expect(measureDidDocument(vm.runInNewContext(`({ id: '${did}', value: new Date(0) })`)).ok).toBe(false);
  });

  it('is told from an instance of a class named Object, whose prototype has a prototype of its own', () => {
    const Named = class Object { kind = 'not plain'; };
    expect(Named.name).toBe('Object');
    const refused = { ok: false, reason: 'value is neither an array nor a plain object' };
    expect(measureDidDocument(documentOf({ service: [new Named()] }, did))).toEqual(refused);
    // The instance itself as the document, carrying the id, here and from the other realm.
    expect(measureDidDocument(Object.assign(new Named(), { id: did }))).toEqual(refused);
    expect(measureDidDocument(vm.runInNewContext(`({ id: '${did}', service: [new (class Object {})()] })`))).toEqual(refused);
  });
});

describe('a document a built-in resolver parsed', () => {
  it('is frozen deeply and branded once admitted, and only then', () => {
    const document = JSON.parse(JSON.stringify(documentOf({ verificationMethod: [{ id: '#k', publicKeyJwk: { x: 'a' } }] }, did)));
    expect(isAdmittedDidDocument(document)).toBe(false);
    expect(admitParsedDidDocument(document).ok).toBe(true);
    expect(isAdmittedDidDocument(document)).toBe(true);
    for (const part of [document, document.verificationMethod, document.verificationMethod[0], document.verificationMethod[0].publicKeyJwk]) {
      expect(Object.isFrozen(part)).toBe(true);
    }
    const refused = JSON.parse(JSON.stringify(documentOf({}, '')));
    expect(admitParsedDidDocument(refused).ok).toBe(false);
    expect(isAdmittedDidDocument(refused)).toBe(false);
    const measured = documentOf({}, did);
    expect(measureDidDocument(measured).ok).toBe(true);
    expect([isAdmittedDidDocument(measured), Object.isFrozen(measured)]).toEqual([false, false]);
  });

  it('is not walked again by the verifier boundary, while any other document is walked, and copied, on each resolution', async () => {
    const admitted = JSON.parse(JSON.stringify(documentOf({ value: [1, 2] }, did))) as DIDDocument;
    admitParsedDidDocument(admitted);
    const other = documentOf({ value: [1, 2] }, did);
    const ownKeys = vi.spyOn(Reflect, 'ownKeys');
    try {
      expect(await resolveBoundedDid({ resolve: async () => admitted }, did)).toBe(admitted);
      expect(ownKeys).not.toHaveBeenCalled();
      const first = await resolveBoundedDid({ resolve: async () => other }, did);
      const second = await resolveBoundedDid({ resolve: async () => other }, did);
      expect(ownKeys.mock.calls.filter(([target]) => target === other)).toHaveLength(2);
      // The verifier reads the walk's frozen copy; the resolver keeps its own object as it was.
      expect([first, second]).toEqual([other, other]);
      expect([first === other, second === first, Object.isFrozen(first), Object.isFrozen(other)]).toEqual([false, false, true, false]);
      ownKeys.mockClear();
      expect(await resolveBoundedDid({ resolve: async () => first }, did)).toBe(first);
      expect(ownKeys).not.toHaveBeenCalled();
    } finally { ownKeys.mockRestore(); }
  });
});

describe('the token preflight and the network read', () => {
  const provider = (response: () => Response) => ({ fetch: async () => response() }) as unknown as FetchProvider;
  const url = 'https://walk.example/did.json';

  it('reads a document of more than 64 containers in all when none nests deeper than 64', async () => {
    const document = documentOf({ siblings: Array.from({ length: 100 }, () => ({ inner: [[]] })) }, did);
    expect(await fetchDidJson(provider(() => new Response(JSON.stringify(document))), url)).toEqual(document);
  });

  it('counts a member whose name is followed by whitespace before its colon', () => {
    const spaced = (count: number, name = (i: number) => `m${i}`) =>
      `{${Array.from({ length: count }, (_, i) => `"${name(i)}" \n\t\r: 0`).join(',')}}`;
    expect(() => checkJsonTokens(spaced(MAX_JSON_MEMBERS), DID_DOCUMENT_JSON)).not.toThrow();
    expect(() => checkJsonTokens(spaced(MAX_JSON_MEMBERS + 1), DID_DOCUMENT_JSON)).toThrow('JSON member limit exceeded');
    const long = (length: number) => spaced(1, () => 'k'.repeat(length));
    expect(() => checkJsonTokens(long(MAX_JSON_MEMBER_LENGTH), DID_DOCUMENT_JSON)).not.toThrow();
    expect(() => checkJsonTokens(long(MAX_JSON_MEMBER_LENGTH + 1), DID_DOCUMENT_JSON)).toThrow('JSON member limit exceeded');
  });

  it('refuses a non-2xx response even when its body is a valid document, quoting its URL as a refusal quotes any value', async () => {
    const valid = () => new Response(JSON.stringify(documentOf({}, did)), { status: 404 });
    await expect(fetchDidJson(provider(valid), url)).rejects.toThrow(`DID resolution failed: HTTP 404 for "${url}"`);
    const long = `${url}/${'l'.repeat(100_000)}`;
    await expect(fetchDidJson(provider(valid), long))
      .rejects.toMatchObject({ message: `DID resolution failed: HTTP 404 for "${long.slice(0, 64)}"...` });
  });
});
