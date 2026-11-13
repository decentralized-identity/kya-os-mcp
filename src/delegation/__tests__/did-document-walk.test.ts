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
  return () => ({ id: did, value: value(1), list: [value(2), null, value(2)] });
}

describe('the walk measures compact JSON in UTF-8', () => {
  it('agrees with JSON.stringify on 500 generated documents, nulls and array commas included', () => {
    const generate = generator(7);
    for (let i = 0; i < 500; i++) {
      const document = generate();
      expect(measureDidDocument(document)).toEqual({ ok: true, bytes: utf8(document) });
      expect(admitParsedDidDocument(JSON.parse(JSON.stringify(document)))).toEqual({ ok: true, bytes: utf8(document) });
    }
  });

  it('counts a null as four bytes and each array comma as one', () => {
    for (const value of [null, [null], [null, null, null], [[], [], []], [{}, {}]]) {
      expect(measureDidDocument({ id: did, value })).toEqual({ ok: true, bytes: utf8({ id: did, value }) });
    }
  });

  it('skips a member that is not enumerable, or whose value is undefined, as JSON.stringify does', () => {
    const document = Object.defineProperty({ id: did, kept: 1, gone: undefined }, 'hidden', { value: 'x'.repeat(2_000_000) });
    expect(measureDidDocument(document)).toEqual({ ok: true, bytes: utf8({ id: did, kept: 1 }) });
    const hiddenSymbol = Object.defineProperty({ id: did }, Symbol('hidden'), { value: 1 });
    expect(measureDidDocument(hiddenSymbol)).toEqual({ ok: true, bytes: utf8({ id: did }) });
  });
});

describe('the walk refuses what JSON could not hold', () => {
  class Instance { id = did; }
  it.each([
    ['NaN', { id: did, value: Number.NaN }],
    ['Infinity', { id: did, value: Number.POSITIVE_INFINITY }],
    ['a class instance', new Instance()],
    ['a class instance inside', { id: did, value: new Instance() }],
    ['a Date', { id: did, value: new Date(0) }],
    ['a Map', { id: did, value: new Map() }],
    ['an enumerable symbol key', { id: did, [Symbol('key')]: 1 }],
    ['an accessor', Object.defineProperty({ id: did }, 'value', { get: () => 1, enumerable: true })],
    ['an accessor that is not enumerable', Object.defineProperty({ id: did }, 'value', { get: () => 1 })],
    ['a sparse array', { id: did, value: [1, , 3] }],
    ['an array with an id, whose named members the walk would not measure', Object.assign([], { id: did })],
    ['a function', { id: did, value: () => 1 }],
  ])('refuses %s', (_name, document) => {
    expect(measureDidDocument(document).ok).toBe(false);
  });

  it('refuses a sparse array as sparse, rather than reading its hole', () => {
    expect(measureDidDocument({ id: did, value: [1, , 3] })).toEqual({ ok: false, reason: 'array is sparse' });
  });

  it('refuses a document whose Proxy trap throws, with a reason', () => {
    const throwing = new Proxy({ id: did }, { ownKeys: () => { throw new Error('trap'); } });
    expect(measureDidDocument(throwing)).toEqual({ ok: false, reason: 'document could not be read as JSON data' });
  });

  it('runs a getter on an array index, as application code, and measures what it returns, or refuses when it throws', () => {
    const value = Object.defineProperty([0], 0, { get: () => 'returned', enumerable: true });
    expect(measureDidDocument({ id: did, value })).toEqual({ ok: true, bytes: utf8({ id: did, value: ['returned'] }) });
    const throwing = Object.defineProperty([0], 0, { get: () => { throw new Error('getter'); }, enumerable: true });
    expect(measureDidDocument({ id: did, value: throwing }))
      .toEqual({ ok: false, reason: 'document could not be read as JSON data' });
  });
});

describe("a document's id", () => {
  it('is a DID: a string that starts with did: and is within the DID limit', () => {
    for (const id of ['did:x', 'did:web:walk.example']) expect(measureDidDocument({ id })).toMatchObject({ ok: true });
    for (const id of [undefined, '', 'x', 'urn:uuid:1', 'DID:web:walk.example', ' did:web:walk.example', 'did', 7]) {
      expect(measureDidDocument({ id })).toEqual({ ok: false, reason: 'document id is not a DID within the limit' });
    }
  });
});

describe('a plain object from another realm', () => {
  it('is accepted, written as a literal there or parsed by that realm', () => {
    const literal = vm.runInNewContext(`({ id: '${did}', value: [1, { nested: null }], empty: Object.create(null) })`) as object;
    expect(Object.getPrototypeOf(literal)).not.toBe(Object.prototype);
    expect(measureDidDocument(literal)).toEqual({ ok: true, bytes: utf8(literal) });
    const parsed = vm.runInNewContext('JSON.parse(text)', { text: JSON.stringify({ id: did, value: [{ a: 1 }] }) }) as object;
    expect(measureDidDocument(parsed)).toEqual({ ok: true, bytes: utf8(parsed) });
  });

  it('is refused when it is a class instance there', () => {
    expect(measureDidDocument(vm.runInNewContext(`new (class Document { id = '${did}' })()`)).ok).toBe(false);
    expect(measureDidDocument(vm.runInNewContext(`({ id: '${did}', value: new Date(0) })`)).ok).toBe(false);
  });
});

describe('a document a built-in resolver parsed', () => {
  it('is frozen deeply and branded once admitted, and only then', () => {
    const document = JSON.parse(JSON.stringify({ id: did, verificationMethod: [{ id: '#k', publicKeyJwk: { x: 'a' } }] }));
    expect(isAdmittedDidDocument(document)).toBe(false);
    expect(admitParsedDidDocument(document).ok).toBe(true);
    expect(isAdmittedDidDocument(document)).toBe(true);
    for (const part of [document, document.verificationMethod, document.verificationMethod[0], document.verificationMethod[0].publicKeyJwk]) {
      expect(Object.isFrozen(part)).toBe(true);
    }
    const refused = JSON.parse(JSON.stringify({ id: '' }));
    expect(admitParsedDidDocument(refused).ok).toBe(false);
    expect(isAdmittedDidDocument(refused)).toBe(false);
    const measured = { id: did };
    expect(measureDidDocument(measured).ok).toBe(true);
    expect([isAdmittedDidDocument(measured), Object.isFrozen(measured)]).toEqual([false, false]);
  });

  it('is not walked again by the verifier boundary, while any other document is walked on each resolution', async () => {
    const admitted = JSON.parse(JSON.stringify({ id: did, value: [1, 2] })) as DIDDocument;
    admitParsedDidDocument(admitted);
    const other = { id: did, value: [1, 2] } as DIDDocument;
    const ownKeys = vi.spyOn(Reflect, 'ownKeys');
    try {
      expect(await resolveBoundedDid({ resolve: async () => admitted }, did)).toBe(admitted);
      expect(ownKeys).not.toHaveBeenCalled();
      expect(await resolveBoundedDid({ resolve: async () => other }, did)).toBe(other);
      expect(await resolveBoundedDid({ resolve: async () => other }, did)).toBe(other);
      expect(ownKeys.mock.calls.filter(([target]) => target === other)).toHaveLength(2);
      // Neither copied nor frozen: the verifier uses what the resolver returned, as it is.
      expect(Object.isFrozen(other)).toBe(false);
    } finally { ownKeys.mockRestore(); }
  });
});

describe('the token preflight and the network read', () => {
  const provider = (response: () => Response) => ({ fetch: async () => response() }) as unknown as FetchProvider;
  const url = 'https://walk.example/did.json';

  it('reads a document of more than 64 containers in all when none nests deeper than 64', async () => {
    const document = { id: did, siblings: Array.from({ length: 100 }, () => ({ inner: [[]] })) };
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
    const valid = () => new Response(JSON.stringify({ id: did }), { status: 404 });
    await expect(fetchDidJson(provider(valid), url)).rejects.toThrow(`DID resolution failed: HTTP 404 for "${url}"`);
    const long = `${url}/${'l'.repeat(100_000)}`;
    await expect(fetchDidJson(provider(valid), long))
      .rejects.toMatchObject({ message: `DID resolution failed: HTTP 404 for "${long.slice(0, 64)}"...` });
  });
});
