/**
 * Deterministic work checks for the real lookup source, independent of JIT, coverage and clock
 * resolution. The test-only meter charges loops, input reads and string operations, including
 * primitive equality and concatenation that proxies cannot observe. It rejects native operations
 * without a cost rule. This guards the source's O(S + D + K) argument; it does not measure V8
 * instructions, allocator behaviour or JSON parsing.
 */
import { readFileSync } from 'node:fs';
import { describe, it, expect } from 'vitest';
import * as actual from '../verification-relationship.js';
import * as guards from '../../utils/guards.js';
import * as descriptions from '../../utils/describe-value.js';
import * as shapes from '../verification-method-shape.js';
import type { DIDDocument } from '../vc-verifier.types.js';
import { keylessMethod as method } from '../../__tests__/utils/did-documents.js';
import { compileMeteredLookup } from '../../__tests__/utils/lookup-work.js';

const source = readFileSync(new URL('../verification-relationship.ts', import.meta.url), 'utf8');
const imports = {
  '../utils/guards.js': guards,
  '../utils/describe-value.js': descriptions,
  './verification-method-shape.js': shapes,
};

describe('lookup work meter', () => {
  it('charges primitive string operations while preserving their results', () => {
    const cases: [string, string, string, unknown, number][] = [
      ['a === b', 'key', 'key', true, 4],
      ['a !== b', 'key', 'longer', true, 1],
      ['a + b', 'did:', 'key', 'did:key', 8],
      ['`${a}:${b}`', 'did', 'key', 'did:key', 8],
      ['a.startsWith(b)', 'did:key', 'did:', true, 5],
      ['a.startsWith(b)', 'key', 'did:key', false, 1],
      ['a.includes(b)', 'did:key', '#', false, 8],
      ['a.slice(4)', 'did:key', '', 'key', 4],
    ];
    for (const [expression, a, b, expected, work] of cases) {
      const meter = compileMeteredLookup(`export function run(a: string, b: string) { return ${expression}; }`, {});
      meter.reset(100);
      const run = meter.exports.run as (a: string, b: string) => unknown;
      expect(run(a, b)).toBe(expected);
      expect(meter.work()).toBe(work);
    }
  });

  it('requires a cost rule for native collection operations', () => {
    for (const text of ['export const index = new Map();', 'export function sort(ids: string[]) { return ids.sort(); }']) {
      expect(() => compileMeteredLookup(text, {})).toThrow(/unmetered lookup operation/i);
    }
  });
});

function documentAt(scale: number, didUnits = 250 * scale, keyUnits = 25 * scale) {
  const did = `did:web:example.com:${'a'.repeat(didUnits)}`;
  const key = `#key-${'k'.repeat(keyUnits)}`;
  const other = 'did:web:other.example';
  const text = JSON.stringify({
    id: did,
    verificationMethod: [...Array.from({ length: 50 * scale }, (_, i) => method(`#method-${i}`, other)), method(key, did)],
    assertionMethod: [
      `${did}${key}`,
      ...Array.from({ length: 200 * scale }, (_, i) => `#reference-${i}`),
      ...Array.from({ length: 50 * scale }, (_, i) => method(`#embedded-${i}`, other)),
    ],
  });
  return { document: JSON.parse(text) as DIDDocument, did, key, size: text.length };
}

/** Charge every property read, including array iteration, without changing the input's shape. */
function counted<T extends object>(value: T, step: () => void, seen = new WeakMap<object, object>()): T {
  const prior = seen.get(value);
  if (prior) return prior as T;
  const proxy = new Proxy(value, {
    get(target, key, receiver) {
      step();
      const result: unknown = Reflect.get(target, key, receiver);
      return typeof result === 'object' && result !== null ? counted(result, step, seen) : result;
    },
  });
  seen.set(value, proxy);
  return proxy;
}

// Fixed allowance per input unit, not a ratio calibrated to the current machine. JSON length
// also pays for entries and property names. The separate DID and requested id are counted once.
function budget(input: ReturnType<typeof documentAt>, named: string | undefined): number {
  return 12 * (input.size + input.did.length + (named?.length ?? 0));
}

describe('lookup work', () => {
  const meter = compileMeteredLookup(source, imports);
  const lookup = meter.exports as unknown as typeof actual;

  it.each([
    [1, 250, 25],
    [4, 1000, 100],
    [16, 4000, 400],
    [16, 100_000, 25],
    [16, 250, 100_000],
  ])('stays within its input budget at scale %i, DID length %i, key length %i', (scale, didUnits, keyUnits) => {
    const input = documentAt(scale, didUnits, keyUnits);
    for (const named of [`${input.did}${input.key}`, input.key, '#absent', undefined]) {
      const expected = actual.selectAssertionMethod(input.document, input.did, named);
      const limit = budget(input, named);
      meter.reset(limit);
      const result = lookup.selectAssertionMethod(counted(input.document, meter.step), input.did, named);
      const work = meter.work();
      // Stop charging before Vitest walks a returned proxy to compare results.
      meter.reset(Number.MAX_SAFE_INTEGER);
      expect(result).toEqual(expected);
      expect(work).toBeLessThanOrEqual(limit);
      if (named !== undefined) {
        meter.reset(limit);
        const found = lookup.retrieveVerificationMethod(counted(input.document, meter.step), input.did, named, 'assertionMethod');
        const retrievalWork = meter.work();
        meter.reset(Number.MAX_SAFE_INTEGER);
        expect(found).toEqual(actual.retrieveVerificationMethod(input.document, input.did, named, 'assertionMethod'));
        expect(retrievalWork).toBeLessThanOrEqual(limit);
      }
    }
  });

  it.each([
    ['rescanning the published methods',
      'for (const entry of published) define(entry);',
      'for (const entry of published) for (const again of published) { define(entry); define(again); }'],
    ['prepending the DID to each relative id',
      "if (id.startsWith('#')) return id;",
      "if (id.startsWith('#')) return `${did}${id}`.slice(did.length);"],
  ])('rejects a regression that spends work %s', (_name, before, after) => {
    expect(source).toContain(before);
    const changed = compileMeteredLookup(source.replace(before, after), imports);
    const changedLookup = changed.exports as unknown as typeof actual;
    const input = documentAt(16, 100_000);
    changed.reset(budget(input, input.key));
    expect(() => changedLookup.selectAssertionMethod(counted(input.document, changed.step), input.did, input.key))
      .toThrow(/work budget/i);
  });
});
