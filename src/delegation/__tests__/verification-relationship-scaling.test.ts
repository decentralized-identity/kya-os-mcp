/**
 * How the lookup's time grows with what it reads: a DID document, a DID and a key id, all of which
 * the other party chose. The lookup reads each entry once, so its time grows in proportion to the
 * document; one that rescans a list for each entry, sorts for each entry, or does work as long as the
 * DID for each entry takes time that grows with the square of the document instead.
 * The test times lookups in a generated document and in one 16 times its size, with 16 times as many
 * references, published and embedded methods, and a DID and key id 16 times as long, and holds the
 * ratio of the two times close to linear: a linear lookup gives about 16, a quadratic one about
 * 256. It counts CPU time (`process.cpuUsage`), not elapsed time, so the machine's other work does
 * not count, repeats each lookup until a sample is long enough to measure on every platform's clock,
 * and keeps the least of several samples per size, taken in turn after a warm-up.
 */
import { describe, it, expect } from 'vitest';
import { retrieveVerificationMethod, selectAssertionMethod } from '../verification-relationship.js';
import type { DIDDocument } from '../vc-verifier.types.js';
import { keylessMethod as method } from '../../__tests__/utils/did-documents.js';

const GROWTH = 16;
/**
 * The largest ratio allowed: 1.5 times the highest the lookup measured, 15.95, rounded up. In 20 runs
 * on each of Node 20 and 22 it measured 14.17 to 15.95 and 14.16 to 15.10; six quadratic variants of
 * it measured 160 to 236, and one whose time grows with n^1.4, 33 to 40. The bound does not catch a
 * lookup whose time grows with n log n, as one that sorts the document once: 16 times the entries
 * make it about 16 * log(16n) / log(n) times slower, too close to the 16 of a linear lookup to tell
 * apart.
 */
const BOUND = 24;
const SAMPLES = 5;
/** CPU microseconds a sample takes at least: Windows counts process time in 15.6 ms ticks. */
const SAMPLE_MICROS = 100_000;

/** A document at `scale`, the DID it is read for, the key it lists first, and its JSON length. */
function documentAt(scale: number) {
  const did = `did:web:example.com:${'a'.repeat(250 * scale)}`;
  const key = `#key-${'k'.repeat(25 * scale)}`;
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
  // Parsed, as a resolver hands it over: its strings are not the DID the lookup is given.
  return { document: JSON.parse(text) as DIDDocument, did, key, size: text.length };
}

/** Every kind of lookup once: by absolute id, by relative id, for an absent id, and with no id. */
function lookups({ document, did, key }: ReturnType<typeof documentAt>): unknown[] {
  return [
    retrieveVerificationMethod(document, did, `${did}${key}`, 'assertionMethod')?.id,
    retrieveVerificationMethod(document, did, key, 'assertionMethod')?.id,
    retrieveVerificationMethod(document, did, '#absent', 'assertionMethod')?.id,
    ((selection) => ('method' in selection ? selection.method.id : undefined))(selectAssertionMethod(document, did, undefined)),
  ];
}

/** CPU microseconds per run of `run`, over `repetitions` runs. */
function cpuMicros(run: () => unknown, repetitions: number): number {
  const sink: unknown[] = [];
  const start = process.cpuUsage();
  for (let index = 0; index < repetitions; index += 1) sink.push(run());
  const { user, system } = process.cpuUsage(start);
  expect(sink).toHaveLength(repetitions);
  return (user + system) / repetitions;
}

/** How many runs of `run` take at least SAMPLE_MICROS; finding out also warms it up. */
function repetitionsFor(run: () => unknown): number {
  let repetitions = 1;
  while (cpuMicros(run, repetitions) * repetitions < SAMPLE_MICROS) repetitions *= 2;
  return repetitions;
}

describe('lookup time', () => {
  it(`grows about ${GROWTH} times, not quadratically, in a document ${GROWTH} times the size`, () => {
    const small = documentAt(1);
    const large = documentAt(GROWTH);
    expect(large.size / small.size).toBeGreaterThan(GROWTH - 1);
    expect(large.size / small.size).toBeLessThan(GROWTH + 2);
    for (const input of [small, large]) {
      expect(lookups(input)).toEqual([input.key, input.key, undefined, input.key]);
    }

    const runs = [small, large].map((input) => () => lookups(input));
    const repetitions = runs.map(repetitionsFor);
    const least = [Infinity, Infinity];
    for (let sample = 0; sample < SAMPLES; sample += 1) {
      runs.forEach((run, size) => {
        least[size] = Math.min(least[size]!, cpuMicros(run, repetitions[size]!));
      });
    }
    const ratio = least[1]! / least[0]!;
    expect(ratio, `${least[0]!.toFixed(1)} us, then ${least[1]!.toFixed(1)} us: ratio ${ratio.toFixed(1)}`).toBeLessThan(BOUND);
  }, 120_000);
});
