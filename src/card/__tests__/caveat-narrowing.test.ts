/**
 * How a hop's caveats are held to its parent's (SPEC.md §6.10), read at their tightest, once per
 * hop. Over random sets of well-formed caveats the rule passes and refuses exactly the hops the
 * 1.25.0 rule did, run as that release wrote it (`./frozen-caveat-rule.ts`): reading caveats at
 * their tightest changes what a verdict carries, never which chains pass. (A malformed `MaxAmount`
 * or `ValidUntil` is now refused for its form, and a caveat of a known type with a member the
 * library does not know is now compared verbatim; the sets here hold neither.) Reading thousands of
 * caveats on a hop costs about what reading them once does, however many kinds of caveat they are.
 */

import { describe, expect, it } from 'vitest';
import { attenuates, validateDelegationChain, type Caveat, type DelegationChain } from '../index.js';
import { attenuatedIn1250 } from './frozen-caveat-rule.js';
import { caveatsFrom, random, unsignedChain } from './random-caveats.js';
import { NOW_MS } from './signed-chain-helpers.js';

const now = (): number => NOW_MS;

describe('a hop held to its parent at their tightest', () => {
  it('passes and refuses exactly the hops the 1.25.0 rule did, over random sets of well-formed caveats', () => {
    const next = random(20261118);
    const outcomes = { passed: 0, refused: 0 };
    for (let run = 0; run < 3000; run += 1) {
      const parent = caveatsFrom(next);
      // Half the children start from the parent's own caveats, so many hops narrow it.
      const child = next() < 0.5 ? [...parent.filter(() => next() < 0.8), ...caveatsFrom(next)] : caveatsFrom(next);
      const expected = attenuatedIn1250(parent, child);
      const [root, leaf] = unsignedChain([parent, child]);
      const context = `seed run ${run}: parent ${JSON.stringify(parent)} child ${JSON.stringify(child)}`;
      expect(attenuates(root!, leaf!).length === 0, context).toBe(expected);
      expect(validateDelegationChain([root!, leaf!], { now }).ok, context).toBe(expected);
      outcomes[expected ? 'passed' : 'refused'] += 1;
    }
    expect(outcomes.passed).toBeGreaterThan(500);
    expect(outcomes.refused).toBeGreaterThan(500);
  });
});

describe('the cost of reading many caveats on a hop', () => {
  const COUNT = 8_000;
  /** Caveats of as many kinds as there are caveats: a limit in each of many currencies, and many of a type the library does not know. */
  const manyKinds: Caveat[] = Array.from({ length: COUNT }, (_, k) =>
    k % 2 === 0 ? { type: 'MaxAmount', limit: String(COUNT - k), currency: `C${k}` } : { type: 'Custom', n: k },
  );
  /** As many caveats of one kind, which even a reading that compares each with every one kept reads once. */
  const oneKind: Caveat[] = Array.from({ length: COUNT }, () => ({ type: 'ValidUntil', date: '2026-12-01T00:00:00Z' }));

  /** The median time, in milliseconds, of validating `chain` three times. */
  function timeOf(chain: DelegationChain): number {
    const runs = [0, 1, 2].map(() => {
      const start = performance.now();
      validateDelegationChain(chain, { now });
      return performance.now() - start;
    });
    return runs.sort((a, b) => a - b)[1]!;
  }

  it.each<[string, (caveats: Caveat[]) => DelegationChain]>([
    ['on one hop', (caveats) => unsignedChain([caveats])],
    ['on a hop and the hop below it, which repeats them', (caveats) => unsignedChain([caveats, caveats])],
  ])('costs a small multiple of one kind %s, however many kinds of caveat there are', (_label, chainOf) => {
    timeOf(chainOf(oneKind)); // warm up
    const baseline = timeOf(chainOf(oneKind));
    expect(timeOf(chainOf(manyKinds))).toBeLessThan(10 * baseline + 50);
  });
});
