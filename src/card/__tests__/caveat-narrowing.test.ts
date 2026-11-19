/**
 * How a hop's caveats are held to its parent's (SPEC.md §6.10), read at their tightest, once per
 * hop. Over random sets of well-formed caveats the rule passes and refuses exactly the hops it did
 * before caveats were read at their tightest: the reading changes what a verdict carries, never
 * which chains pass. (A malformed `MaxAmount` or `ValidUntil` is now refused for its form, and a
 * caveat of a known type with a member the library does not know is now compared verbatim; the
 * sets here hold neither.) Reading thousands of caveats on a hop costs about what reading them
 * once does, however many kinds of caveat they are.
 */

import { describe, expect, it } from 'vitest';
import { attenuates, validateDelegationChain, type Caveat, type DelegationChain, type DelegationCredential } from '../index.js';
import { NOW_MS, RESOURCE } from './signed-chain-helpers.js';

const now = (): number => NOW_MS;

/** An unsigned hop from `issuer` to `invoker` under `caveats`: the chain rules read no proof. */
function credential(id: string, parentCapability: string, issuer: string, invoker: string, caveats: Caveat[]): DelegationCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://w3id.org/security/zcap/v1'],
    type: ['VerifiableCredential', 'DelegationCredential'],
    issuer,
    validUntil: '2027-01-01T00:00:00Z',
    credentialSubject: { id, invoker, parentCapability, invocationTarget: RESOURCE, allowedAction: ['orders.place'], caveats },
  } as DelegationCredential;
}

/** Acme to the agent under `rootCaveats`, then the agent to the worker under `leafCaveats`. */
const twoHops = (rootCaveats: Caveat[], leafCaveats: Caveat[]): [DelegationCredential, DelegationCredential] => [
  credential('urn:zcap:root', RESOURCE, 'did:web:acme.example', 'did:web:agent.example', rootCaveats),
  credential('urn:zcap:leaf', 'urn:zcap:root', 'did:web:agent.example', 'did:web:worker.example', leafCaveats),
];

// ── The rule as it read caveats before they were read at their tightest ──────

function decimalLte(child: string, parent: string): boolean {
  const parts = (dec: string) => /^(\d+)(?:\.(\d+))?$/.exec(dec.trim());
  const c = parts(child);
  const p = parts(parent);
  if (!c?.[1] || !p?.[1]) return false;
  const scale = Math.max((c[2] ?? '').length, (p[2] ?? '').length);
  return BigInt(c[1] + (c[2] ?? '').padEnd(scale, '0')) <= BigInt(p[1] + (p[2] ?? '').padEnd(scale, '0'));
}
const sortKeys = (value: unknown): unknown =>
  Array.isArray(value)
    ? value.map(sortKeys)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.keys(value).sort().map((k) => [k, sortKeys((value as Record<string, unknown>)[k])]))
      : value;
function narrowedBefore(parent: Caveat, child: Caveat): boolean {
  if (parent.type !== child.type) return false;
  if (parent.type === 'ValidUntil') return Date.parse(child.date ?? '') <= Date.parse(parent.date ?? '');
  if (parent.type === 'MaxAmount') {
    const currency = parent.currency === undefined || parent.currency === child.currency;
    return currency && typeof parent.limit === 'string' && typeof child.limit === 'string' && decimalLte(child.limit, parent.limit);
  }
  return JSON.stringify(sortKeys(parent)) === JSON.stringify(sortKeys(child));
}
const attenuatedBefore = (parent: Caveat[], child: Caveat[]): boolean => parent.every((p) => child.some((c) => narrowedBefore(p, c)));

// ── Random well-formed caveats ───────────────────────────────────────────────

/** A seeded generator (mulberry32), so a failure is reproduced by its seed. */
function random(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const DATES = ['2026-12-01T00:00:00Z', '2026-12-01T01:00:00+01:00', '2026-12-15T00:00:00Z', '2027-01-01T00:00:00Z'];
const LIMITS = ['0', '10', '10.00', '50', '100', '100.5'];
const CURRENCIES = [undefined, 'USD', 'EUR'];
const OTHERS: Caveat[] = [{ type: 'Custom', n: 1 }, { type: 'Custom', n: 2 }, { type: 'Other' }, { type: 'Custom', n: 1, m: 'x' }];

function caveatFrom(next: () => number): Caveat {
  const pick = <T>(values: readonly T[]): T => values[Math.floor(next() * values.length)]!;
  const kind = next();
  if (kind < 0.3) return { type: 'ValidUntil', date: pick(DATES) };
  if (kind < 0.75) {
    const currency = pick(CURRENCIES);
    return { type: 'MaxAmount', limit: pick(LIMITS), ...(currency === undefined ? {} : { currency }) };
  }
  return { ...pick(OTHERS) };
}
const caveatsFrom = (next: () => number): Caveat[] => Array.from({ length: Math.floor(next() * 5) }, () => caveatFrom(next));

describe('a hop held to its parent at their tightest', () => {
  it('passes and refuses exactly the hops it did before, over random sets of well-formed caveats', () => {
    const next = random(20261118);
    const outcomes = { passed: 0, refused: 0 };
    for (let run = 0; run < 3000; run += 1) {
      const parent = caveatsFrom(next);
      // Half the children start from the parent's own caveats, so many hops narrow it.
      const child = next() < 0.5 ? [...parent.filter(() => next() < 0.8), ...caveatsFrom(next)] : caveatsFrom(next);
      const expected = attenuatedBefore(parent, child);
      const [root, leaf] = twoHops(parent, child);
      const context = `seed run ${run}: parent ${JSON.stringify(parent)} child ${JSON.stringify(child)}`;
      expect(attenuates(root, leaf).length === 0, context).toBe(expected);
      expect(validateDelegationChain([root, leaf], { now }).ok, context).toBe(expected);
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
    ['on one hop', (caveats) => [twoHops(caveats, [])[0]]],
    ['on a hop and the hop below it, which repeats them', (caveats) => twoHops(caveats, caveats)],
  ])('costs a small multiple of one kind %s, however many kinds of caveat there are', (_label, chainOf) => {
    timeOf(chainOf(oneKind)); // warm up
    const baseline = timeOf(chainOf(oneKind));
    expect(timeOf(chainOf(manyKinds))).toBeLessThan(10 * baseline + 50);
  });
});
