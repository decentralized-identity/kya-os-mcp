/**
 * What `caveatRefusal` permits is never broader than any hop of the chain permits. Over random
 * chains and calls, every call it passes keeps to each caveat every hop states, read hop by hop by
 * the rule every caveat applies to every call: a `MaxAmount` that names a currency only in that
 * currency, one that names none in any; each `ValidUntil` and each hop's own `validUntil` at the
 * time of the call. A caveat the library does not interpret is the host's, which here enforces
 * those of an unknown type and so passes them; one of a known type with a member the library does
 * not know is never passed. A verdict that refuses the chain passes no call.
 */

import { describe, expect, it } from 'vitest';
import { caveatRefusal, validateDelegationChain, type Caveat, type CaveatCall } from '../index.js';
import { parseDateTime } from '../../utils/rfc3339.js';
import { decimalLte } from './frozen-caveat-rule.js';
import { CURRENCIES, DATES, LIMITS, caveatsFrom, pick, random, unsignedChain } from './random-caveats.js';
import { NOW_MS } from './signed-chain-helpers.js';

const now = (): number => NOW_MS;
const KNOWN = new Set(['MaxAmount', 'ValidUntil']);
const MEMBERS: Record<string, readonly string[]> = { MaxAmount: ['type', 'limit', 'currency'], ValidUntil: ['type', 'date'] };
const ENFORCED = ['Custom', 'Other'];

/** Whether `call` keeps to `caveat`, as the hop that states it reads it, held to the instant with no tolerance. */
function keepsTo(caveat: Caveat, call: CaveatCall): boolean {
  if (KNOWN.has(caveat.type) && Object.keys(caveat).some((member) => !MEMBERS[caveat.type]!.includes(member))) return false;
  const atMs = call.at ?? NOW_MS;
  if (caveat.type === 'ValidUntil') return atMs <= parseDateTime(caveat.date)!;
  if (caveat.type === 'MaxAmount') {
    if (call.amount === undefined || (caveat.currency !== undefined && call.currency !== caveat.currency)) return false;
    return decimalLte(call.amount, caveat.limit!);
  }
  return ENFORCED.includes(caveat.type);
}

/** A hop's caveats, each its parent's or one tighter, and a few of its own. */
function narrowerThan(next: () => number, parent: Caveat[]): Caveat[] {
  const kept = parent.map((caveat): Caveat => {
    if (next() < 0.5 || !KNOWN.has(caveat.type) || Object.keys(caveat).length > MEMBERS[caveat.type]!.length) return caveat;
    if (caveat.type === 'MaxAmount') {
      const tighter = LIMITS.filter((limit) => decimalLte(limit, caveat.limit!));
      return { ...caveat, limit: pick(next, tighter) };
    }
    const earlier = DATES.filter((date) => parseDateTime(date)! <= parseDateTime(caveat.date)!);
    return { ...caveat, date: pick(next, earlier) };
  });
  return [...kept, ...caveatsFrom(next, true)];
}

const WINDOWS = ['2026-11-20T00:00:00Z', '2026-12-10T00:00:00Z', '2027-01-01T00:00:00Z'];
const AMOUNTS = ['0', '5', '10', '10.000', '50', '99.99', '100', '100.5', '100.50001', '1000'];
const TIMES = ['2026-11-04T00:00:00Z', '2026-11-25T00:00:00Z', '2026-12-05T00:00:00Z', '2026-12-12T00:00:00Z', '2026-12-20T00:00:00Z', '2027-02-01T00:00:00Z'].map(
  (date) => parseDateTime(date)!,
);

describe('caveatRefusal over random chains and calls', () => {
  it('passes only a call every hop of the chain passes, and none under a verdict that refuses it', () => {
    const next = random(20261119);
    const counts = { chainsPassed: 0, chainsRefused: 0, callsPassed: 0, callsRefused: 0 };
    for (let run = 0; run < 1500; run += 1) {
      const depth = 1 + Math.floor(next() * 3);
      const caveats: Caveat[][] = [caveatsFrom(next, true)];
      // Most chains narrow at every hop; the rest draw each hop afresh, so many are refused.
      const honest = next() < 0.75;
      for (let i = 1; i < depth; i += 1) caveats.push(honest ? narrowerThan(next, caveats[i - 1]!) : caveatsFrom(next, true));
      // Each hop expires no later than its parent, as the chain rules require.
      const windows = caveats.map(() => pick(next, WINDOWS)).sort().reverse();
      const chain = unsignedChain(caveats, windows);
      const verdict = validateDelegationChain(chain, { now });
      counts[verdict.ok ? 'chainsPassed' : 'chainsRefused'] += 1;
      for (let c = 0; c < 6; c += 1) {
        const currency = pick(next, CURRENCIES);
        const call: CaveatCall = { amount: pick(next, AMOUNTS), ...(currency === undefined ? {} : { currency }), at: pick(next, TIMES) };
        const refusal = caveatRefusal(verdict, { ...call, maxClockSkewMs: 0, enforcedTypes: ENFORCED });
        const context = `run ${run}: chain ${JSON.stringify(caveats)} windows ${JSON.stringify(windows)} call ${JSON.stringify(call)}`;
        if (!verdict.ok) {
          expect(refusal, context).toBeDefined();
          continue;
        }
        counts[refusal === undefined ? 'callsPassed' : 'callsRefused'] += 1;
        if (refusal !== undefined) continue;
        chain.forEach((hop, i) => {
          expect(call.at! <= parseDateTime(hop.validUntil)!, `${context}: hop ${i} validUntil`).toBe(true);
          for (const caveat of hop.credentialSubject.caveats ?? []) {
            expect(keepsTo(caveat, call), `${context}: hop ${i} caveat ${JSON.stringify(caveat)}`).toBe(true);
          }
        });
      }
    }
    expect(counts.chainsPassed).toBeGreaterThan(500);
    expect(counts.chainsRefused).toBeGreaterThan(100);
    expect(counts.callsPassed).toBeGreaterThan(500);
    expect(counts.callsRefused).toBeGreaterThan(500);
  });
});
