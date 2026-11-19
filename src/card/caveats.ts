/**
 * KYA-OS Entity Card: the caveats of a delegation chain (SPEC.md §6.10). How one caveat narrows
 * another, which is the rule each hop's caveats are held to against its parent's, and from that
 * rule the caveats a verified chain grants under: the tightest of each kind the chain states, so a
 * host holds a call to the chain's limits from the verdict alone, without reading the chain again.
 *
 * The library knows two caveat types. It holds each hop to its `ValidUntil` itself
 * (`./hop-window.ts`). A `MaxAmount` limits a value only the host sees, such as the total of an
 * order, so the host enforces it. A caveat of any other type is compared verbatim, and only the
 * host can enforce it, so the verdict lists it apart and the library warns once per process.
 */

import { parseDateTime } from '../utils/rfc3339.js';
import { warnOncePerProcess } from '../utils/warn-once.js';
import type { Caveat, DelegationChain } from './delegation.js';

/** The caveat types this library reads, and so reduces to the tightest; any other is kept as written. */
const KNOWN_CAVEAT_TYPES: ReadonlySet<string> = new Set(['ValidUntil', 'MaxAmount']);

/** A non-negative decimal split into its digit strings, or `undefined` when it is not one. */
function decimalParts(dec: string): { whole: string; fraction: string } | undefined {
  const match = /^(\d+)(?:\.(\d+))?$/.exec(dec.trim());
  return match?.[1] ? { whole: match[1], fraction: match[2] ?? '' } : undefined;
}

// `child ≤ parent`, compared EXACTLY, fail-closed (any unparseable value ⇒ false). Both sides are
// scaled to the longer fraction, never truncated: rounding to a fixed precision would let a child
// whose excess sits below that precision (100.0000009 under a parent of 100) pass as a narrowing.
function decimalLte(child: string, parent: string): boolean {
  const c = decimalParts(child);
  const p = decimalParts(parent);
  if (!c || !p) return false;
  const scale = Math.max(c.fraction.length, p.fraction.length);
  const scaled = ({ whole, fraction }: { whole: string; fraction: string }): bigint =>
    BigInt(whole + fraction.padEnd(scale, '0'));
  return scaled(c) <= scaled(p);
}

/** `child ≤ parent`, each read as an RFC 3339 date-time with its zone, fail-closed (any other value ⇒ false). */
export function dateLte(child: string, parent: string): boolean {
  const c = parseDateTime(child);
  const p = parseDateTime(parent);
  return c !== undefined && p !== undefined && c <= p;
}

// Stable structural form (sorted-key JSON): two caveats of a type the library does not know are the
// same caveat iff their forms are equal.
function canonical(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}
function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(record).sort().map((k) => [k, sortKeys(record[k])]));
  }
  return value;
}

/** True iff `child` is at least as narrow as `parent` for the same caveat. */
export function caveatNarrows(parent: Caveat, child: Caveat): boolean {
  if (parent.type !== child.type) return false;
  if (parent.type === 'ValidUntil') {
    return typeof parent.date === 'string' && typeof child.date === 'string' && dateLte(child.date, parent.date);
  }
  if (parent.type === 'MaxAmount') {
    // Currency is monotone, not strict-equal: a currency-LESS parent (any currency, per the optional
    // schema) may be narrowed by a child that pins one; a parent that already pins a currency requires
    // the SAME one (dropping/switching it broadens). Never fail-open — the amount must still narrow.
    const currencyNarrows = parent.currency === undefined || parent.currency === child.currency;
    return (
      currencyNarrows &&
      typeof parent.limit === 'string' &&
      typeof child.limit === 'string' &&
      decimalLte(child.limit, parent.limit)
    );
  }
  return canonical(parent) === canonical(child); // unknown caveat type — must be replicated verbatim
}

/**
 * The tightest of `caveats`: each that no other narrows ({@link caveatNarrows}), so a call held to
 * these is held to every one of `caveats`. Of two that each narrow the other, such as `MaxAmount`
 * limits written `100` and `100.00`, the first is kept. Two that neither narrows, such as
 * `MaxAmount` limits in two currencies, are both kept. A caveat of a type this library does not
 * know narrows only one written the same, so each is kept once, as first written, after the rest.
 */
export function tightestCaveats(caveats: readonly Caveat[]): Caveat[] {
  let known: Caveat[] = [];
  const unknown = new Map<string, Caveat>();
  for (const caveat of caveats) {
    if (!KNOWN_CAVEAT_TYPES.has(caveat.type)) {
      const form = canonical(caveat);
      if (!unknown.has(form)) unknown.set(form, caveat);
    } else if (!known.some((kept) => caveatNarrows(caveat, kept))) {
      known = [...known.filter((kept) => !caveatNarrows(kept, caveat)), caveat];
    }
  }
  return [...known, ...unknown.values()];
}

/**
 * The caveats a delegation chain grants under, as every verdict on a chain carries them: what
 * `validateDelegationChain` and `evaluateDelegationChain` find, and the grant of `requireDelegation`
 * and `verifyRequestDelegation`. The library sets both members on each one it returns. They are
 * optional only so that a result built by code written before they were added still compiles.
 */
export interface EffectiveCaveats {
  /**
   * Every limit the chain states, at its tightest: of the caveats its hops state, each that no
   * other narrows, by the rule a hop's caveats are held to against its parent's. So the lowest
   * `MaxAmount`, one for each currency where the others do not narrow it, the earliest `ValidUntil`,
   * and each caveat of a type this library does not know, once, as written. A looser duplicate in
   * one hop never shows here. The library has held the call to each `ValidUntil`; the host holds
   * it to every other caveat here, each `MaxAmount` included, or refuses it. Empty when no hop
   * states a caveat.
   */
  caveats?: Caveat[];
  /**
   * Those of `caveats` of a type this library does not know, as written. The library passes the
   * call without enforcing them, and warns once per process when a chain carries one, so the host
   * must enforce each or refuse the call.
   */
  unknownCaveats?: Caveat[];
}

/**
 * The caveats `chain` grants under: the tightest ({@link tightestCaveats}) of every caveat its hops
 * state, root to leaf. On a chain that attenuates at every hop, they state the same limits as the
 * leaf's own caveats, which must narrow every one above them.
 */
export function effectiveCaveatsOf(chain: DelegationChain): Required<EffectiveCaveats> {
  const caveats = tightestCaveats(chain.flatMap((vc) => vc.credentialSubject.caveats ?? []));
  return { caveats, unknownCaveats: caveats.filter((caveat) => !KNOWN_CAVEAT_TYPES.has(caveat.type)) };
}

/** Where every copy of this package records the unknown-caveat warning for this process. */
const UNKNOWN_CAVEAT_WARNED = Symbol.for('@kya-os/mcp/unknown-caveat-warned');

/** Warn once per process, in fixed words, that a chain carries a caveat the library does not enforce. */
export function warnOfUnknownCaveats(): void {
  warnOncePerProcess(
    UNKNOWN_CAVEAT_WARNED,
    '[kya-os] A delegation chain carries a caveat of a type this library does not know, so it does not enforce it. ' +
      'The verdict lists it in unknownCaveats: the host must enforce it or refuse the call.',
  );
}
