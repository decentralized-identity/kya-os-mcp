/**
 * The rule a hop's caveats were held to against its parent's in 1.25.0, copied from
 * `src/card/delegation.ts` at that release with only two comments' punctuation changed, so a test
 * can show that the rule today passes and refuses the same hops over well-formed caveats. It is
 * frozen: never change it to match the library.
 */

import { parseDateTime } from '../../utils/rfc3339.js';
import type { Caveat } from '../delegation.js';

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
// `child ≤ parent`, each read as an RFC 3339 date-time with its zone, fail-closed (any other value ⇒ false).
function dateLte(child: string, parent: string): boolean {
  const c = parseDateTime(child);
  const p = parseDateTime(parent);
  return c !== undefined && p !== undefined && c <= p;
}

// Stable structural equality (sorted-key JSON) for verbatim unknown-caveat comparison.
function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b));
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
function caveatNarrows(parent: Caveat, child: Caveat): boolean {
  if (parent.type !== child.type) return false;
  if (parent.type === 'ValidUntil') {
    return typeof parent.date === 'string' && typeof child.date === 'string' && dateLte(child.date, parent.date);
  }
  if (parent.type === 'MaxAmount') {
    // Currency is monotone, not strict-equal: a currency-LESS parent (any currency, per the optional
    // schema) may be narrowed by a child that pins one; a parent that already pins a currency requires
    // the SAME one (dropping/switching it broadens). Never fail-open: the amount must still narrow.
    const currencyNarrows = parent.currency === undefined || parent.currency === child.currency;
    return (
      currencyNarrows &&
      typeof parent.limit === 'string' &&
      typeof child.limit === 'string' &&
      decimalLte(child.limit, parent.limit)
    );
  }
  return deepEqual(parent, child); // unknown caveat type: must be replicated verbatim
}
function caveatReasons(parent: readonly Caveat[], child: readonly Caveat[]): string[] {
  return parent
    .filter((pc) => !child.some((cc) => caveatNarrows(pc, cc)))
    .map((pc) => `caveat "${pc.type}" broadened or dropped by child (monotone-narrowing violated)`);
}

/** Whether `child` narrows every caveat of `parent`, as 1.25.0 held a hop to its parent. */
export const attenuatedIn1250 = (parent: readonly Caveat[], child: readonly Caveat[]): boolean => caveatReasons(parent, child).length === 0;

/** `child <= parent`, each a plain non-negative decimal, compared exactly as 1.25.0 compared them. */
export { decimalLte };
