/**
 * KYA-OS Entity Card: the caveats of a delegation chain (SPEC.md §6.10). How the library reads each
 * caveat, which is the rule each hop's caveats are held to against its parent's, and from that rule
 * the caveats a verified chain grants under: the tightest of each kind the chain states, so a host
 * holds a call to the chain's limits from the verdict alone, without reading the chain again.
 *
 * Every caveat applies to every call. A `MaxAmount` limits the amount of every call: one that
 * names a currency also requires the call to be in that currency, and one that names none limits
 * the amount whatever its currency. So `MaxAmount` limits in two currencies permit no call at all.
 * That is the reading under which a child that adds a caveat, or pins a currency its parent left
 * open, only narrows it.
 *
 * The library knows two caveat types, each read by its rule in {@link RULES}: the members it may
 * state, its form, the group it is read at its tightest within, how it narrows another, and how a
 * call keeps to it. It holds each hop to its `ValidUntil` itself (`./hop-window.ts`). A `MaxAmount`
 * limits a value only the host sees, so the host enforces it, with `caveatRefusal`
 * (`./caveat-refusal.ts`). A caveat of any other type, or of a known type with a member the library
 * does not know, is one it does not interpret: it is compared verbatim, never stands in for another
 * nor another for it, and only the host can enforce it, so the verdict lists it apart.
 *
 * A hop's caveats are read at their tightest once, in time linear in their number, and that reading
 * serves both the rule against its parent and the caveats the chain grants under. A caveat whose
 * arrays and objects nest deeper than a credential may ({@link MAX_CREDENTIAL_NESTING_DEPTH}) is
 * malformed, whatever its type, and is never read whole, so no depth runs a reader out of stack.
 * A reason quotes at most 64 characters of any value a caveat or a call states (`describeValue`).
 */

import type { RefusalCode } from '../refusal-codes.js';
import { MAX_CREDENTIAL_NESTING_DEPTH } from '../delegation/signed-form.js';
import { describeValue } from '../utils/describe-value.js';
import { nestsDeeperThan } from '../utils/plain-data.js';
import { DATE_TIME_FORM, dateLte, parseDateTime } from '../utils/rfc3339.js';
import { windowBreach } from '../utils/validity-window.js';
import { warnOncePerProcess } from '../utils/warn-once.js';
import type { Caveat, DelegationChain } from './delegation.js';

/** A call as a caveat is held to it: what it spends, and when, with the clock tolerance to read dates with. */
export interface HeldCall {
  amount: unknown;
  currency: unknown;
  atMs: number;
  skewMs: number;
}

/** Why a call breaks a caveat, with the code of the rule it breaks. */
export interface CaveatBreach {
  code: RefusalCode;
  reason: string;
}

/** How the library reads one caveat type it knows. */
interface CaveatRule {
  /** The members a caveat of the type may state beside `type`; one that states any other is not interpreted. */
  members: readonly string[];
  /** Why `caveat` is malformed, or `undefined` when its form is one the rule reads. */
  malformed(caveat: Caveat): string | undefined;
  /** The group a well-formed caveat is read at its tightest within: of two in one group, the tighter makes the other redundant under any reading. */
  group(caveat: Caveat): string | undefined;
  /** Whether well-formed `child` is at least as narrow as well-formed `parent`. */
  narrows(parent: Caveat, child: Caveat): boolean;
  /** Whether a caveat in another group of the type may narrow well-formed `parent`. */
  narrowedAcrossGroups(parent: Caveat): boolean;
  /** Why `call` breaks well-formed `caveat`, or `undefined` when it keeps to it. */
  breach(caveat: Caveat, call: HeldCall): CaveatBreach | undefined;
}

/** A plain non-negative decimal, compared exactly: digits, then a point and digits or nothing. */
const DECIMAL = /^(\d+)(?:\.(\d+))?$/;

/** `value` split into its digit strings when it is a plain non-negative decimal, else `undefined`. */
function decimalParts(value: unknown): { whole: string; fraction: string } | undefined {
  const match = typeof value === 'string' ? DECIMAL.exec(value) : null;
  return match?.[1] === undefined ? undefined : { whole: match[1], fraction: match[2] ?? '' };
}

// `child ≤ parent`, compared EXACTLY, fail-closed (any value that is not a plain decimal ⇒ false).
// Both sides are scaled to the longer fraction, never truncated: rounding to a fixed precision would
// let a child whose excess sits below that precision (100.0000009 under a parent of 100) pass.
function decimalLte(child: unknown, parent: unknown): boolean {
  const c = decimalParts(child);
  const p = decimalParts(parent);
  if (!c || !p) return false;
  const scale = Math.max(c.fraction.length, p.fraction.length);
  const scaled = ({ whole, fraction }: { whole: string; fraction: string }): bigint => BigInt(whole + fraction.padEnd(scale, '0'));
  return scaled(c) <= scaled(p);
}

const VALID_UNTIL: CaveatRule = {
  members: ['date'],
  malformed: (caveat) => {
    if (caveat.date === undefined) return 'ValidUntil caveat states no date';
    return parseDateTime(caveat.date) === undefined ? `ValidUntil caveat ${describeValue(caveat.date)} is not ${DATE_TIME_FORM}` : undefined;
  },
  group: () => undefined,
  narrows: (parent, child) => dateLte(child.date, parent.date),
  narrowedAcrossGroups: () => false,
  breach: (caveat, call) =>
    windowBreach(undefined, parseDateTime(caveat.date), call.atMs, call.skewMs) === 'expired'
      ? { code: 'delegation_expired', reason: `the delegation's ValidUntil ${describeValue(caveat.date)} has passed` }
      : undefined,
};

const MAX_AMOUNT: CaveatRule = {
  members: ['limit', 'currency'],
  malformed: (caveat) => {
    if (caveat.limit === undefined) return 'MaxAmount caveat states no limit';
    if (decimalParts(caveat.limit) === undefined) return `MaxAmount caveat limit ${describeValue(caveat.limit)} is not a non-negative decimal`;
    if (caveat.currency !== undefined && typeof caveat.currency !== 'string') {
      return `MaxAmount caveat currency ${describeValue(caveat.currency)} is not a string`;
    }
    return undefined;
  },
  // A limit that names a currency is read apart from one that names none: under every reading of a
  // currency the tighter of two in one currency stands for both, but a host that reads a limit as one
  // currency's alone would read a limit in any currency as gone if the other stood in for it.
  group: (caveat) => caveat.currency,
  // A child narrows a parent that names a currency only in that currency; one that names none, in any.
  narrows: (parent, child) => (parent.currency === undefined || parent.currency === child.currency) && decimalLte(child.limit, parent.limit),
  narrowedAcrossGroups: (parent) => parent.currency === undefined,
  // A call that breaks a limit is one the chain does not grant.
  breach: (caveat, call) => {
    const outside = (reason: string): CaveatBreach => ({ code: 'insufficient_scope', reason });
    const limit = `the delegated MaxAmount of ${describeValue(caveat.limit)}${caveat.currency === undefined ? '' : ` in ${describeValue(caveat.currency)}`}`;
    if (call.amount === undefined) return outside('the call states no amount, which a delegated MaxAmount limits');
    if (decimalParts(call.amount) === undefined) return outside(`the call's amount ${describeValue(call.amount)} is not a non-negative decimal`);
    if (caveat.currency !== undefined && call.currency !== caveat.currency) {
      return outside(`${limit} permits no call ${call.currency === undefined ? 'that names no currency' : `in ${describeValue(call.currency)}`}`);
    }
    return decimalLte(call.amount, caveat.limit) ? undefined : outside(`the call's amount ${describeValue(call.amount)} is over ${limit}`);
  },
};

/** The caveat types this library knows, each with the one rule it reads them by. */
const RULES: ReadonlyMap<string, CaveatRule> = new Map([
  ['ValidUntil', VALID_UNTIL],
  ['MaxAmount', MAX_AMOUNT],
]);

/** Whether `type` is one the library reads by a rule of its own. */
export function isKnownCaveatType(type: string): boolean {
  return RULES.has(type);
}

/**
 * Why `caveat` is malformed, or `undefined`: of any type, when its arrays and objects nest deeper
 * than {@link MAX_CREDENTIAL_NESTING_DEPTH}, counted with no call stack before anything reads it
 * whole; and of a type the library knows, whatever else it states, when its rule cannot read it.
 */
export function caveatMalformation(caveat: Caveat): string | undefined {
  if (nestsDeeperThan(caveat, MAX_CREDENTIAL_NESTING_DEPTH)) {
    return `caveat ${describeValue(caveat.type)} nests more than ${MAX_CREDENTIAL_NESTING_DEPTH} levels deep`;
  }
  return RULES.get(caveat.type)?.malformed(caveat);
}

/** A member `caveat` states beside those its type's rule reads, when it is of a known type; else `undefined`. */
function memberBeyondRule(caveat: Caveat): string | undefined {
  const rule = RULES.get(caveat.type);
  return rule === undefined ? undefined : Object.keys(caveat).find((member) => member !== 'type' && !rule.members.includes(member));
}

/** Whether the library interprets `caveat`: it knows its type and every member it states. */
export function interprets(caveat: Caveat): boolean {
  return RULES.has(caveat.type) && memberBeyondRule(caveat) === undefined;
}

/**
 * Why `call` breaks `caveat`, or `undefined` when it keeps to it: a malformed caveat
 * (`delegation_malformed`); the rule of a known type, which holds even a caveat with a member the
 * library does not know to what it reads; then such a member, which the host cannot name as one it
 * enforces (`configuration_error`); and a caveat of an unknown type, unless `enforcedTypes` names
 * it (`configuration_error`).
 */
export function caveatBreach(caveat: Caveat, call: HeldCall, enforcedTypes: ReadonlySet<string>): CaveatBreach | undefined {
  const malformed = caveatMalformation(caveat);
  if (malformed !== undefined) return { code: 'delegation_malformed', reason: `the delegation carries a malformed caveat: ${malformed}` };
  const rule = RULES.get(caveat.type);
  if (rule !== undefined) {
    const member = memberBeyondRule(caveat);
    return (
      rule.breach(caveat, call) ??
      (member === undefined
        ? undefined
        : {
            code: 'configuration_error',
            reason: `the delegation carries a ${caveat.type} caveat that states ${describeValue(member)}, a member the library does not interpret`,
          })
    );
  }
  if (enforcedTypes.has(caveat.type)) return undefined;
  return { code: 'configuration_error', reason: `the delegation carries a caveat of type ${describeValue(caveat.type)} that the host does not enforce` };
}

/** A caveat as a hop's reading keeps it: with its type's rule when the library reads it by one. */
interface Read {
  caveat: Caveat;
  /** The rule of its type, when the library interprets the caveat and it is well-formed. */
  rule?: CaveatRule;
  /** Set when the caveat is of a known type and malformed: it then narrows nothing and nothing narrows it. */
  malformed?: true;
}

/** The group a caveat is read within: its type and group, its verbatim form, or, for a malformed caveat, its own. */
type GroupKey = string | symbol;

/** One hop's caveats at their tightest: the group each is read within, and the caveat it keeps. */
export type HopCaveats = ReadonlyMap<GroupKey, Read>;

/** Stable structural form (sorted-key JSON): two caveats read verbatim are the same iff their forms are equal. */
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

/**
 * `caveat` as a reading keeps it, and the group it is read within: its type and group, or its
 * verbatim form. A malformed caveat, which may nest too deep to write out, is in a group of its own.
 */
function readOf(caveat: Caveat): [GroupKey, Read] {
  if (caveatMalformation(caveat) !== undefined) return [Symbol('malformed caveat'), { caveat, malformed: true }];
  const rule = interprets(caveat) ? RULES.get(caveat.type) : undefined;
  if (rule === undefined) return [`verbatim:${canonical(caveat)}`, { caveat }];
  return [JSON.stringify([caveat.type, rule.group(caveat) ?? null]), { caveat, rule }];
}

/** Keep `read` in `groups` unless the caveat kept in its group is at least as narrow: of two equal, the first stays. */
function keepTighter(groups: Map<GroupKey, Read>, [group, read]: [GroupKey, Read]): void {
  const kept = groups.get(group);
  if (kept === undefined || (read.rule !== undefined && !read.rule.narrows(read.caveat, kept.caveat))) groups.set(group, read);
}

/**
 * The caveats of one hop at their tightest, by group, in the order each group first appears. Two
 * caveats share a group only when one makes the other redundant under any reading: two of a known
 * type the library interprets, in one currency or with none, of which the tighter is kept, the
 * first of two equal ones; or two read verbatim and written the same, of which one is kept.
 */
export function tightestOf(caveats: readonly Caveat[]): HopCaveats {
  const groups = new Map<GroupKey, Read>();
  for (const caveat of caveats) keepTighter(groups, readOf(caveat));
  return groups;
}

/** Whether a caveat of `child` narrows `parent`, kept in `group` of its own hop. */
function narrowedIn(group: GroupKey, parent: Read, child: HopCaveats): boolean {
  if (parent.malformed) return false;
  const same = child.get(group);
  if (parent.rule === undefined) return same !== undefined; // read verbatim: only its equal narrows it
  const { rule, caveat } = parent;
  if (same !== undefined && rule.narrows(caveat, same.caveat)) return true;
  if (!rule.narrowedAcrossGroups(caveat)) return false;
  for (const read of child.values()) if (read.rule === rule && rule.narrows(caveat, read.caveat)) return true;
  return false;
}

/** The caveats of `parent` that no caveat of `child` narrows, each hop read at its tightest. */
export function unnarrowedCaveats(parent: HopCaveats, child: HopCaveats): Caveat[] {
  return [...parent].filter(([group, read]) => !narrowedIn(group, read, child)).map(([, read]) => read.caveat);
}

/** The rules the caveats of `chain` break by their form: each malformed caveat ({@link caveatMalformation}), on any hop. */
export function malformedCaveatRules(chain: DelegationChain): { code: 'delegation_malformed'; reason: string }[] {
  return chain.flatMap((vc, i) =>
    (vc.credentialSubject.caveats ?? []).flatMap((caveat) => {
      const malformed = caveatMalformation(caveat);
      return malformed === undefined ? [] : [{ code: 'delegation_malformed' as const, reason: `hop ${i}: ${malformed}` }];
    }),
  );
}

/**
 * The caveats a delegation chain grants under, as every verdict on a chain carries them: what
 * `validateDelegationChain` and `evaluateDelegationChain` find, and the grant of `requireDelegation`
 * and `verifyRequestDelegation`. The library sets both members on each one it returns. They are
 * optional only so that a result built by code written before they were added still compiles; a
 * host that reads a result without them, such as a test double or a cached grant, must not read it
 * as unlimited, which `caveatRefusal` never does.
 */
export interface EffectiveCaveats {
  /**
   * Every limit the chain states, at its tightest: the lowest `MaxAmount` of each currency it names
   * and the lowest of those that name none, the earliest `ValidUntil`, and each caveat the library
   * does not interpret, once, as written, in the order each first appears, root to leaf. The hops'
   * own `validUntil` count as `ValidUntil` caveats read after every caveat the hops state, so the
   * earliest of them stands in for a later `ValidUntil`, or is added when no hop states one, and a
   * verdict kept for later is still held to the chain's expiry. Every one applies to every call. A
   * `MaxAmount` that names a currency also requires the call to be in that currency, so two in
   * different currencies permit no call, and one that names none limits the amount whatever its
   * currency. A looser duplicate in one hop never shows here. The library has held the call to each
   * `ValidUntil` when it read the chain; the host holds it to every caveat here, each `MaxAmount`
   * included, or refuses it: `caveatRefusal` does that. Empty when no hop states a caveat or a
   * `validUntil`.
   */
  caveats?: Caveat[];
  /**
   * Those of `caveats` the library does not interpret, as written: of a type it does not know, or of
   * a known type with a member it does not know, such as `per`. The library passes the call without
   * enforcing them, and warns once per process when it passes one, so the host must enforce each or
   * refuse the call.
   */
  unknownCaveats?: Caveat[];
}

/**
 * The caveats `chain` grants under, its hops' caveats read as `hops`, root to leaf: the tightest of
 * them by group ({@link tightestOf}), each in the order its group first appears, then the `validUntil`
 * of each hop that states a date, read as a `ValidUntil` caveat.
 */
export function effectiveCaveatsOf(chain: DelegationChain, hops: readonly HopCaveats[]): Required<EffectiveCaveats> {
  const groups = new Map<GroupKey, Read>();
  for (const hop of hops) for (const entry of hop) keepTighter(groups, entry);
  for (const { validUntil } of chain) {
    if (parseDateTime(validUntil) !== undefined) keepTighter(groups, readOf({ type: 'ValidUntil', date: validUntil }));
  }
  const caveats = [...groups.values()].map((read) => read.caveat);
  return { caveats, unknownCaveats: caveats.filter((caveat) => !interprets(caveat)) };
}

/** Where every copy of this package records the unknown-caveat warning for this process. */
const UNKNOWN_CAVEAT_WARNED = Symbol.for('@kya-os/mcp/unknown-caveat-warned');

/**
 * Warn once per process, in fixed words, when `verdict`, a verdict the library is about to pass,
 * carries a caveat it does not interpret. Called only where a passing verdict is returned, so
 * reading a chain stays free of side effects.
 */
export function warnOfUnknownCaveats(verdict: EffectiveCaveats): void {
  if ((verdict.unknownCaveats?.length ?? 0) === 0) return;
  warnOncePerProcess(
    UNKNOWN_CAVEAT_WARNED,
    '[kya-os] A delegation chain carries a caveat this library does not interpret, so it does not enforce it. ' +
      'The verdict lists it in unknownCaveats: the host must enforce it or refuse the call.',
  );
}
