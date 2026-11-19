/**
 * Attenuation of what a delegation's constraints state beside its scopes (SPEC.md §6.3, §6.4).
 * Whatever enforces a constraint the chain walk does not, a CRISP budget or a member of the
 * envelope the library does not interpret, reads it from the presented credential, the chain's
 * last, alone. So a re-delegation may only narrow its parent's budget, and must replicate, as
 * written, each member of `constraints` and of `constraints.crisp` its parent states that the walk
 * does not interpret. Pure: each function reads two credentials. Scope attenuation is
 * `./chain-attenuation.ts`'s; the chain walk applies both.
 */
import type { DelegationCredential } from "../types/protocol.js";
import { sameCanonicalJson } from "../utils/canonical-json.js";
import { describeValue } from "../utils/describe-value.js";
import { isRecord } from "../utils/guards.js";
import { refusal, type Checked } from "../utils/refusal.js";

/** The members of `constraints` the chain walk interprets: each is checked by a rule of its own. */
const INTERPRETED_CONSTRAINTS: ReadonlySet<string> = new Set(["notBefore", "notAfter", "scopes", "audience", "crisp"]);

/** The members of `constraints.crisp` the chain walk interprets. */
const INTERPRETED_CRISP_MEMBERS: ReadonlySet<string> = new Set(["scopes", "budget"]);

/** The members a budget may state, and those its window may: any other leaves the budget unread. */
const BUDGET_MEMBERS: ReadonlySet<string> = new Set(["unit", "cap", "window"]);
const WINDOW_MEMBERS: ReadonlySet<string> = new Set(["kind", "durationSec"]);
const WINDOW_KINDS: ReadonlySet<unknown> = new Set(["rolling", "fixed"]);

/** A CRISP budget as the walk compares it: a cap of `unit` for all time, or for each `window`. */
interface ReadBudget {
  readonly unit: string;
  readonly cap: number;
  readonly window?: { readonly kind: string; readonly durationSec: number };
}

/**
 * Why `childCredential` does not narrow the constraints of `parentCredential` beside its scopes,
 * or `{ valid: true }`. A refusal is `chain_invalid`.
 *
 * The budget (`constraints.crisp.budget`): a child under a parent that states none may state any;
 * under one that does, it must state the same, or one in the same `unit` whose `cap` is no higher,
 * and either no `window`, so the cap is for all time, or, under a parent's window, a window of the
 * same `kind` at least as long. A budget the walk cannot read, one with a member it does not
 * interpret among them, passes only where the child states the parent's as written.
 *
 * Every other member of `constraints` and of `constraints.crisp` the parent states, other than
 * those the walk checks by their own rules (`notBefore`, `notAfter`, `scopes`, `audience`), the
 * child must state with an equal value (RFC 8785). The child may add members of its own.
 */
export function checkConstraintAttenuation(
  parentCredential: DelegationCredential,
  childCredential: DelegationCredential,
): Checked {
  const parentId = parentCredential.credentialSubject.delegation.id;
  const childId = childCredential.credentialSubject.delegation.id;
  const parent = constraintsOf(parentCredential);
  const child = constraintsOf(childCredential);
  const parentCrisp = isRecord(parent.crisp) ? parent.crisp : {};
  const childCrisp = isRecord(child.crisp) ? child.crisp : {};

  const budget = budgetRefusal(parentCrisp, childCrisp);
  if (budget !== undefined) return refusal("chain_invalid", `Delegation ${childId} ${budget(parentId)}`);

  const constraint = unreplicated(parent, child, INTERPRETED_CONSTRAINTS);
  if (constraint !== undefined) {
    return refusal("chain_invalid", `Delegation ${childId} does not replicate the constraint ${describeValue(constraint)} parent ${parentId} states`);
  }
  const member = unreplicated(parentCrisp, childCrisp, INTERPRETED_CRISP_MEMBERS);
  if (member !== undefined) {
    return refusal("chain_invalid", `Delegation ${childId} does not replicate the CRISP member ${describeValue(member)} parent ${parentId} states`);
  }
  return { valid: true };
}

/** A credential's `constraints`, or none when it states no object there. */
function constraintsOf(credential: DelegationCredential): Record<string, unknown> {
  const constraints: unknown = credential.credentialSubject.delegation.constraints;
  return isRecord(constraints) ? constraints : {};
}

/** The first member of `parent` outside `interpreted` that `child` does not state with an equal value. */
function unreplicated(
  parent: Record<string, unknown>,
  child: Record<string, unknown>,
  interpreted: ReadonlySet<string>,
): string | undefined {
  return Object.keys(parent).find(
    (key) => !interpreted.has(key) && !(Object.hasOwn(child, key) && sameCanonicalJson(child[key], parent[key])),
  );
}

/**
 * Why the child's budget is wider than the parent's, as the rest of a sentence about the child
 * that names the parent, or `undefined` when it is not.
 */
function budgetRefusal(
  parentCrisp: Record<string, unknown>,
  childCrisp: Record<string, unknown>,
): ((parentId: string) => string) | undefined {
  if (!Object.hasOwn(parentCrisp, "budget")) return undefined;
  if (!Object.hasOwn(childCrisp, "budget")) return (parentId) => `drops the budget parent ${parentId} states`;
  if (sameCanonicalJson(childCrisp.budget, parentCrisp.budget)) return undefined;
  const parent = readBudget(parentCrisp.budget);
  const child = readBudget(childCrisp.budget);
  if (parent === undefined || child === undefined) {
    return (parentId) => `states a budget that cannot be compared with parent ${parentId}'s`;
  }
  if (child.unit !== parent.unit) return (parentId) => `states a budget in another unit than parent ${parentId}`;
  if (child.cap > parent.cap) return (parentId) => `states a budget cap above parent ${parentId}'s`;
  if (!windowWithin(parent.window, child.window)) {
    return (parentId) => `states a budget window parent ${parentId}'s budget does not contain`;
  }
  return undefined;
}

/**
 * Whether a cap for each `child` window spends no more than one for each `parent` window: a cap for
 * all time does, and under a parent's window so does one for a window of its kind at least as long.
 * A cap for each window spends more than one for all time.
 */
function windowWithin(parent: ReadBudget["window"], child: ReadBudget["window"]): boolean {
  if (child === undefined) return true;
  return parent !== undefined && child.kind === parent.kind && child.durationSec >= parent.durationSec;
}

/** `value` as a budget the walk compares, or `undefined` when it states anything else. */
function readBudget(value: unknown): ReadBudget | undefined {
  if (!isRecord(value) || !onlyMembers(value, BUDGET_MEMBERS)) return undefined;
  const { unit, cap, window } = value;
  if (typeof unit !== "string" || unit === "" || !isNonNegative(cap)) return undefined;
  if (window === undefined) return { unit, cap };
  if (!isRecord(window) || !onlyMembers(window, WINDOW_MEMBERS) || !WINDOW_KINDS.has(window.kind)) return undefined;
  const { durationSec } = window;
  if (!isNonNegative(durationSec) || durationSec === 0) return undefined;
  return { unit, cap, window: { kind: window.kind as string, durationSec } };
}

function onlyMembers(value: Record<string, unknown>, members: ReadonlySet<string>): boolean {
  return Object.keys(value).every((key) => members.has(key));
}

function isNonNegative(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}
