/**
 * A re-delegation narrows its parent's constraints beside its scopes (SPEC.md §6.3, §6.4): a CRISP
 * budget no wider than the parent's, and each member of `constraints` or `constraints.crisp` the
 * walk does not interpret replicated as written, since whatever enforces them reads them from the
 * presented credential alone.
 */
import { describe, expect, it } from "vitest";
import { validateDelegationChain } from "../chain-enforcement.js";
import { checkConstraintAttenuation } from "../constraint-attenuation.js";
import type { CrispBudget, DelegationCredential } from "../../types/protocol.js";
import { SERVER, cred, resolving } from "./helpers/chain-fixtures.js";

/** `credential` with `extra` merged into its delegation's constraints. */
function constrained(credential: DelegationCredential, extra: Record<string, unknown>): DelegationCredential {
  const delegation = credential.credentialSubject.delegation;
  return {
    ...credential,
    credentialSubject: {
      ...credential.credentialSubject,
      delegation: { ...delegation, constraints: { ...delegation.constraints, ...extra } },
    },
  };
}

const budgeted = (budget: unknown, crisp: Record<string, unknown> = {}) => ({ crisp: { scopes: [], budget, ...crisp } });
/** A case of a child the walk refuses: what it does, its parent's constraints, its own, and the reason. */
type Refused = [name: string, parent: Record<string, unknown>, child: Record<string, unknown>, reason: string];
const parentOf = (extra: Record<string, unknown>) =>
  constrained(cred({ id: "parent", issuerDid: "did:user", subjectDid: "did:agent", scopes: ["orders:place"] }), extra);
const childOf = (extra: Record<string, unknown>) =>
  constrained(
    cred({ id: "child", issuerDid: "did:agent", subjectDid: "did:sub", parentId: "parent", scopes: ["orders:place"], audience: SERVER }),
    extra,
  );
const check = (parent: Record<string, unknown>, child: Record<string, unknown>) =>
  checkConstraintAttenuation(parentOf(parent), childOf(child));

const USD_100: CrispBudget = { unit: "USD", cap: 100 };
const DAILY_100: CrispBudget = { unit: "USD", cap: 100, window: { kind: "rolling", durationSec: 86_400 } };
const FIXED_DAY_100: CrispBudget = { unit: "USD", cap: 100, window: { kind: "fixed", durationSec: 86_400 } };

describe("checkConstraintAttenuation: the budget", () => {
  it.each([
    ["the parent states none", {}, budgeted(USD_100)],
    ["the child states the parent's", budgeted(USD_100), budgeted(USD_100)],
    ["the child lowers the cap", budgeted(USD_100), budgeted({ unit: "USD", cap: 40 })],
    ["the child lowers the cap of each window", budgeted(DAILY_100), budgeted({ ...DAILY_100, cap: 10 })],
    ["the child caps for all time what the parent caps for each window", budgeted(DAILY_100), budgeted(USD_100)],
    ["the child's window is of the same kind and longer", budgeted(DAILY_100), budgeted({ ...DAILY_100, window: { kind: "rolling", durationSec: 604_800 } })],
    ["both state the same budget the walk cannot read", budgeted({ unit: "USD", cap: "100" }), budgeted({ unit: "USD", cap: "100" })],
    ["the child lowers the cap of each of the parent's fixed windows", budgeted(FIXED_DAY_100), budgeted({ ...FIXED_DAY_100, cap: 10 })],
    ["the child caps for all time what the parent caps for each fixed window", budgeted(FIXED_DAY_100), budgeted(USD_100)],
    // Every fixed day lies within some rolling window as long, which the child's cap holds.
    ["the child rolls a window as long as the parent's fixed one", budgeted(FIXED_DAY_100), budgeted(DAILY_100)],
    ["the child rolls a window longer than the parent's fixed one", budgeted(FIXED_DAY_100), budgeted({ ...DAILY_100, window: { kind: "rolling", durationSec: 604_800 } })],
  ])("passes when %s", (_name, parent, child) => {
    expect(check(parent, child)).toEqual({ valid: true });
  });

  it.each<Refused>([
    ["drops the budget", budgeted(USD_100), {}, "Delegation child drops the budget parent parent states"],
    ["raises the cap", budgeted(USD_100), budgeted({ unit: "USD", cap: 1_000_000 }), "Delegation child states a budget cap above parent parent's"],
    ["changes the unit", budgeted(USD_100), budgeted({ unit: "points", cap: 1 }), "Delegation child states a budget in another unit than parent parent"],
    [
      "resets each window what the parent caps for all time",
      budgeted(USD_100),
      budgeted(DAILY_100),
      "Delegation child states a budget window parent parent's budget does not contain",
    ],
    [
      "shortens the window",
      budgeted(DAILY_100),
      budgeted({ ...DAILY_100, window: { kind: "rolling", durationSec: 3_600 } }),
      "Delegation child states a budget window parent parent's budget does not contain",
    ],
    [
      "changes the kind of window",
      budgeted(DAILY_100),
      budgeted({ ...DAILY_100, window: { kind: "fixed", durationSec: 86_400 } }),
      "Delegation child states a budget window parent parent's budget does not contain",
    ],
    // A fixed window of another length starts where the parent's does not, so the child could spend
    // its cap at the end of one of its windows and again at the start of the next, in one parent day.
    ...[
      ["longer than", 129_600],
      ["shorter than", 43_200],
      ["a whole number of times as long as", 172_800],
    ].map(([what, durationSec]): Refused => [
      `resets a fixed window ${String(what)} the parent's fixed one`,
      budgeted(FIXED_DAY_100),
      budgeted({ ...FIXED_DAY_100, window: { kind: "fixed", durationSec } }),
      "Delegation child states a budget window parent parent's budget does not contain",
    ]),
    [
      "rolls a window shorter than the parent's fixed one",
      budgeted(FIXED_DAY_100),
      budgeted({ ...DAILY_100, window: { kind: "rolling", durationSec: 3_600 } }),
      "Delegation child states a budget window parent parent's budget does not contain",
    ],
    [
      "states a cap that is not a number",
      budgeted(USD_100),
      budgeted({ unit: "USD", cap: "10" }),
      "Delegation child states a budget that cannot be compared with parent parent's",
    ],
    [
      "states a budget member the walk does not interpret",
      budgeted(USD_100),
      budgeted({ unit: "USD", cap: 10, per: "call" }),
      "Delegation child states a budget that cannot be compared with parent parent's",
    ],
    [
      "narrows a parent budget the walk cannot read",
      budgeted({ unit: "USD", cap: -1 }),
      budgeted({ unit: "USD", cap: 0 }),
      "Delegation child states a budget that cannot be compared with parent parent's",
    ],
    [
      "states a window that is not one",
      budgeted(DAILY_100),
      budgeted({ ...DAILY_100, window: { kind: "rolling", durationSec: 0 } }),
      "Delegation child states a budget that cannot be compared with parent parent's",
    ],
    ...[
      ["named in words", "daily"],
      ["of a kind the walk does not know", { kind: "sliding", durationSec: 86_400 }],
      ["with a member the walk does not interpret", { kind: "rolling", durationSec: 86_400, anchor: "midnight" }],
    ].map(([what, window]): Refused => [
      `states a window ${String(what)}`,
      budgeted(DAILY_100),
      budgeted({ ...DAILY_100, window }),
      "Delegation child states a budget that cannot be compared with parent parent's",
    ]),
  ])("refuses a child that %s", (_name, parent, child, reason) => {
    expect(check(parent, child)).toEqual({ valid: false, reason, code: "chain_invalid", transient: false });
  });
});

describe("checkConstraintAttenuation: members the walk does not interpret", () => {
  it("passes a child that replicates them as written, in any member order, and adds its own", () => {
    const parent = { region: { allow: ["eu", "uk"], mode: "strict" }, crisp: { scopes: [], tier: "gold" } };
    const child = { region: { mode: "strict", allow: ["eu", "uk"] }, crisp: { scopes: [], tier: "gold", extra: 1 }, own: true };
    expect(check(parent, child)).toEqual({ valid: true });
  });

  it.each([
    ["drops a constraint", { region: "eu" }, {}, 'Delegation child does not replicate the constraint "region" parent parent states'],
    ["changes a constraint", { region: "eu" }, { region: "us" }, 'Delegation child does not replicate the constraint "region" parent parent states'],
    ["drops a CRISP member", { crisp: { scopes: [], tier: "gold" } }, {}, 'Delegation child does not replicate the CRISP member "tier" parent parent states'],
    [
      "changes a CRISP member",
      { crisp: { scopes: [], tier: "gold" } },
      { crisp: { scopes: [], tier: "platinum" } },
      'Delegation child does not replicate the CRISP member "tier" parent parent states',
    ],
  ])("refuses a child that %s", (_name, parent, child, reason) => {
    expect(check(parent, child)).toEqual({ valid: false, reason, code: "chain_invalid", transient: false });
  });

  it("reads no member of a parent's CRISP envelope that is not an object", () => {
    expect(check({ crisp: "opaque" }, {})).toEqual({ valid: true });
  });

  it("reads constraints that are not an object as none", () => {
    const stating = (credential: DelegationCredential, constraints: unknown): DelegationCredential => ({
      ...credential,
      credentialSubject: {
        ...credential.credentialSubject,
        delegation: { ...credential.credentialSubject.delegation, constraints: constraints as never },
      },
    });
    expect(checkConstraintAttenuation(stating(parentOf({}), "opaque"), childOf({}))).toEqual({ valid: true });
    expect(checkConstraintAttenuation(parentOf(budgeted(USD_100)), stating(childOf({}), null))).toMatchObject({
      valid: false,
      reason: "Delegation child drops the budget parent parent states",
    });
  });
});

describe("validateDelegationChain: a re-delegation that widens its parent's budget", () => {
  it("is refused, with no warnings, whichever hop widens it", async () => {
    const root = parentOf(budgeted(USD_100));
    const widened = childOf(budgeted({ unit: "USD", cap: 1_000_000 }));
    const walk = await validateDelegationChain(widened, resolving([root]));
    expect(walk).toMatchObject({
      valid: false,
      reason: "Delegation child states a budget cap above parent parent's",
      code: "chain_invalid",
    });
    expect(walk.warnings).toBeUndefined();

    const narrowed = childOf(budgeted({ unit: "USD", cap: 50 }));
    expect(await validateDelegationChain(narrowed, resolving([root]))).toMatchObject({ valid: true });
  });
});
