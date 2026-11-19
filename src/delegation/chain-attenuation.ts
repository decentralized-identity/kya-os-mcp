/**
 * Scope attenuation across a delegation chain (SPEC.md §6.4): the rule a re-delegation is refused
 * by when it grants more than its parent, and the ways it may be wider than its parent that chain
 * validation reports as warnings rather than refuses. Pure: each function reads two credentials.
 * Re-exported from `./chain-enforcement.ts`, where the chain walk applies them.
 */
import type { CrispScope, DelegationCredential } from "../types/protocol.js";
import { sameCanonicalJson } from "../utils/canonical-json.js";
import { parseDateTime } from "../utils/rfc3339.js";
import { refusal, type Checked } from "../utils/refusal.js";
import type { RefusalCoding } from "./vc-verifier.types.js";
import { authorityContains, crispScopes, matcherContains, scopeAuthority } from "./scope-matcher.js";

/** Union of a credential's delegation scopes and its constraint scopes. */
export function getDelegationScopes(credential: DelegationCredential): string[] {
  const scopes = new Set<string>();
  for (const scope of credential.credentialSubject.delegation.scopes ?? []) {
    scopes.add(scope);
  }
  for (const scope of credential.credentialSubject.delegation.constraints?.scopes ?? []) {
    scopes.add(scope);
  }
  return Array.from(scopes);
}

/**
 * A child re-delegation may only narrow (attenuate) its parent's authority
 * (SPEC.md §6.4). Scope authority comes in two representations (SPEC.md §6.3):
 * flat scopes, matched exactly, and CRISP scope matchers. Both credentials are
 * read as one typed authority ({@link scopeAuthority}), and every flat scope and
 * matcher the child grants must be proven inside the parent's authority
 * ({@link authorityContains}), whichever representation either side uses;
 * anything unprovable, including a malformed entry, fails closed. A credential
 * with no scopes of either kind grants no scope, as `scopeSatisfies` reads it:
 * such a parent admits only a child that grants none either, and such a child
 * never attenuates a parent that has scopes. A refusal is `chain_invalid`,
 * which its `code` says. Pure.
 */
export function validateScopeAttenuation(
  parentCredential: DelegationCredential,
  childCredential: DelegationCredential,
): { valid: boolean; reason?: string } & RefusalCoding {
  return checkScopeAttenuation(parentCredential, childCredential);
}

/**
 * {@link validateScopeAttenuation}, with a refusal that cannot be built without its code: the
 * chain walk reads it through this, so the code of a refusal is typed as always present.
 */
export function checkScopeAttenuation(
  parentCredential: DelegationCredential,
  childCredential: DelegationCredential,
): Checked {
  const parentId = parentCredential.credentialSubject.delegation.id;
  const childId = childCredential.credentialSubject.delegation.id;
  const parentAuthority = scopeAuthority(parentCredential);
  if (parentAuthority.length === 0) {
    // A child whose scope fields cannot be read may grant anything, so only one read as empty passes.
    return authorityOf(childCredential)?.length === 0
      ? { valid: true }
      : refusal("chain_invalid", `Delegation ${childId} widens scopes beyond parent ${parentId}, which grants no scope`);
  }

  const childScopes = getDelegationScopes(childCredential);
  const childMatchers = crispScopes(childCredential);
  if (childScopes.length === 0 && childMatchers.length === 0) {
    return refusal("chain_invalid", `Delegation ${childId} omits scopes required to prove attenuation from parent ${parentId}`);
  }

  const withinParent = authorityContains(parentAuthority);
  const widenedMatchers = childMatchers.filter((scope) => !withinParent(scope));
  if (widenedMatchers.length > 0) {
    return refusal(
      "chain_invalid",
      `Delegation ${childId} introduces crisp scope matcher(s) outside parent ${parentId}: ${widenedMatchers
        .map((s) => `${s?.matcher}:${s?.resource}`)
        .join(", ")}`,
    );
  }
  const widenedScopes = childScopes.filter((scope) => !withinParent({ resource: scope, matcher: "exact" }));
  if (widenedScopes.length > 0) {
    return refusal("chain_invalid", `Delegation ${childId} widens scopes beyond parent ${parentId}: ${widenedScopes.join(", ")}`);
  }

  return { valid: true };
}

/**
 * The earliest finite expiry a credential states (ms epoch), from `expirationDate`, read as an RFC
 * 3339 date-time with its zone, and `constraints.notAfter`.
 */
export function statedExpiry(credential: DelegationCredential): number | undefined {
  const notAfter = credential?.credentialSubject?.delegation?.constraints?.notAfter;
  const deadlines = [
    credential?.expirationDate ? parseDateTime(credential.expirationDate) : undefined,
    notAfter !== undefined ? notAfter * 1000 : undefined,
  ].filter((deadline): deadline is number => deadline !== undefined && Number.isFinite(deadline));
  return deadlines.length > 0 ? Math.min(...deadlines) : undefined;
}

/** The DIDs a credential's `constraints.audience` names, or undefined when it names none. */
function statedAudience(credential: DelegationCredential): string[] | undefined {
  const audience = credential?.credentialSubject?.delegation?.constraints?.audience;
  if (typeof audience === "string") return [audience];
  return Array.isArray(audience) ? audience.filter((did) => typeof did === "string") : undefined;
}

/** A scope's `constraints` record as entries; anything but a plain object constrains nothing. */
function constraintEntries(constraints: unknown): [string, unknown][] {
  return constraints !== null && typeof constraints === "object" && !Array.isArray(constraints)
    ? Object.entries(constraints)
    : [];
}

/** A credential's scope authority, or undefined when its scope fields are not lists and cannot be read. */
function authorityOf(credential: DelegationCredential): CrispScope[] | undefined {
  try {
    return scopeAuthority(credential);
  } catch {
    return undefined;
  }
}

/** A credential's scope authority, or none when its scope fields are not lists and cannot be read. */
function readableAuthority(credential: DelegationCredential): CrispScope[] {
  return authorityOf(credential) ?? [];
}

/**
 * SPEC.md §6.4: "Scope constraints MUST be equal to or narrower than parent's
 * constraints." Ways a re-delegation is wider than its parent, or cannot be
 * shown not to be, that chain validation accepts today:
 *
 * - it expires after its parent, or states no expiry when its parent does.
 *   Each credential's own expiry is still checked on every use, so the child
 *   is honored only as long as its parent;
 * - it names an audience its parent does not, or none when its parent names
 *   one. Each credential's own audience is still checked, so the extra
 *   audience grants nothing;
 * - one of its scopes lies inside parent scopes that all carry per-scope
 *   `constraints`, and repeats none of those records. Constraint keys are
 *   opaque to the verifier, so only a key repeated with an equal value (RFC
 *   8785) is provably no wider. A parent's flat scope, or a CRISP scope with
 *   no `constraints`, covers a child scope without conditions.
 *
 * These are reported, not refused: `validateDelegationChain` returns them as
 * `warnings` on a chain that validates. Issuers can call this before minting
 * to see what a strict verifier would refuse. Pure. Never throws: a field it
 * cannot read yields no warning, so it cannot turn a chain that validates
 * into an error.
 */
export function attenuationWarnings(
  parentCredential: DelegationCredential,
  childCredential: DelegationCredential,
): string[] {
  const parentId = parentCredential?.credentialSubject?.delegation?.id;
  const childId = childCredential?.credentialSubject?.delegation?.id;
  const warnings = new Set<string>();

  const parentExpiry = statedExpiry(parentCredential);
  const childExpiry = statedExpiry(childCredential);
  if (parentExpiry !== undefined && childExpiry === undefined) {
    warnings.add(`Delegation ${childId} states no expiry but parent ${parentId} does`);
  } else if (parentExpiry !== undefined && childExpiry !== undefined && childExpiry > parentExpiry) {
    warnings.add(`Delegation ${childId} expires after parent ${parentId}`);
  }

  const parentAudience = statedAudience(parentCredential);
  const childAudience = statedAudience(childCredential);
  if (parentAudience !== undefined && childAudience === undefined) {
    warnings.add(`Delegation ${childId} names no audience but parent ${parentId} does`);
  } else if (parentAudience !== undefined && childAudience !== undefined) {
    const added = childAudience.filter((did) => !parentAudience.includes(did));
    if (added.length > 0) {
      warnings.add(`Delegation ${childId} names an audience parent ${parentId} does not: ${added.join(", ")}`);
    }
  }

  const parentAuthority = readableAuthority(parentCredential);
  for (const scope of readableAuthority(childCredential)) {
    const required = parentAuthority
      .filter((entry) => matcherContains(entry, scope))
      .map((entry) => constraintEntries(entry.constraints));
    // No covering parent scope is scope attenuation's to refuse, not this function's.
    if (required.length === 0) continue;
    const carried = new Map(constraintEntries(scope.constraints));
    // An unconstrained covering scope has no entries, so it is repeated vacuously.
    const repeatsOne = required.some((entries) =>
      entries.every(([key, value]) => carried.has(key) && sameCanonicalJson(carried.get(key), value)),
    );
    if (!repeatsOne) {
      warnings.add(
        `Delegation ${childId} scope ${scope.matcher}:${scope.resource} does not repeat the constraints parent ${parentId} places on it`,
      );
    }
  }

  return Array.from(warnings);
}
