import type { DelegationCredential, CrispScope } from '../types/protocol.js';

const MAX_REGEX_LEN = 256;
const MAX_VALUE_LEN = 256;

/**
 * Conservative detector for the classic catastrophic-backtracking shape — a
 * quantified group whose body also contains a quantifier, e.g. `(a+)+`, `(a*)*`,
 * `(.{1,9})+`. This is a heuristic reject, NOT a proof of safety.
 */
const NESTED_QUANTIFIER = /\([^()]*[+*?{][^()]*\)\s*[+*{]/;

export type ScopeMatcher = 'exact' | 'prefix' | 'regex';

/**
 * Match a single requested scope/resource value against a pattern by matcher kind.
 *
 * - `exact`  : strict string equality.
 * - `prefix` : value starts with the pattern (a single trailing `*` is optional sugar).
 *              An empty base ('' or lone '*') matches nothing — it will NOT grant
 *              universal scope.
 * - `regex`  : anchored full-string match; never throws (invalid patterns → false).
 *
 * SECURITY: the regex pattern is supplied by the credential ISSUER. JS `RegExp`
 * is not linear-time, so this guards against the common catastrophic-backtracking
 * shapes (nested quantifiers) and bounds input length — but it is a conservative
 * mitigation, not a guarantee. Deployments accepting `regex` matchers from
 * untrusted issuers should prefer `exact`/`prefix` or evaluate via a linear-time
 * engine (e.g. RE2).
 */
export function matchScope(pattern: string, matcher: ScopeMatcher, value: string): boolean {
  switch (matcher) {
    case 'exact':
      return pattern === value;
    case 'prefix': {
      const base = pattern.endsWith('*') ? pattern.slice(0, -1) : pattern;
      // Refuse to grant universal scope via an empty/`*`-only prefix.
      if (base.length === 0) return false;
      return value.startsWith(base);
    }
    case 'regex': {
      if (pattern.length > MAX_REGEX_LEN || value.length > MAX_VALUE_LEN) return false;
      if (NESTED_QUANTIFIER.test(pattern)) return false;
      try {
        return new RegExp(`^(?:${pattern})$`).test(value);
      } catch {
        return false;
      }
    }
    default:
      return false;
  }
}

/**
 * Flat exact-match scope set: delegation.scopes ∪ constraints.scopes.
 * Null-safe by design: scopeSatisfies is a public, never-throw predicate, so a
 * structurally malformed credential (missing constraints) yields an empty set
 * rather than a TypeError.
 */
function flatScopes(credential: DelegationCredential): string[] {
  const d = credential?.credentialSubject?.delegation;
  return [...(d?.scopes ?? []), ...(d?.constraints?.scopes ?? [])];
}

/** Opt-in CrispScope[] entries (constraints.crisp.scopes), if any. Null-safe. */
function crispScopes(credential: DelegationCredential): CrispScope[] {
  return credential?.credentialSubject?.delegation?.constraints?.crisp?.scopes ?? [];
}

export interface ScopeSatisfaction {
  satisfied: boolean;
  /**
   * True when satisfaction came via a non-exact (prefix|regex) CrispScope matcher.
   * Callers should surface a warning — non-exact matchers widen effective authority.
   */
  usedNonExactMatcher: boolean;
}

/**
 * Decide whether a required scope id is satisfied by a credential.
 *
 * Flat `scopes[]` are matched EXACTLY (backwards-compatible). The opt-in
 * `constraints.crisp.scopes[]` entries are honored per their declared matcher.
 */
export function scopeSatisfies(
  requiredScopeId: string,
  credential: DelegationCredential,
): ScopeSatisfaction {
  if (flatScopes(credential).includes(requiredScopeId)) {
    return { satisfied: true, usedNonExactMatcher: false };
  }
  for (const cs of crispScopes(credential)) {
    if (matchScope(cs.resource, cs.matcher, requiredScopeId)) {
      return { satisfied: true, usedNonExactMatcher: cs.matcher !== 'exact' };
    }
  }
  return { satisfied: false, usedNonExactMatcher: false };
}
