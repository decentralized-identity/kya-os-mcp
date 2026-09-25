import type { DelegationCredential, CrispScope } from '../types/protocol.js';

const MAX_REGEX_LEN = 256;
const MAX_VALUE_LEN = 256;

/**
 * Conservative detector for the classic catastrophic-backtracking shape — a
 * quantified group whose body also contains a quantifier, e.g. `(a+)+`, `(a*)*`,
 * `(.{1,9})+`. This is a heuristic reject, NOT a proof of safety.
 */
const NESTED_QUANTIFIER = /\([^()]*[+*?{][^()]*\)\s*[+*{]/;

export type ScopeMatcher = 'exact' | 'prefix' | 'path-prefix' | 'regex';

/** A `prefix` pattern's base: one trailing `*` is optional sugar. */
function prefixBase(pattern: string): string {
  return pattern.endsWith('*') ? pattern.slice(0, -1) : pattern;
}

/** A `path-prefix` pattern's base: a trailing `*` and trailing `/`s are optional sugar. */
function pathBase(pattern: string): string {
  let base = prefixBase(pattern);
  while (base.endsWith('/')) base = base.slice(0, -1);
  return base;
}

/**
 * Match a single requested scope/resource value against a pattern by matcher kind.
 *
 * - `exact`  : strict string equality.
 * - `prefix` : value starts with the pattern (a single trailing `*` is optional sugar).
 *              An empty base ('' or lone '*') matches nothing — it will NOT grant
 *              universal scope. Character-level: `notes` matches `notesx/secret.md`.
 *              Use it for scope ids, where the value is an identifier, not a path.
 * - `path-prefix` : the value IS the pattern, or lies under it as a `/`-separated
 *              path (`notes` matches `notes` and `notes/a/b.md`, never
 *              `notesx/secret.md`). Trailing `/` or `/*` on the pattern is optional
 *              sugar; an empty base matches nothing. Use it for resource paths.
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
      const base = prefixBase(pattern);
      // Refuse to grant universal scope via an empty/`*`-only prefix.
      if (base.length === 0) return false;
      return value.startsWith(base);
    }
    case 'path-prefix': {
      const base = pathBase(pattern);
      // Refuse to grant universal scope via an empty/`*`-only prefix.
      if (base.length === 0) return false;
      return value === base || value.startsWith(`${base}/`);
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
export function crispScopes(credential: DelegationCredential): CrispScope[] {
  return credential?.credentialSubject?.delegation?.constraints?.crisp?.scopes ?? [];
}

/**
 * A credential's whole scope authority in one typed form: its flat scopes as
 * `exact` matchers, then its CRISP matchers (SPEC.md §6.3). A value is granted
 * exactly when one of these matches it, which is what {@link scopeSatisfies}
 * decides. Null-safe.
 */
export function scopeAuthority(credential: DelegationCredential): CrispScope[] {
  return [
    ...flatScopes(credential).map((resource): CrispScope => ({ resource, matcher: 'exact' })),
    ...crispScopes(credential),
  ];
}

/**
 * Sound containment rules for pattern matchers, keyed `<inner>:<outer>` and
 * applied to non-empty bases: each holds only when every value the inner
 * pattern matches, the outer one matches too.
 */
const CONTAINMENT: ReadonlyMap<string, (inner: string, outer: string) => boolean> = new Map([
  ['prefix:prefix', (inner: string, outer: string) => inner.startsWith(outer)],
  ['path-prefix:path-prefix', (inner: string, outer: string) => inner === outer || inner.startsWith(`${outer}/`)],
  ['path-prefix:prefix', (inner: string, outer: string) => inner.startsWith(outer)],
  ['prefix:path-prefix', (inner: string, outer: string) => inner.startsWith(`${outer}/`)],
]);

const baseOf = (scope: CrispScope): string =>
  scope.matcher === 'path-prefix' ? pathBase(scope.resource) : prefixBase(scope.resource);

/** Credentials are untrusted input: an entry without a string resource and matcher is not a scope. */
function isCrispScope(scope: unknown): scope is CrispScope {
  const entry = scope as Partial<CrispScope> | null | undefined;
  return typeof entry?.resource === 'string' && typeof entry.matcher === 'string';
}

const scopeKey = (scope: CrispScope): string => `${scope.matcher}\u0000${scope.resource}`;

/**
 * Whether `outer` grants every value `inner` grants, proven by a sound rule and
 * never by sampling. An `exact` inner is decided by {@link matchScope} itself.
 * Only an identical pattern contains a `regex`, and an empty base or a
 * malformed entry proves nothing, so an unprovable case is `false` and
 * attenuation fails closed. Never throws.
 */
export function matcherContains(outer: CrispScope, inner: CrispScope): boolean {
  if (!isCrispScope(outer) || !isCrispScope(inner)) return false;
  if (outer.matcher === inner.matcher && outer.resource === inner.resource) return true;
  if (inner.matcher === 'exact') return matchScope(outer.resource, outer.matcher, inner.resource);
  const rule = CONTAINMENT.get(`${inner.matcher}:${outer.matcher}`);
  const [innerBase, outerBase] = [baseOf(inner), baseOf(outer)];
  return rule !== undefined && innerBase.length > 0 && outerBase.length > 0 && rule(innerBase, outerBase);
}

/**
 * Whether some entry of `authority` contains `scope` ({@link matcherContains}),
 * built once per authority so a check stays linear in the common cases: an
 * identical entry is found in a set, and only pattern entries are searched,
 * because an `exact` entry contains nothing but itself.
 */
export function authorityContains(authority: readonly CrispScope[]): (scope: CrispScope) => boolean {
  const granted = authority.filter(isCrispScope);
  const identical = new Set(granted.map(scopeKey));
  const patterns = granted.filter((entry) => entry.matcher !== 'exact');
  return (scope) =>
    isCrispScope(scope) &&
    (identical.has(scopeKey(scope)) || patterns.some((entry) => matcherContains(entry, scope)));
}

export interface ScopeSatisfaction {
  satisfied: boolean;
  /**
   * True when satisfaction came via a non-exact (prefix|path-prefix|regex) CrispScope matcher.
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
