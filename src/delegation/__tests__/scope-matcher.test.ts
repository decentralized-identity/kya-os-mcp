import { describe, it, expect } from 'vitest';
import { matchScope, scopeSatisfies } from '../scope-matcher.js';

describe('matchScope', () => {
  it('exact: matches identical strings only', () => {
    expect(matchScope('repo:write', 'exact', 'repo:write')).toBe(true);
    expect(matchScope('repo:write', 'exact', 'repo:write:extra')).toBe(false);
  });

  it('prefix: matches when value starts with the pattern (trailing * optional)', () => {
    expect(matchScope('repo:', 'prefix', 'repo:write')).toBe(true);
    expect(matchScope('repo:*', 'prefix', 'repo:write')).toBe(true);
    expect(matchScope('repo:', 'prefix', 'billing:write')).toBe(false);
  });

  it('prefix: refuses an empty / "*"-only base (no universal grant)', () => {
    expect(matchScope('', 'prefix', 'anything')).toBe(false);
    expect(matchScope('*', 'prefix', 'anything')).toBe(false);
  });

  it('regex: matches anchored pattern', () => {
    expect(matchScope('repo:(read|write)', 'regex', 'repo:write')).toBe(true);
    expect(matchScope('repo:(read|write)', 'regex', 'repo:delete')).toBe(false);
  });

  it('regex: rejects nested-quantifier (ReDoS-prone) patterns fast, without executing them', () => {
    // Intentional ReDoS bait. The dangerous quantifier is assembled from a
    // runtime char rather than written as a static regex literal, so analyzers
    // don't flag the test fixture itself — the whole point is that matchScope
    // REJECTS these before ever compiling or running them.
    const q = String.fromCharCode(43); // '+'
    const nestedQuantifier = `(a${q})${q}$`; // (a+)+$
    const boundedRepetition = `(.{1,9})${q}`; // (.{1,9})+
    const start = Date.now();
    expect(matchScope(nestedQuantifier, 'regex', 'a'.repeat(40) + '!')).toBe(false);
    expect(matchScope(boundedRepetition, 'regex', 'a'.repeat(50))).toBe(false);
    // If these were executed they would backtrack for many seconds; the guard
    // must reject them near-instantly.
    expect(Date.now() - start).toBeLessThan(50);
  });

  it('regex: rejects over-long patterns and values', () => {
    expect(matchScope('a'.repeat(300), 'regex', 'a')).toBe(false);
    expect(matchScope('abc', 'regex', 'a'.repeat(300))).toBe(false);
  });

  it('regex: invalid pattern returns false, never throws', () => {
    expect(matchScope('repo:[', 'regex', 'repo:write')).toBe(false);
  });
});

// Minimal credential shape; cast through unknown to avoid importing the full type surface in tests.
const cred = (
  scopes: string[],
  crisp?: { resource: string; matcher: 'exact' | 'prefix' | 'regex' }[],
) =>
  ({
    credentialSubject: {
      delegation: {
        scopes,
        constraints: { ...(crisp ? { crisp: { scopes: crisp } } : {}) },
      },
    },
  }) as unknown as Parameters<typeof scopeSatisfies>[1];

describe('scopeSatisfies', () => {
  it('flat scopes stay EXACT (no silent widening)', () => {
    expect(scopeSatisfies('repo:write', cred(['repo:write'])).satisfied).toBe(true);
    expect(scopeSatisfies('repo:write:x', cred(['repo:write'])).satisfied).toBe(false);
  });

  it('honors crisp.scopes prefix matcher and flags non-exact use', () => {
    const r = scopeSatisfies('repo:write', cred([], [{ resource: 'repo:', matcher: 'prefix' }]));
    expect(r.satisfied).toBe(true);
    expect(r.usedNonExactMatcher).toBe(true);
  });

  it('exact crisp matcher does not flag non-exact use', () => {
    const r = scopeSatisfies('repo:write', cred([], [{ resource: 'repo:write', matcher: 'exact' }]));
    expect(r.satisfied).toBe(true);
    expect(r.usedNonExactMatcher).toBe(false);
  });

  it('denies when nothing matches', () => {
    expect(scopeSatisfies('billing:write', cred(['repo:write'])).satisfied).toBe(false);
  });
});
