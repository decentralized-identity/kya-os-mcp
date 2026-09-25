import { describe, it, expect } from 'vitest';
import type { CrispScope } from '../../types/protocol.js';
import { matchScope, matcherContains, scopeSatisfies } from '../scope-matcher.js';

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

  it('path-prefix: matches the path itself and anything beneath it', () => {
    expect(matchScope('notes', 'path-prefix', 'notes')).toBe(true);
    expect(matchScope('notes', 'path-prefix', 'notes/plan.md')).toBe(true);
    expect(matchScope('notes', 'path-prefix', 'notes/2026/plan.md')).toBe(true);
    expect(matchScope('notes/', 'path-prefix', 'notes/plan.md')).toBe(true);
    expect(matchScope('notes/*', 'path-prefix', 'notes/plan.md')).toBe(true);
  });

  it('path-prefix: never escapes the directory boundary (unlike prefix)', () => {
    expect(matchScope('notes', 'path-prefix', 'notesx/secret.md')).toBe(false);
    expect(matchScope('notes', 'path-prefix', 'notes.md')).toBe(false);
    expect(matchScope('notes', 'prefix', 'notesx/secret.md')).toBe(true); // the contrast
  });

  it('path-prefix: refuses an empty / "*"-only / "/"-only base (no universal grant)', () => {
    expect(matchScope('', 'path-prefix', 'anything')).toBe(false);
    expect(matchScope('*', 'path-prefix', 'anything')).toBe(false);
    expect(matchScope('/', 'path-prefix', 'anything')).toBe(false);
    expect(matchScope('/*', 'path-prefix', 'anything')).toBe(false);
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

  it('honors crisp.scopes path-prefix matcher and flags non-exact use', () => {
    const vc = cred([], [{ resource: 'notes', matcher: 'path-prefix' }]);
    expect(scopeSatisfies('notes/plan.md', vc)).toEqual({ satisfied: true, usedNonExactMatcher: true });
    expect(scopeSatisfies('notesx/secret.md', vc).satisfied).toBe(false);
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

describe('matcherContains (attenuation across matcher kinds)', () => {
  const m = (matcher: CrispScope['matcher'], resource: string): CrispScope => ({ matcher, resource });

  it('proves identity for every kind, including regex', () => {
    for (const kind of ['exact', 'prefix', 'path-prefix', 'regex'] as const) {
      expect(matcherContains(m(kind, 'repo:(read)'), m(kind, 'repo:(read)'))).toBe(true);
    }
  });

  it('decides an exact scope by the runtime matcher itself', () => {
    expect(matcherContains(m('prefix', 'repo:'), m('exact', 'repo:read'))).toBe(true);
    expect(matcherContains(m('path-prefix', 'notes'), m('exact', 'notes/2026/plan.md'))).toBe(true);
    expect(matcherContains(m('regex', 'repo:(read|write)'), m('exact', 'repo:read'))).toBe(true);
    expect(matcherContains(m('prefix', 'safe:'), m('exact', 'admin:root'))).toBe(false);
  });

  it('proves a narrower prefix or path, never a wider one or one across the path boundary', () => {
    expect(matcherContains(m('prefix', 'repo:*'), m('prefix', 'repo:read'))).toBe(true);
    expect(matcherContains(m('path-prefix', 'notes/'), m('path-prefix', 'notes/2026'))).toBe(true);
    expect(matcherContains(m('prefix', 'notes'), m('path-prefix', 'notes/2026'))).toBe(true);
    expect(matcherContains(m('path-prefix', 'notes'), m('prefix', 'notes/'))).toBe(true);
    expect(matcherContains(m('prefix', 'repo:read'), m('prefix', 'repo:'))).toBe(false);
    expect(matcherContains(m('path-prefix', 'notes'), m('path-prefix', 'notesx'))).toBe(false);
    expect(matcherContains(m('path-prefix', 'notes'), m('prefix', 'notes'))).toBe(false);
  });

  it('never proves a regex, an empty base, or a pattern under an exact scope', () => {
    expect(matcherContains(m('regex', 'repo:(read|write)'), m('regex', 'repo:read'))).toBe(false);
    expect(matcherContains(m('prefix', 'repo:'), m('regex', 'repo:read'))).toBe(false);
    expect(matcherContains(m('prefix', 'repo:'), m('prefix', ''))).toBe(false);
    expect(matcherContains(m('prefix', '*'), m('prefix', 'repo:'))).toBe(false);
    expect(matcherContains(m('exact', 'repo:'), m('prefix', 'repo:'))).toBe(false);
  });

  it('is sound: whatever the inner matcher matches, the outer one matches too', () => {
    const pool = [
      m('exact', 'repo:read'), m('exact', 'notes'), m('prefix', 'repo:'), m('prefix', 'repo:read'),
      m('prefix', 're'), m('prefix', 'notes'), m('prefix', 'notes/'), m('prefix', ''), m('prefix', '*'),
      m('path-prefix', 'notes'), m('path-prefix', 'notes/2026'), m('path-prefix', 'notesx'),
      m('path-prefix', 'notes/*'), m('regex', 'repo:(read|write)'), m('regex', 'repo:read'),
    ];
    const values = ['repo:read', 'repo:write', 'repo:readme', 're', 'rex', 'notes', 'notes/', 'notes/2026',
      'notes/2026/plan.md', 'notesx/secret.md', 'admin:root', ''];
    let proven = 0;
    for (const outer of pool) {
      for (const inner of pool) {
        if (!matcherContains(outer, inner)) continue;
        proven += 1;
        for (const value of values) {
          if (matchScope(inner.resource, inner.matcher, value)) {
            expect(matchScope(outer.resource, outer.matcher, value), `${inner.matcher}:${inner.resource} ⊄ ${outer.matcher}:${outer.resource} at "${value}"`).toBe(true);
          }
        }
      }
    }
    expect(proven).toBeGreaterThan(pool.length); // identities plus real narrowings, not vacuous
  });
});
