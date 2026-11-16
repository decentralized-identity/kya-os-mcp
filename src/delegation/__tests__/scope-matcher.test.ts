import { describe, it, expect } from 'vitest';
import type { CrispScope } from '../../types/protocol.js';
import { authorityContains, matchScope, matcherContains, scopeSatisfies } from '../scope-matcher.js';

/** A percent-encoded `/` and `\`, in each case a path can spell them. */
const ENCODED_SEPARATORS = ['%2f', '%2F', '%5c', '%5C'];

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

  it('path-prefix: a dot segment in the value never matches, however it is spelled', () => {
    for (const value of [
      'notes/../secrets/x.md',
      'notes/..',
      'notes/a/../../secrets/x.md',
      'notes/./plan.md',
      'notes/a\\..\\..\\secrets\\x.md',
      'notes\\..\\secrets',
    ]) {
      expect(matchScope('notes', 'path-prefix', value)).toBe(false);
      expect(matchScope('notes/', 'path-prefix', value)).toBe(false);
    }
  });

  it('path-prefix: a percent-encoded dot segment in the value is the dot segment it encodes', () => {
    for (const value of [
      'notes/%2e%2e/a',
      'notes/%2E%2E/a',
      'notes/%2e%2E/a',
      'notes/%2e/a',
      'notes/%2E/a',
      'notes/.%2e/a',
      'notes/%2e./a',
      'notes/%2e%2e',
      'notes/a\\%2e%2e\\b',
    ]) {
      expect(matchScope('notes', 'path-prefix', value)).toBe(false);
      expect(matchScope('notes/', 'path-prefix', value)).toBe(false);
    }
  });

  it('path-prefix: an encoded dot inside a name is not a dot segment, and nothing else is decoded', () => {
    for (const value of ['notes/%2ea/b', 'notes/a%2e/b', 'notes/%2e%2e%2e/b', 'notes/...%2e/b', 'notes/%252e%252e/b']) {
      expect(matchScope('notes', 'path-prefix', value)).toBe(true);
    }
  });

  it('path-prefix: an encoded separator beside a dot segment never matches', () => {
    for (const value of ['notes/..%2fsecrets/x.md', 'notes/%2e%2e%2fsecrets/x.md', 'notes/..%5csecrets/x.md']) {
      expect(matchScope('notes', 'path-prefix', value), value).toBe(false);
      expect(matchScope('notes/', 'path-prefix', value), value).toBe(false);
    }
  });

  it.each(ENCODED_SEPARATORS)('path-prefix: a value with %s never matches, dot segment or not', (escape) => {
    for (const value of [`notes/a${escape}b.md`, `notes/${escape}/b`, `notes/2026/plan.md${escape}`, `notes/%2e${escape}/b`, `notes/%${escape}`]) {
      expect(matchScope('notes', 'path-prefix', value), value).toBe(false);
    }
  });

  it.each(ENCODED_SEPARATORS)('path-prefix: a pattern with %s grants nothing', (escape) => {
    for (const pattern of [`notes${escape}2026`, `${escape}notes`, `notes/a${escape}`]) {
      for (const value of [pattern, `${pattern}/plan.md`, 'notes', 'notes/2026/plan.md']) {
        expect(matchScope(pattern, 'path-prefix', value), `${pattern} for ${value}`).toBe(false);
        expect(matchScope(`${pattern}/*`, 'path-prefix', value), `${pattern}/* for ${value}`).toBe(false);
      }
    }
  });

  it('path-prefix: a percent sign that is not an encoded separator is the text it is', () => {
    for (const value of [
      'notes/a%20b.md', 'notes/a%2eb.md', 'notes/100%.md', 'notes/a%2', 'notes/a%5', 'notes/a%2/f', 'notes/a%5/c',
      'notes/a%2g', 'notes/a%5d', 'notes/a%2 f', 'notes/a2fb5c',
    ]) {
      expect(matchScope('notes', 'path-prefix', value), value).toBe(true);
    }
    expect(matchScope('notes/100%', 'path-prefix', 'notes/100%/a%2e.md')).toBe(true);
  });

  it('path-prefix: a doubly encoded separator is text to a consumer that decodes once, and matches', () => {
    for (const value of ['notes/a%252fb.md', 'notes/a%255Cb.md', 'notes/..%252fsecrets/x.md']) {
      expect(decodeURIComponent(value)).toMatch(/%(2f|5c)/i);
      expect(matchScope('notes', 'path-prefix', value), value).toBe(true);
    }
    expect(matchScope('notes%252fa', 'path-prefix', 'notes%252fa/b')).toBe(true);
  });

  it.each(ENCODED_SEPARATORS)('exact, prefix and regex compare %s as the text it is', (escape) => {
    const value = `notes/..${escape}secrets/x.md`;
    expect(matchScope(value, 'exact', value)).toBe(true);
    expect(matchScope('notes/', 'prefix', value)).toBe(true);
    expect(matchScope(`notes/..${escape}`, 'prefix', value)).toBe(true);
    expect(matchScope(`notes/\\.\\.${escape}.*`, 'regex', value)).toBe(true);
    expect(matchScope('notes/.*', 'regex', value)).toBe(true);
  });

  it('path-prefix: a pattern with a percent-encoded dot segment grants nothing', () => {
    expect(matchScope('notes/%2e%2e', 'path-prefix', 'notes/%2e%2e')).toBe(false);
    expect(matchScope('notes/%2e%2e', 'path-prefix', 'notes/%2e%2e/x.md')).toBe(false);
    expect(matchScope('notes/%2E/secrets', 'path-prefix', 'notes/%2E/secrets/x.md')).toBe(false);
    expect(matchScope('%2e/notes', 'path-prefix', '%2e/notes/x.md')).toBe(false);
    // The other matchers compare the text as written.
    expect(matchScope('notes/%2e%2e', 'exact', 'notes/%2e%2e')).toBe(true);
    expect(matchScope('notes/', 'prefix', 'notes/%2e%2e/a')).toBe(true);
    expect(matchScope('notes/%2e%2e/.*', 'regex', 'notes/%2e%2e/a')).toBe(true);
  });

  it('path-prefix: dots inside a name are not dot segments', () => {
    expect(matchScope('notes', 'path-prefix', 'notes/..hidden')).toBe(true);
    expect(matchScope('notes', 'path-prefix', 'notes/v1.2/plan.md')).toBe(true);
    expect(matchScope('notes', 'path-prefix', 'notes/.env')).toBe(true);
  });

  it('path-prefix: a pattern with a dot segment grants nothing', () => {
    expect(matchScope('notes/..', 'path-prefix', 'notes/../secrets')).toBe(false);
    expect(matchScope('notes/../secrets', 'path-prefix', 'notes/../secrets/x.md')).toBe(false);
    expect(matchScope('./notes', 'path-prefix', './notes/x.md')).toBe(false);
  });

  it('prefix: stays character-level, for identifiers (the contrast)', () => {
    expect(matchScope('notes/', 'prefix', 'notes/../secrets/x.md')).toBe(true);
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

  it('never proves a prefix inside a path-prefix, which refuses values the prefix matches', () => {
    // A path-prefix matches no value with a dot segment; a prefix matches any value that starts
    // with its base. So the prefix grants `notes/../admin`, which its would-be parent does not.
    const [parent, child] = [m('path-prefix', 'notes'), m('prefix', 'notes/')];
    const value = 'notes/../admin';
    expect([matchScope(child.resource, child.matcher, value), matchScope(parent.resource, parent.matcher, value)]).toEqual([true, false]);
    expect(matcherContains(parent, child)).toBe(false);
    expect(matcherContains(m('path-prefix', 'notes/'), m('prefix', 'notes/2026/'))).toBe(false);
    // The same authority written as a path-prefix is still proven inside its parent.
    expect(matcherContains(parent, m('path-prefix', 'notes/2026'))).toBe(true);
  });

  it('never proves containment through a path-prefix with a dot segment', () => {
    expect(matcherContains(m('path-prefix', 'notes'), m('path-prefix', 'notes/../secrets'))).toBe(false);
    expect(matcherContains(m('path-prefix', 'notes/..'), m('path-prefix', 'notes/../x'))).toBe(false);
    expect(matcherContains(m('path-prefix', 'notes'), m('exact', 'notes/../secrets/x.md'))).toBe(false);
    expect(matcherContains(m('prefix', 'notes'), m('path-prefix', 'notes/../secrets'))).toBe(false);
  });

  it('never proves containment through a path-prefix with a percent-encoded dot segment', () => {
    expect(matcherContains(m('path-prefix', 'notes'), m('path-prefix', 'notes/%2e%2e/secrets'))).toBe(false);
    expect(matcherContains(m('path-prefix', 'notes/%2E%2E'), m('path-prefix', 'notes/%2E%2E/x'))).toBe(false);
    expect(matcherContains(m('path-prefix', 'notes'), m('exact', 'notes/%2e%2e/secrets/x.md'))).toBe(false);
    expect(matcherContains(m('prefix', 'notes'), m('path-prefix', 'notes/.%2e/secrets'))).toBe(false);
    // An encoded dot inside a name leaves the pattern an ordinary one.
    expect(matcherContains(m('path-prefix', 'notes'), m('path-prefix', 'notes/%2ea'))).toBe(true);
  });

  it.each(ENCODED_SEPARATORS)('never proves a path-prefix with %s inside anything but itself', (escape) => {
    for (const resource of [`notes/a${escape}b`, `notes/..${escape}secrets`, `notes${escape}a`, `notes/a${escape}/*`]) {
      const inner = m('path-prefix', resource);
      expect(matcherContains(m('path-prefix', 'notes'), inner), resource).toBe(false);
      expect(matcherContains(m('prefix', 'notes'), inner), resource).toBe(false);
      expect(matcherContains(m('path-prefix', resource), m('path-prefix', `${resource}/x`)), resource).toBe(false);
    }
    // The same entry is the same authority, which is none.
    expect(matcherContains(m('path-prefix', `notes${escape}a`), m('path-prefix', `notes${escape}a`))).toBe(true);
  });

  it.each(ENCODED_SEPARATORS)('never proves anything inside a path-prefix with %s', (escape) => {
    const outer = m('path-prefix', `notes${escape}a`);
    for (const inner of [
      m('path-prefix', `notes${escape}a/2026`), m('path-prefix', `notes${escape}a/`), m('exact', `notes${escape}a`),
      m('exact', `notes${escape}a/plan.md`), m('prefix', `notes${escape}a/`), m('path-prefix', 'notes'),
    ]) {
      expect(matcherContains(outer, inner), `${inner.matcher}:${inner.resource}`).toBe(false);
    }
    expect(matcherContains(m('path-prefix', 'notes'), m('exact', `notes/a${escape}b.md`))).toBe(false);
  });

  it('proves containment as before for a prefix or an exact scope with an encoded separator, and for its neighbours', () => {
    expect(matcherContains(m('prefix', 'notes%2f'), m('prefix', 'notes%2fa'))).toBe(true);
    expect(matcherContains(m('prefix', 'notes%5C'), m('exact', 'notes%5Ca'))).toBe(true);
    expect(matcherContains(m('regex', 'notes%2f.*'), m('exact', 'notes%2fa'))).toBe(true);
    for (const resource of ['notes/a%20b', 'notes/a%2eb', 'notes/100%', 'notes/a%2', 'notes/a%5', 'notes/a%252fb']) {
      expect(matcherContains(m('path-prefix', 'notes'), m('path-prefix', resource)), resource).toBe(true);
      expect(matcherContains(m('path-prefix', resource), m('path-prefix', `${resource}/x`)), resource).toBe(true);
    }
  });

  const pool = [
    m('exact', 'repo:read'), m('exact', 'notes'), m('prefix', 'repo:'), m('prefix', 'repo:read'),
    m('prefix', 're'), m('prefix', 'notes'), m('prefix', 'notes/'), m('prefix', ''), m('prefix', '*'),
    m('path-prefix', 'notes'), m('path-prefix', 'notes/2026'), m('path-prefix', 'notesx'),
    m('path-prefix', 'notes/*'), m('regex', 'repo:(read|write)'), m('regex', 'repo:read'),
  ];
  const values = ['repo:read', 'repo:write', 'repo:readme', 're', 'rex', 'notes', 'notes/', 'notes/2026',
    'notes/2026/plan.md', 'notesx/secret.md', 'admin:root', ''];
  /** Entries a credential can carry that are not scopes. */
  const malformed = [
    { matcher: 'prefix', resource: 42 }, { matcher: 'regex', resource: null }, { matcher: 'prefix' },
    { resource: 'repo:' }, null,
  ] as unknown as CrispScope[];

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
    expect(matcherContains(m('path-prefix', 'notes/'), m('path-prefix', 'notes'))).toBe(true);
    expect(matcherContains(m('prefix', 'notes'), m('path-prefix', 'notes/2026'))).toBe(true);
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

  it('proves nothing from or about a malformed entry, and never throws', () => {
    for (const bad of malformed) {
      expect(matcherContains(bad, bad)).toBe(false);
      for (const scope of pool) {
        expect(matcherContains(bad, scope)).toBe(false);
        expect(matcherContains(scope, bad)).toBe(false);
      }
    }
  });

  it('authorityContains agrees with matcherContains over every entry of the authority', () => {
    const authorities = [[], ...pool.map((scope) => [scope]), pool, malformed, [...malformed, m('prefix', 'repo:')]];
    for (const authority of authorities) {
      const contains = authorityContains(authority);
      for (const inner of [...pool, ...malformed]) {
        expect(contains(inner), JSON.stringify({ authority, inner })).toBe(authority.some((entry) => matcherContains(entry, inner)));
      }
    }
  });
});
