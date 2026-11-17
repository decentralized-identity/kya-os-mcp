/**
 * The DID rule of `utils/did-syntax.ts`: the pattern a JSON Schema publishes for a DID member, and
 * the reason a value breaks it. The Card's members are held to it through their schemas in
 * `card/__tests__/card-did-syntax.test.ts`; these are the values the rule is given.
 */

import { describe, expect, it } from 'vitest';
import { didPattern, isDid, whyNotDid } from '../did-syntax.js';

/** The methods a Card takes, and the same with did:webvh beside them. */
const KEY_WEB = ['key', 'web'] as const;
const KEY_WEB_WEBVH = ['key', 'web', 'webvh'] as const;

/** The method-specific id, as each published pattern ends. */
const ID = ':(?:(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})*:)*(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+$';

/** Every DID value a Card member may be given, and what it gives under did:key and did:web: `undefined` for a DID, else the reason. */
const TABLE: ReadonlyArray<readonly [string, string | undefined]> = [
  ['did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', undefined],
  ['did:web:example.com', undefined],
  ['did:web:example.com:agents:pay-1', undefined],
  ['did:web:localhost%3A8443', undefined],
  ['did:web:example.com#key-1', 'is a DID URL: drop the "#key-1" fragment'],
  ['did:web:example.com?v=1', 'is a DID URL: drop the "?v=1" query'],
  ['did:web:example.com/agents', 'is a DID URL: drop the "/agents" path'],
  ['did:web:has space', 'contains a space'],
  ['did:web:exämple.com', 'contains "ä", which a DID writes percent-encoded'],
  ['did:web:example.com:', 'ends with ":", so its last part is empty'],
  ['did:web:', 'has no method-specific id'],
  ['did:ion:abc', 'uses "did:ion", not did:key or did:web'],
  [
    'did:webvh:QmWboSTA2BJ9CJEXqS881Q6nxSmjEksR5MUorrTfzRcUtD:example.com:e:1',
    'uses "did:webvh", not did:key or did:web',
  ],
  ['DID:web:example.com', 'starts with "DID:"; the scheme is written in lower case: "did:"'],
  ['did:web:ex%2', 'has a "%" not followed by two hex digits'],
];

/** The rows refused only for their method, which are DIDs of some method all the same. */
const OTHER_METHOD = new Set(['did:ion:abc', 'did:webvh:QmWboSTA2BJ9CJEXqS881Q6nxSmjEksR5MUorrTfzRcUtD:example.com:e:1']);

describe('the DID rule, on the values a Card member is given', () => {
  it.each(TABLE)('%s', (value, reason) => {
    expect(whyNotDid(value, KEY_WEB)).toBe(reason);
    expect(didPattern(KEY_WEB).test(value)).toBe(reason === undefined);
    expect(isDid(value)).toBe(reason === undefined || OTHER_METHOD.has(value));
  });
});

describe('didPattern', () => {
  it('is the pattern the Card schema publishes, with the methods in the order given', () => {
    expect(didPattern(KEY_WEB).source).toBe(
      '^did:(?:key|web):(?:(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})*:)*(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+$',
    );
    expect(didPattern(KEY_WEB_WEBVH).source).toBe(`^did:(?:key|web|webvh)${ID}`);
    expect(didPattern(['web', 'key']).source).toBe(`^did:(?:web|key)${ID}`);
    expect(didPattern(['key']).source).toBe(`^did:(?:key)${ID}`);
  });

  it('takes any method when none is named', () => {
    expect(didPattern().source).toBe(`^did:[a-z0-9]+${ID}`);
    expect(didPattern([]).source).toBe(`^did:[a-z0-9]+${ID}`);
    expect(didPattern().test('did:ion:abc')).toBe(true);
    expect(didPattern().test('did:example:123456789abcdefghi')).toBe(true);
  });

  it('has no flags, so it tests a value the same way each time', () => {
    const pattern = didPattern(KEY_WEB);
    expect(pattern.flags).toBe('');
    expect([pattern.test('did:web:example.com'), pattern.test('did:web:example.com')]).toEqual([true, true]);
  });

  it('throws a TypeError for a name that is not a DID method name', () => {
    for (const method of ['WEB', 'Web', '', 'we b', 'web:', 'did:web', 'wéb', 'web\n']) {
      expect(() => didPattern([method]), method).toThrow(TypeError);
      expect(() => whyNotDid('did:web:example.com', [method]), method).toThrow(TypeError);
    }
    expect(() => didPattern(['key', 42 as unknown as string])).toThrow(TypeError);
  });
});

describe('isDid', () => {
  it('tests a value against the rule for any method', () => {
    expect(isDid('did:example:123')).toBe(true);
    expect(isDid('did:web:example.com::x')).toBe(true);
    expect(isDid('did:web:example.com#key-1')).toBe(false);
    expect(isDid('DID:web:example.com')).toBe(false);
    expect(isDid('did:WEB:example.com')).toBe(false);
    expect(isDid('did:web:example.com\n')).toBe(false);
  });

  it('is false for a value that is not a string', () => {
    for (const value of [undefined, null, 42, true, ['did:web:example.com'], { id: 'did:web:example.com' }]) {
      expect(isDid(value)).toBe(false);
    }
  });
});

describe('whyNotDid', () => {
  it('names the type of a value that is not a string', () => {
    expect(whyNotDid(42)).toBe('is of type number, not a string');
    expect(whyNotDid(null, KEY_WEB)).toBe('is of type null, not a string');
    expect(whyNotDid(undefined)).toBe('is of type undefined, not a string');
    expect(whyNotDid(['did:web:example.com'])).toBe('is of type array, not a string');
    expect(whyNotDid({ id: 'did:web:example.com' })).toBe('is of type object, not a string');
  });

  it('says a value is empty', () => {
    expect(whyNotDid('', KEY_WEB)).toBe('is empty');
  });

  it('says the scheme is written in lower case when it is written in another', () => {
    expect(whyNotDid('Did:web:example.com')).toBe('starts with "Did:"; the scheme is written in lower case: "did:"');
    expect(whyNotDid('dID:')).toBe('starts with "dID:"; the scheme is written in lower case: "did:"');
  });

  it('says a value that does not start with the scheme does not', () => {
    for (const value of ['did', 'di', 'web:example.com', ' did:web:example.com', 'did;web:example.com', 'dıd:web:x']) {
      expect(whyNotDid(value, KEY_WEB), value).toBe('does not start with "did:"');
    }
  });

  it('says a DID has no method-specific id before it judges the method', () => {
    for (const value of ['did:', 'did:web', 'did:web:', 'did::', 'did:WEB', 'did:has space']) {
      expect(whyNotDid(value, KEY_WEB), value).toBe('has no method-specific id');
    }
  });

  it('says a DID has no method name, or one of other characters than lower-case letters and digits', () => {
    expect(whyNotDid('did::example.com')).toBe('has no method name');
    expect(whyNotDid('did:WEB:example.com', KEY_WEB)).toBe(
      'has the method name "WEB", which may hold only lower-case letters and digits',
    );
    expect(whyNotDid('did:w_b:example.com')).toBe('has the method name "w_b", which may hold only lower-case letters and digits');
    expect(whyNotDid('did:we b:example.com')).toBe('has the method name "we b", which may hold only lower-case letters and digits');
    expect(whyNotDid('did:w​b:x')).toBe('has the method name "w\\u200bb", which may hold only lower-case letters and digits');
  });

  it('lists the methods it takes, in the order given, when a DID uses another', () => {
    expect(whyNotDid('did:ion:abc', ['key'])).toBe('uses "did:ion", not did:key');
    expect(whyNotDid('did:ion:abc', ['web', 'key'])).toBe('uses "did:ion", not did:web or did:key');
    expect(whyNotDid('did:ion:abc', KEY_WEB_WEBVH)).toBe('uses "did:ion", not did:key, did:web or did:webvh');
    expect(whyNotDid('did:webvh:QmWboSTA2BJ9CJEXqS881Q6nxSmjEksR5MUorrTfzRcUtD:example.com', KEY_WEB_WEBVH)).toBeUndefined();
    expect(whyNotDid('did:ion:abc')).toBeUndefined();
    expect(whyNotDid('did:ion:abc', [])).toBeUndefined();
  });

  it('names the first character of the method-specific id that a DID does not hold as it stands', () => {
    expect(whyNotDid('did:web:a b#c', KEY_WEB)).toBe('contains a space');
    expect(whyNotDid('did:web:a#b c', KEY_WEB)).toBe('is a DID URL: drop the "#b c" fragment');
    expect(whyNotDid('did:web:ä/x', KEY_WEB)).toBe('contains "ä", which a DID writes percent-encoded');
    expect(whyNotDid('did:web:x%/a', KEY_WEB)).toBe('has a "%" not followed by two hex digits');
    expect(whyNotDid('did:web:x/a%', KEY_WEB)).toBe('is a DID URL: drop the "/a%" path');
  });

  it('quotes a query up to its fragment, and a path up to its query or fragment', () => {
    expect(whyNotDid('did:web:example.com?a=1#f', KEY_WEB)).toBe('is a DID URL: drop the "?a=1" query');
    expect(whyNotDid('did:web:example.com/a/b?q#f', KEY_WEB)).toBe('is a DID URL: drop the "/a/b" path');
    expect(whyNotDid('did:web:example.com/a#f', KEY_WEB)).toBe('is a DID URL: drop the "/a" path');
    expect(whyNotDid('did:web:example.com#a?b/c', KEY_WEB)).toBe('is a DID URL: drop the "#a?b/c" fragment');
    expect(whyNotDid('did:web:example.com/', KEY_WEB)).toBe('is a DID URL: drop the "/" path');
    expect(whyNotDid('did:web:example.com#', KEY_WEB)).toBe('is a DID URL: drop the "#" fragment');
  });

  it('takes a percent-encoded octet with hex digits of either case, and refuses a "%" without two', () => {
    for (const value of ['did:web:example.com%3a8443', 'did:web:%2F', 'did:web:a%41%4a%4A']) {
      expect(whyNotDid(value, KEY_WEB), value).toBeUndefined();
    }
    for (const value of ['did:web:x%', 'did:web:x%4', 'did:web:x%G1', 'did:web:x%%41', 'did:web:x%4:']) {
      expect(whyNotDid(value, KEY_WEB), value).toBe('has a "%" not followed by two hex digits');
    }
  });

  it('quotes any other character escaped, a character outside the Basic Multilingual Plane whole', () => {
    expect(whyNotDid('did:web:a\tb')).toBe('contains "\\t", which a DID writes percent-encoded');
    expect(whyNotDid('did:web:example.com\n')).toBe('contains "\\n", which a DID writes percent-encoded');
    expect(whyNotDid('did:web:a​b')).toBe('contains "\\u200b", which a DID writes percent-encoded');
    expect(whyNotDid('did:web:a\u{1F600}')).toBe('contains "\u{1F600}", which a DID writes percent-encoded');
    expect(whyNotDid('did:web:a\uD800b')).toBe('contains "\\ud800", which a DID writes percent-encoded');
    expect(whyNotDid('did:web:a"b')).toBe('contains "\\"", which a DID writes percent-encoded');
    expect(whyNotDid('did:web:a+b')).toBe('contains "+", which a DID writes percent-encoded');
  });

  it('refuses an empty last segment and takes an empty one before it', () => {
    expect(whyNotDid('did:web::', KEY_WEB)).toBe('ends with ":", so its last part is empty');
    expect(whyNotDid('did:web:example.com:agents:', KEY_WEB)).toBe('ends with ":", so its last part is empty');
    expect(whyNotDid('did:web:example.com::x', KEY_WEB)).toBeUndefined();
    expect(whyNotDid('did:web::example.com', KEY_WEB)).toBeUndefined();
  });

  it('quotes at most the first 64 characters of what it names', () => {
    const fragment = `#${'f'.repeat(100)}`;
    expect(whyNotDid(`did:web:example.com${fragment}`, KEY_WEB)).toBe(
      `is a DID URL: drop the "${fragment.slice(0, 64)}"... fragment`,
    );
    const method = 'm'.repeat(100);
    expect(whyNotDid(`did:${method}:x`, KEY_WEB)).toBe(`uses "did:${method.slice(0, 60)}"..., not did:key or did:web`);
  });
});

describe('a value of a million characters', () => {
  const MILLION = 1_000_000;

  it('is refused within the test timeout, with a short reason', () => {
    const nearMisses: ReadonlyArray<readonly [string, string, boolean]> = [
      [`did:web:${'a'.repeat(MILLION)}#`, 'is a DID URL: drop the "#" fragment', false],
      [`did:web:${'a:'.repeat(MILLION / 2)}`, 'ends with ":", so its last part is empty', false],
      [`did:web:${':'.repeat(MILLION)}`, 'ends with ":", so its last part is empty', false],
      [`did:web:${'%41'.repeat(MILLION / 4)}%4`, 'has a "%" not followed by two hex digits', false],
      [`did:web:${'a.'.repeat(MILLION / 2)} `, 'contains a space', false],
      [`did:${'a'.repeat(MILLION)}:x`, `uses "did:${'a'.repeat(60)}"..., not did:key or did:web`, true],
    ];
    for (const [value, reason, anyMethod] of nearMisses) {
      expect(didPattern(KEY_WEB).test(value)).toBe(false);
      expect(isDid(value)).toBe(anyMethod);
      expect(whyNotDid(value, KEY_WEB)).toBe(reason);
    }
  });

  it('is accepted within the test timeout when it is a DID', () => {
    const value = `did:web:${'a:'.repeat(MILLION / 2)}a`;
    expect(didPattern(KEY_WEB).test(value)).toBe(true);
    expect(isDid(value)).toBe(true);
    expect(whyNotDid(value, KEY_WEB)).toBeUndefined();
  });
});

/** Deterministic PRNG (mulberry32), as `canonical-json.test.ts` uses, so a failing case reproduces. */
function prng(seed: number): () => number {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** The start of a DID of a method one of the lists takes, which three values in five start with. */
const DID_STARTS = ['did:key:', 'did:web:', 'did:webvh:'];

/** Starts that stop at each earlier check. */
const OTHER_STARTS = ['', 'd', 'did', 'did:', 'did::', 'DID:web:', 'did:ion:', 'did:WEB:', 'did:we'];

/**
 * The characters a method name or method-specific id holds as it stands: the letters of the methods,
 * upper case, digits, hex digits, `.-_`, and `%` and `:` twice and four times over, so that values
 * often hold a percent-encoded octet and end with an empty part.
 */
const ID_CHARACTERS = [...'dikeywbvh', ...'ABCDEFGHIJKLMNOPQRSTUVWXYZ', ...'0123456789', ...'acf', ...'.-_', ...'%%', ...'::::'];

/** The characters a DID does not hold as they stand: those of a DID URL, white space, and characters a DID writes percent-encoded, one outside the Basic Multilingual Plane and a lone surrogate among them. */
const OTHER_CHARACTERS = [...'#?/ ', 'ä', '\t', '\u{1F600}', '\uD800'];

/** One of `choices`, at random. */
function pick<T>(rand: () => number, choices: readonly T[]): T {
  return choices[Math.floor(rand() * choices.length)]!;
}

/** A value made of a start and up to 15 characters, nine in ten of them ones a DID holds. */
function fuzzed(rand: () => number): string {
  let value = pick(rand, rand() < 0.6 ? DID_STARTS : OTHER_STARTS);
  const length = Math.floor(rand() * 16);
  for (let at = 0; at < length; at += 1) value += pick(rand, rand() < 0.9 ? ID_CHARACTERS : OTHER_CHARACTERS);
  return value;
}

/** A reason with each value it quotes taken out, so the reasons of one check read the same. */
function kindOf(reason: string): string {
  return reason.replace(/"(?:[^"\\]|\\.)*"(?:\.\.\.)?/g, 'Q');
}

describe('didPattern and whyNotDid agree', () => {
  const VALUES = 20_000;

  it.each([
    ['did:key and did:web', KEY_WEB, 14],
    ['did:key, did:web and did:webvh', KEY_WEB_WEBVH, 14],
    ['any method', undefined, 13],
  ] as const)('on every fuzzed value, for %s, reaching every reason a string can have', (_name, methods, reasons) => {
    const rand = prng(311);
    const pattern = didPattern(methods);
    const kinds = new Set<string>();
    let accepted = 0;
    for (let made = 0; made < VALUES; made += 1) {
      const value = fuzzed(rand);
      const reason = whyNotDid(value, methods);
      expect(pattern.test(value), JSON.stringify(value)).toBe(reason === undefined);
      if (methods === undefined) expect(isDid(value), JSON.stringify(value)).toBe(reason === undefined);
      if (reason === undefined) accepted += 1;
      else kinds.add(kindOf(reason));
    }
    expect([...kinds].sort()).toHaveLength(reasons);
    expect(accepted).toBeGreaterThan(VALUES / 10);
    expect(accepted).toBeLessThan(VALUES / 2);
  });
});
