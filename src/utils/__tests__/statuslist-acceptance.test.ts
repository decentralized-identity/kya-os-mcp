import { describe, it, expect } from 'vitest';
import {
  acceptEntryPurpose,
  acceptStatusList,
  acceptStatusPurpose,
  statusListExpectationFor,
  type StatusCheckContext,
  type StatusListExpectation,
  type StatusListIssuers,
  type StatusListKeeper,
} from '../statuslist-acceptance.js';

const ISSUER = 'did:web:acme.example';
const OTHER = 'did:web:status.example';
const LIST_URL = 'https://acme.example/status/1';

const expected: StatusListExpectation = {
  statusListCredential: LIST_URL,
  statusPurpose: 'revocation',
  keeper: { did: ISSUER, why: 'credential-issuer' },
  requireId: false,
};

/**
 * A Bitstring Status List v1.0 list as fetched; the rule reads only its `issuer`, `id` and `type`, and
 * its `credentialSubject`'s `type` and `statusPurpose`.
 */
const list = (fields: Record<string, unknown> = {}): Record<string, unknown> => ({
  id: LIST_URL,
  type: ['VerifiableCredential', 'BitstringStatusListCredential'],
  issuer: ISSUER,
  credentialSubject: { type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: 'uH4sI' },
  ...fields,
});

const subject = (statusPurpose: unknown): Record<string, unknown> => ({
  credentialSubject: { type: 'BitstringStatusList', statusPurpose, encodedList: 'uH4sI' },
});

const rejection = (verdict: ReturnType<typeof acceptStatusList>): string =>
  verdict.valid ? 'accepted' : verdict.reason;

/** Values their author chose: 100,000 characters, and a parsed object whose `toString` is a string. */
const LONG = 'v'.repeat(100_000);
const LONG_QUOTED = `"${'v'.repeat(64)}"...`;
const NAMED: unknown = JSON.parse('{"toString":"revocation"}');

/** `expected` with `did` as the keeper of the list's URL, because of `why`. */
const keptBy = (did: string, why: StatusListKeeper['why'] = 'credential-issuer'): StatusListExpectation => ({
  ...expected,
  keeper: { did, why },
});

describe('acceptStatusList: the issuer', () => {
  it("accepts a list the keeper of its URL issued, written as a string or as an object's id", () => {
    expect(acceptStatusList(list(), expected)).toEqual({ valid: true });
    expect(acceptStatusList(list({ issuer: { id: ISSUER, name: 'Acme' } }), expected)).toEqual({ valid: true });
    expect(acceptStatusList(list({ issuer: { id: OTHER } }), keptBy(OTHER, 'configured-url'))).toEqual({ valid: true });
  });

  it.each([
    ['configured-url', 'the issuer statusListIssuers binds this URL to'],
    ['configured-origin', "the issuer statusListIssuers binds this URL's origin to"],
    ['root-credential', 'the pinned root whose own credential names it'],
    ['credential-issuer', 'the issuer of the credential'],
    ['resolver-issuer', 'the issuer this resolver is configured with'],
  ] as const)('rejects a list any other DID issued, written either way, naming the keeper and that it keeps the URL as %s', (why, phrase) => {
    for (const issuer of [OTHER, { id: OTHER }]) {
      expect(rejection(acceptStatusList(list({ issuer }), keptBy(ISSUER, why)))).toBe(
        `status list issuer "${OTHER}" does not keep this list's URL: "${ISSUER}" does, as ${phrase}`,
      );
    }
  });

  it("rejects the credential's own issuer's list at a URL another issuer keeps", () => {
    expect(rejection(acceptStatusList(list(), keptBy(OTHER, 'root-credential')))).toBe(
      `status list issuer "${ISSUER}" does not keep this list's URL: "${OTHER}" does, as the pinned root whose own credential names it`,
    );
  });

  it('compares the issuer exactly', () => {
    for (const issuer of [`${ISSUER}#key-1`, ISSUER.toUpperCase(), ` ${ISSUER}`, `${ISSUER}:sub`]) {
      expect(acceptStatusList(list({ issuer }), expected).valid).toBe(false);
    }
  });

  it('rejects a list that names no usable issuer', () => {
    const { issuer: _issuer, ...noIssuer } = list();
    for (const candidate of [noIssuer, list({ issuer: '' }), list({ issuer: {} }), list({ issuer: { id: '' } }), list({ issuer: 7 }), list({ issuer: null })]) {
      expect(rejection(acceptStatusList(candidate, expected))).toBe('status list names no issuer');
    }
  });

  it('rejects anything that is not a list object', () => {
    for (const candidate of [null, undefined, 'list', 42, [list()]]) {
      expect(rejection(acceptStatusList(candidate, expected))).toBe('status list names no issuer');
    }
  });
});

describe('acceptStatusList: the statusPurpose', () => {
  it('accepts a list whose purpose is the entry purpose, or an array that includes it', () => {
    expect(acceptStatusList(list(subject('revocation')), expected)).toEqual({ valid: true });
    expect(acceptStatusList(list(subject(['suspension', 'revocation'])), expected)).toEqual({ valid: true });
  });

  it('rejects a list of another purpose, naming an array of purposes by its type', () => {
    expect(rejection(acceptStatusList(list(subject('suspension')), expected))).toBe(
      `status list statusPurpose mismatch: the list's is "suspension" and the entry's is "revocation"`,
    );
    expect(rejection(acceptStatusList(list(subject(['suspension', 'message'])), expected))).toBe(
      `status list statusPurpose mismatch: the list's is of type array and the entry's is "revocation"`,
    );
  });

  it('rejects a list with no purpose, an empty array, or a purpose that is not a string', () => {
    const noPurpose = `status list has no statusPurpose (the entry's is "revocation")`;
    for (const statusPurpose of [undefined, null, 7, { revocation: true }, [], ['revocation', 7]]) {
      expect(rejection(acceptStatusList(list(subject(statusPurpose)), expected))).toBe(noPurpose);
    }
    expect(rejection(acceptStatusList(list({ credentialSubject: undefined }), expected))).toBe(noPurpose);
    expect(rejection(acceptStatusList(list({ credentialSubject: [{ statusPurpose: 'revocation' }] }), expected))).toBe(
      noPurpose,
    );
  });

  it('compares the purpose exactly', () => {
    for (const statusPurpose of ['', 'Revocation', 'revocation ', ['revocations']]) {
      expect(rejection(acceptStatusList(list(subject(statusPurpose)), expected))).toMatch(/statusPurpose mismatch/);
    }
  });
});

// Verifiable Credentials Status List v2021 §2.2 has a StatusList2021Credential's statusPurpose be "a
// string"; Bitstring Status List v1.0 §2.2 lets it be "one or more strings" on a list whose `type`
// includes BitstringStatusListCredential and whose subject's `type` is BitstringStatusList.
describe('acceptStatusList: the statusPurpose forms a list type allows', () => {
  const ARRAY_REFUSED =
    'status list statusPurpose is an array, which only a BitstringStatusListCredential with a BitstringStatusList ' +
    `subject may state (the entry's is "revocation")`;
  const BITSTRING = ['VerifiableCredential', 'BitstringStatusListCredential'];
  const STATUS_LIST_2021 = ['VerifiableCredential', 'StatusList2021Credential'];
  const typed = (type: unknown, subjectType: unknown, statusPurpose: unknown) =>
    list({ type, credentialSubject: { type: subjectType, statusPurpose, encodedList: 'uH4sI' } });
  const ARRAYS = [['suspension', 'revocation'], ['revocation']];

  /** Lists not typed as a Bitstring Status List in both places §2.2 names: each states one string. */
  const ONE_STRING: [string, unknown, unknown][] = [
    ['a StatusList2021Credential', STATUS_LIST_2021, 'StatusList2021'],
    ['a BitstringStatusListCredential whose subject is a StatusList2021', BITSTRING, 'StatusList2021'],
    ['a StatusList2021Credential whose subject is a BitstringStatusList', STATUS_LIST_2021, 'BitstringStatusList'],
    ['a list typed as neither', ['VerifiableCredential'], undefined],
    ['a list whose type is the bare string BitstringStatusListCredential', 'BitstringStatusListCredential', 'BitstringStatusList'],
    ['a list whose subject type is an array', BITSTRING, ['BitstringStatusList']],
  ];

  it("reads an array that includes the entry's purpose on a list typed as a Bitstring Status List in both places", () => {
    for (const type of [BITSTRING, [...STATUS_LIST_2021, 'BitstringStatusListCredential']]) {
      for (const statusPurpose of ARRAYS) {
        expect(acceptStatusList(typed(type, 'BitstringStatusList', statusPurpose), expected)).toEqual({ valid: true });
        expect(acceptStatusPurpose(typed(type, 'BitstringStatusList', statusPurpose), 'revocation')).toEqual({ valid: true });
      }
    }
  });

  it.each(ONE_STRING)('holds %s to one string, whether or not the reader verifies its proof', (_list, type, subjectType) => {
    for (const statusPurpose of [...ARRAYS, []]) {
      expect(rejection(acceptStatusList(typed(type, subjectType, statusPurpose), expected))).toBe(ARRAY_REFUSED);
      expect(rejection(acceptStatusPurpose(typed(type, subjectType, statusPurpose), 'revocation'))).toBe(ARRAY_REFUSED);
    }
    expect(acceptStatusList(typed(type, subjectType, 'revocation'), expected)).toEqual({ valid: true });
    expect(acceptStatusPurpose(typed(type, subjectType, 'revocation'), 'revocation')).toEqual({ valid: true });
  });
});

describe('acceptStatusList: the stated id', () => {
  const { id: _id, ...noId } = list();
  const NO_ID = `status list states no id, but must state the URL it was fetched from ("${LIST_URL}")`;

  it('accepts a list whose id is the URL it was fetched from, or one that states no id where the reader requires none', () => {
    expect(acceptStatusList(list(), expected)).toEqual({ valid: true });
    expect(acceptStatusList(list(), { ...expected, requireId: true })).toEqual({ valid: true });
    expect(acceptStatusList(noId, expected)).toEqual({ valid: true });
    expect(acceptStatusList({ ...noId, issuer: { id: ISSUER } }, expected)).toEqual({ valid: true });
  });

  it('rejects a list that states no id when the reader requires one, whoever keeps the URL', () => {
    expect(rejection(acceptStatusList(noId, { ...expected, requireId: true }))).toBe(NO_ID);
    expect(rejection(acceptStatusList({ ...noId, issuer: OTHER }, { ...keptBy(OTHER, 'configured-url'), requireId: true }))).toBe(NO_ID);
  });

  it('rejects a list that states another id, naming one that is not a string by its type', () => {
    const named: [unknown, string][] = [
      ...['https://acme.example/status/2', `${LIST_URL}#list`, `${LIST_URL}/`].map((id): [string, string] => [id, `"${id}"`]),
      [null, 'of type null'],
      [1, 'of type number'],
    ];
    for (const [id, as] of named) {
      expect(rejection(acceptStatusList(list({ id }), expected))).toBe(
        `status list id ${as} is not the URL it was fetched from ("${LIST_URL}")`,
      );
    }
  });

  it('says where the id and the URL first differ, counting code points, when both read the same once cut', () => {
    const url = `https://status.example/${'\u{1F600}'.repeat(60)}/list-a`;
    const at = (id: string) => rejection(acceptStatusList(list({ id }), { ...expected, statusListCredential: url }));
    const cut = `"https://status.example/${'\u{1F600}'.repeat(41)}"...`;
    const differ = (position: number) => `status list id ${cut} is not the URL it was fetched from (${cut}); they first differ at character ${position}`;
    expect(at(url.replace('list-a', 'list-b'))).toBe(differ(90));
    expect(at(url.slice(0, -1))).toBe(differ(90));
    expect(at([...url].slice(0, 80).join(''))).toBe(differ(81));
    expect(at('https://status.example/x')).toBe(`status list id "https://status.example/x" is not the URL it was fetched from (${cut})`);
    const early = url.replace('\u{1F600}', 'x');
    expect(at(early)).toBe(`status list id "https://status.example/x${'\u{1F600}'.repeat(40)}"... is not the URL it was fetched from (${cut})`);
  });

  it('compares the id byte for byte, as a string', () => {
    const sameResource = ['https://ACME.example/status/1', 'https://acme.example:443/status/1', 'https://acme.example/status/%31'];
    const near = ['https://acme.example/status/', `${LIST_URL}?resourceName=other`];
    for (const id of [...sameResource, ...near, [LIST_URL], new URL(LIST_URL)]) {
      expect(acceptStatusList(list({ id }), expected).valid).toBe(false);
    }
    const queried = `${LIST_URL}?resourceName=revocation-a&resourceType=StatusList`;
    for (const id of [LIST_URL, queried.replace('revocation-a', 'revocation-b')]) {
      expect(acceptStatusList(list({ id }), { ...expected, statusListCredential: queried }).valid).toBe(false);
    }
  });
});

describe('acceptStatusList: the verdict', () => {
  it('reports the issuer first, then the purpose, then the id', () => {
    const everythingWrong = list({ issuer: OTHER, id: 'https://elsewhere.example', ...subject('suspension') });
    expect(rejection(acceptStatusList(everythingWrong, expected))).toMatch(/^status list issuer /);
    expect(rejection(acceptStatusList({ ...everythingWrong, issuer: ISSUER }, expected))).toMatch(/statusPurpose mismatch/);
    expect(rejection(acceptStatusList({ ...everythingWrong, issuer: ISSUER, ...subject('revocation') }, expected))).toMatch(
      /^status list id /,
    );
  });

  it('reads its inputs without changing them', () => {
    const frozen = Object.freeze(list({ issuer: Object.freeze({ id: OTHER }) }));
    const keeper = Object.freeze({ did: OTHER, why: 'configured-url' } as const);
    expect(acceptStatusList(frozen, Object.freeze({ ...expected, keeper }))).toEqual({ valid: true });
    const context = Object.freeze({ credentialIssuer: ISSUER, trustedRootIssuer: OTHER, trustedRootStatusList: LIST_URL });
    const bound = Object.freeze({ [OTHER]: Object.freeze(['https://status.example']) });
    expect(statusListExpectationFor({ statusListCredential: LIST_URL, statusPurpose: 'revocation' }, context, bound).keeper).toEqual({
      did: OTHER,
      why: 'root-credential',
    });
  });
});

describe('statusListExpectationFor', () => {
  const ROOT = 'did:web:root.example';
  const ROOT_URL = 'https://root.example/status/1';
  const entry = { statusListCredential: LIST_URL, statusPurpose: 'suspension' };
  const pinned = { credentialIssuer: ISSUER, trustedRootIssuer: ROOT, trustedRootStatusList: ROOT_URL };

  it("expects a list from the keeper statusListKeeperFor names, with the entry's URL and purpose", () => {
    expect(statusListExpectationFor(entry, { credentialIssuer: ISSUER })).toStrictEqual({
      statusListCredential: LIST_URL,
      statusPurpose: 'suspension',
      keeper: { did: ISSUER, why: 'credential-issuer' },
      requireId: false,
    });
    expect(statusListExpectationFor({ ...entry, statusListCredential: ROOT_URL }, pinned)).toStrictEqual({
      statusListCredential: ROOT_URL,
      statusPurpose: 'suspension',
      keeper: { did: ROOT, why: 'root-credential' },
      requireId: true,
    });
    expect(statusListExpectationFor(entry, pinned, { [OTHER]: [LIST_URL] }).keeper).toEqual({ did: OTHER, why: 'configured-url' });
    expect(statusListExpectationFor(entry, pinned, { [OTHER]: ['https://acme.example'] }).keeper).toEqual({
      did: OTHER,
      why: 'configured-origin',
    });
  });

  it('throws the TypeError a misconfigured checker throws for a map it could not apply', () => {
    const NOT_A_MAP = 'statusListIssuers must be a plain object mapping each status-list issuer DID to the status-list URLs or https origins it keeps';
    for (const map of [null, OTHER, [], new Map(), Object.create({ [OTHER]: [LIST_URL] })]) {
      expect(() => statusListExpectationFor(entry, { credentialIssuer: ISSUER }, map)).toThrow(new TypeError(NOT_A_MAP));
    }
    expect(() => statusListExpectationFor(entry, { credentialIssuer: ISSUER }, { [ISSUER]: [OTHER] })).toThrow(TypeError);
  });

  // A list may leave out its id only where the credential's own issuer is the only issuer whose
  // list the reader would take at any URL. Each line below is one part of that condition.
  it("requires an id of every list but the credential's own issuer's, and of that one unless nobody else keeps any URL", () => {
    const requires = (context: StatusCheckContext, statusListIssuers?: StatusListIssuers, url = LIST_URL) =>
      statusListExpectationFor({ ...entry, statusListCredential: url }, context, statusListIssuers).requireId;
    expect(requires({ credentialIssuer: ISSUER })).toBe(false);
    expect(requires({ credentialIssuer: ISSUER }, {})).toBe(false);
    expect(requires({ credentialIssuer: ISSUER, trustedRootIssuer: ISSUER })).toBe(false);
    expect(requires({ credentialIssuer: ISSUER, trustedRootIssuer: ISSUER, trustedRootStatusList: ROOT_URL })).toBe(false);
    expect(requires({ credentialIssuer: ISSUER }, { [ISSUER]: ['https://elsewhere.example'] })).toBe(false);
    // The pinned root's own credential, at the URL that credential names: the root is its issuer.
    expect(requires({ credentialIssuer: ROOT, trustedRootIssuer: ROOT, trustedRootStatusList: ROOT_URL }, undefined, ROOT_URL)).toBe(false);
    // Another root is pinned, whatever URL its credential names, or none.
    expect(requires({ credentialIssuer: ISSUER, trustedRootIssuer: ROOT })).toBe(true);
    expect(requires(pinned)).toBe(true);
    // The configuration names another issuer, whatever it binds to it.
    expect(requires({ credentialIssuer: ISSUER }, { [OTHER]: [] })).toBe(true);
    expect(requires({ credentialIssuer: ISSUER }, { [OTHER]: ['https://status.example'] })).toBe(true);
    expect(requires({ credentialIssuer: ISSUER }, { [ISSUER]: [LIST_URL], [OTHER]: ['https://status.example'] })).toBe(true);
    expect(requires({ credentialIssuer: ROOT, trustedRootIssuer: ROOT, trustedRootStatusList: ROOT_URL }, { [OTHER]: [] }, ROOT_URL)).toBe(true);
    // The keeper is not the credential's issuer: the pinned root, for a delegate's entry at the
    // URL the root's credential names.
    expect(requires(pinned, undefined, ROOT_URL)).toBe(true);
    // The configuration names the keeper, the credential's own issuer included.
    expect(requires({ credentialIssuer: ISSUER }, { [OTHER]: [LIST_URL] })).toBe(true);
    expect(requires({ credentialIssuer: ISSUER }, { [ISSUER]: [LIST_URL] })).toBe(true);
    expect(requires({ credentialIssuer: ISSUER }, { [ISSUER]: ['https://acme.example'] })).toBe(true);
  });

  // The rule this one replaced accepted, for a credential, its issuer, the pinned root and the
  // issuers a map keyed by credential issuer listed for it, and let a list leave out its id only
  // when its signer was every one of them. Each row is a case of that rule with the same case of
  // this one beside it: `old` and `now` say whether the credential's own issuer's list may leave
  // out its id. No row is wider now. The two that are narrower differ in the configuration, whose
  // shape changed: a map that binds this URL to the issuer itself names a keeper by configuration,
  // and a key for any other issuer names another keeper, where the old map's key for another
  // credential issuer said nothing of this one.
  it.each([
    ['nobody pinned, nothing configured', { credentialIssuer: ISSUER }, undefined, LIST_URL, true, true],
    ["a root pinned, the credential the root's own, its URL not named", { credentialIssuer: ROOT, trustedRootIssuer: ROOT }, undefined, ROOT_URL, true, true],
    ["a root pinned, the credential the root's own, at the URL it names", { credentialIssuer: ROOT, trustedRootIssuer: ROOT, trustedRootStatusList: ROOT_URL }, undefined, ROOT_URL, true, true],
    ["a root pinned, the credential a delegate's, at its own URL", { credentialIssuer: ISSUER, trustedRootIssuer: ROOT, trustedRootStatusList: ROOT_URL }, undefined, LIST_URL, false, false],
    ["a root pinned, the credential a delegate's, at the URL the root's credential names", { credentialIssuer: ISSUER, trustedRootIssuer: ROOT, trustedRootStatusList: ROOT_URL }, undefined, ROOT_URL, false, false],
    ['the configuration naming the issuer itself, for another URL', { credentialIssuer: ISSUER }, { [ISSUER]: ['https://elsewhere.example'] }, LIST_URL, true, true],
    ['the configuration naming the issuer itself, for this URL', { credentialIssuer: ISSUER }, { [ISSUER]: [LIST_URL] }, LIST_URL, true, false],
    ['the configuration naming another issuer, for this URL', { credentialIssuer: ISSUER }, { [OTHER]: [LIST_URL] }, LIST_URL, false, false],
    ['the configuration naming another issuer, for another URL', { credentialIssuer: ISSUER }, { [OTHER]: ['https://elsewhere.example'] }, LIST_URL, true, false],
    ["a root pinned, the credential the root's own, the configuration naming another issuer", { credentialIssuer: ROOT, trustedRootIssuer: ROOT, trustedRootStatusList: ROOT_URL }, { [OTHER]: ['https://elsewhere.example'] }, ROOT_URL, true, false],
  ] as [string, StatusCheckContext, StatusListIssuers | undefined, string, boolean, boolean][])(
    'is no wider than the rule it replaced: %s',
    (_label, context, statusListIssuers, url, old, now) => {
      const { keeper, requireId } = statusListExpectationFor({ ...entry, statusListCredential: url }, context, statusListIssuers);
      const mayOmit = keeper.did === context.credentialIssuer && !requireId;
      expect(mayOmit).toBe(now);
      expect(now && !old).toBe(false);
    },
  );

  it("reads the credential's own issuer's list that states no id only in those cases", () => {
    const { id: _id, ...noId } = list();
    const read = (context: StatusCheckContext, statusListIssuers?: StatusListIssuers) =>
      rejection(
        acceptStatusList(noId, statusListExpectationFor({ ...entry, statusPurpose: 'revocation' }, context, statusListIssuers)),
      );
    expect(read({ credentialIssuer: ISSUER })).toBe('accepted');
    expect(read({ credentialIssuer: ISSUER, trustedRootIssuer: ISSUER }, { [ISSUER]: ['https://elsewhere.example'] })).toBe('accepted');
    const NO_ID = `status list states no id, but must state the URL it was fetched from ("${LIST_URL}")`;
    expect(read({ credentialIssuer: ISSUER, trustedRootIssuer: ROOT })).toBe(NO_ID);
    expect(read({ credentialIssuer: ISSUER }, { [OTHER]: ['https://status.example'] })).toBe(NO_ID);
    expect(read({ credentialIssuer: ISSUER }, { [ISSUER]: [LIST_URL] })).toBe(NO_ID);
  });
});

describe('acceptEntryPurpose', () => {
  it("reads an entry that states no purpose, or the reader's, for the reader's purpose", () => {
    expect(acceptEntryPurpose(undefined, 'revocation')).toEqual({ valid: true });
    expect(acceptEntryPurpose('revocation', 'revocation')).toEqual({ valid: true });
    expect(acceptEntryPurpose('suspension', 'suspension')).toEqual({ valid: true });
  });

  it('rejects an entry that states another purpose, or one that is not a string, null included, naming it as the rule quotes it', () => {
    const named: [unknown, string][] = [
      ['suspension', '"suspension"'],
      ['', '""'],
      [LONG, LONG_QUOTED],
      [NAMED, 'of type object'],
      [null, 'of type null'],
      [7, 'of type number'],
      [['revocation'], 'of type array'],
    ];
    for (const [statusPurpose, as] of named) {
      expect(rejection(acceptEntryPurpose(statusPurpose, 'revocation'))).toBe(
        `the entry's statusPurpose is ${as}, not the checker's "revocation"`,
      );
    }
  });

  it("quotes the checker's purpose as it quotes the entry's, bounded and well-formed", () => {
    expect(rejection(acceptEntryPurpose('revocation', `suspension\n${'x\uD800'.repeat(100)}`))).toBe(
      `the entry's statusPurpose is "revocation", not the checker's "suspension\\n${'x\\ud800'.repeat(26)}x"...`,
    );
  });
});

describe('acceptStatusPurpose', () => {
  it('applies the purpose part of the rule alone', () => {
    expect(acceptStatusPurpose(list({ issuer: OTHER, id: 'https://elsewhere.example' }), 'revocation')).toEqual({
      valid: true,
    });
    expect(acceptStatusPurpose(list(subject(['revocation', 'suspension'])), 'suspension')).toEqual({ valid: true });
    expect(rejection(acceptStatusPurpose(list(subject('suspension')), 'revocation'))).toBe(
      `status list statusPurpose mismatch: the list's is "suspension" and the entry's is "revocation"`,
    );
    expect(rejection(acceptStatusPurpose(null, 'revocation'))).toBe(`status list has no statusPurpose (the entry's is "revocation")`);
  });

  it('quotes the purposes as the whole rule does', () => {
    expect(rejection(acceptStatusPurpose(list(subject(LONG)), NAMED as string))).toBe(
      `status list statusPurpose mismatch: the list's is ${LONG_QUOTED} and the entry's is of type object`,
    );
    expect(rejection(acceptStatusPurpose(null, LONG))).toBe(`status list has no statusPurpose (the entry's is ${LONG_QUOTED})`);
  });
});

// A reason is shown to people, written to logs and signed into response proofs, so it quotes at most
// the first 64 characters of a value the list, the entry or the credential chose, and names one that
// is not a string by its type, never converting it.
describe('acceptStatusList: the values a reason quotes', () => {
  it("quotes the list's issuer and the keeper; a list issuer that is not a string names no issuer", () => {
    expect(rejection(acceptStatusList(list({ issuer: LONG }), expected))).toBe(
      `status list issuer ${LONG_QUOTED} does not keep this list's URL: "${ISSUER}" does, as the issuer of the credential`,
    );
    for (const issuer of [NAMED, { id: NAMED }]) {
      expect(rejection(acceptStatusList(list({ issuer }), expected))).toBe('status list names no issuer');
    }
    expect(rejection(acceptStatusList(list({ issuer: OTHER }), keptBy(LONG)))).toBe(
      `status list issuer "${OTHER}" does not keep this list's URL: ${LONG_QUOTED} does, as the issuer of the credential`,
    );
    expect(rejection(acceptStatusList(list({ issuer: OTHER }), keptBy(NAMED as string)))).toBe(
      `status list issuer "${OTHER}" does not keep this list's URL: of type object does, as the issuer of the credential`,
    );
  });

  it("quotes the entry's statusPurpose, whether the list states another or none", () => {
    const { credentialSubject: _subject, ...noPurpose } = list();
    for (const [statusPurpose, as] of [[LONG, LONG_QUOTED], [NAMED, 'of type object']]) {
      const entry = { ...expected, statusPurpose: statusPurpose as string };
      expect(rejection(acceptStatusList(list(), entry))).toBe(
        `status list statusPurpose mismatch: the list's is "revocation" and the entry's is ${as}`,
      );
      expect(rejection(acceptStatusList(noPurpose, entry))).toBe(`status list has no statusPurpose (the entry's is ${as})`);
    }
  });

  it("quotes the entry's statusPurpose when a list that may not state an array states one", () => {
    const listed = list({
      type: ['VerifiableCredential', 'StatusList2021Credential'],
      credentialSubject: { type: 'StatusList2021', statusPurpose: ['revocation'], encodedList: 'uH4sI' },
    });
    for (const [statusPurpose, as] of [[LONG, LONG_QUOTED], [NAMED, 'of type object']]) {
      expect(rejection(acceptStatusList(listed, { ...expected, statusPurpose: statusPurpose as string }))).toBe(
        'status list statusPurpose is an array, which only a BitstringStatusListCredential with a BitstringStatusList ' +
          `subject may state (the entry's is ${as})`,
      );
    }
  });

  it("quotes the list's statusPurpose; one that is neither a string nor an array of strings is none", () => {
    expect(rejection(acceptStatusList(list(subject(LONG)), expected))).toBe(
      `status list statusPurpose mismatch: the list's is ${LONG_QUOTED} and the entry's is "revocation"`,
    );
    expect(rejection(acceptStatusList(list(subject(NAMED)), expected))).toBe(
      `status list has no statusPurpose (the entry's is "revocation")`,
    );
  });

  it("quotes the list's id and the URL it was fetched from", () => {
    for (const [id, as] of [[LONG, LONG_QUOTED], [NAMED, 'of type object']]) {
      expect(rejection(acceptStatusList(list({ id }), expected))).toBe(
        `status list id ${as} is not the URL it was fetched from ("${LIST_URL}")`,
      );
    }
    expect(rejection(acceptStatusList(list(), { ...expected, statusListCredential: LONG }))).toBe(
      `status list id "${LIST_URL}" is not the URL it was fetched from (${LONG_QUOTED})`,
    );
    expect(rejection(acceptStatusList(list({ id: `${LONG}w` }), { ...expected, statusListCredential: LONG }))).toBe(
      `status list id ${LONG_QUOTED} is not the URL it was fetched from (${LONG_QUOTED}); they first differ at character 100001`,
    );
    const { id: _id, ...noId } = list();
    const strict = { ...expected, requireId: true, statusListCredential: LONG };
    expect(rejection(acceptStatusList(noId, strict))).toBe(
      `status list states no id, but must state the URL it was fetched from (${LONG_QUOTED})`,
    );
  });
});
