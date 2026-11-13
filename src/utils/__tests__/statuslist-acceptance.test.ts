import { describe, it, expect } from 'vitest';
import {
  acceptedStatusListIssuers,
  acceptEntryPurpose,
  acceptStatusList,
  acceptStatusPurpose,
  statusListExpectationFor,
  type StatusCheckContext,
  type StatusListExpectation,
  type StatusListIssuers,
} from '../statuslist-acceptance.js';

const ISSUER = 'did:web:acme.example';
const OTHER = 'did:web:status.example';
const LIST_URL = 'https://acme.example/status/1';

const expected: StatusListExpectation = {
  statusListCredential: LIST_URL,
  statusPurpose: 'revocation',
  acceptedIssuers: [ISSUER],
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

describe('acceptStatusList: the issuer', () => {
  it("accepts a list issued by an accepted issuer, written as a string or as an object's id", () => {
    expect(acceptStatusList(list(), expected)).toEqual({ valid: true });
    expect(acceptStatusList(list({ issuer: { id: ISSUER, name: 'Acme' } }), expected)).toEqual({ valid: true });
    const either = { ...expected, acceptedIssuers: [OTHER, ISSUER] };
    expect(acceptStatusList(list(), either)).toEqual({ valid: true });
    expect(acceptStatusList(list({ issuer: { id: OTHER } }), either)).toEqual({ valid: true });
  });

  it('rejects a list issued by any other DID, written either way, naming the issuers it expected', () => {
    for (const issuer of [OTHER, { id: OTHER }]) {
      expect(rejection(acceptStatusList(list({ issuer }), expected))).toBe(
        `status list issuer "${OTHER}" is not the expected issuer ("${ISSUER}")`,
      );
    }
    const either = { ...expected, acceptedIssuers: [ISSUER, 'did:web:root.example'] };
    expect(rejection(acceptStatusList(list({ issuer: OTHER }), either))).toBe(
      `status list issuer "${OTHER}" is not the expected issuer ("${ISSUER}" or "did:web:root.example")`,
    );
  });

  it('names each expected issuer once', () => {
    expect(rejection(acceptStatusList(list({ issuer: OTHER }), { ...expected, acceptedIssuers: [ISSUER, ISSUER] }))).toBe(
      `status list issuer "${OTHER}" is not the expected issuer ("${ISSUER}")`,
    );
  });

  it('accepts no list when no issuer is accepted', () => {
    expect(acceptStatusList(list(), { ...expected, acceptedIssuers: [] }).valid).toBe(false);
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

describe('acceptedStatusListIssuers', () => {
  const ROOT = 'did:web:root.example';

  it("names the credential's issuer, then the pinned root, then those configured for the credential's issuer", () => {
    expect(acceptedStatusListIssuers({ credentialIssuer: ISSUER })).toEqual([ISSUER]);
    expect(acceptedStatusListIssuers({ credentialIssuer: ISSUER, trustedRootIssuer: ROOT })).toEqual([ISSUER, ROOT]);
    expect(acceptedStatusListIssuers({ credentialIssuer: ISSUER, trustedRootIssuer: ROOT }, { [ISSUER]: [OTHER] })).toEqual([
      ISSUER,
      ROOT,
      OTHER,
    ]);
    expect(acceptedStatusListIssuers({ credentialIssuer: ISSUER }, { [ISSUER]: [OTHER, ROOT] })).toEqual([ISSUER, OTHER, ROOT]);
  });

  it("takes configured issuers only for the credential's own issuer, not for the root's", () => {
    const configured = { [ROOT]: [OTHER], 'did:web:someone-else.example': ['did:web:x.example'] };
    expect(acceptedStatusListIssuers({ credentialIssuer: ISSUER, trustedRootIssuer: ROOT }, configured)).toEqual([
      ISSUER,
      ROOT,
    ]);
  });

  it('names each issuer once, where it first comes', () => {
    expect(acceptedStatusListIssuers({ credentialIssuer: ISSUER, trustedRootIssuer: ISSUER })).toEqual([ISSUER]);
    const configured = { [ISSUER]: [ROOT, OTHER, ISSUER, OTHER] };
    expect(acceptedStatusListIssuers({ credentialIssuer: ISSUER, trustedRootIssuer: ROOT }, configured)).toEqual([ISSUER, ROOT, OTHER]);
  });

  it('adds nobody through a key the map does not own', () => {
    expect(acceptedStatusListIssuers({ credentialIssuer: 'constructor' }, {})).toEqual(['constructor']);
    expect(acceptedStatusListIssuers({ credentialIssuer: 'toString' }, { [ISSUER]: [OTHER] })).toEqual(['toString']);
  });

  it('throws the TypeError a misconfigured checker throws for a map that is not a plain object of string arrays', () => {
    const NOT_A_MAP = 'statusListIssuers must be a plain object mapping credential issuer DIDs to arrays of status-list issuer DIDs';
    const entry = { statusListCredential: LIST_URL, statusPurpose: 'revocation' };
    for (const map of [null, OTHER, [], new Map(), Object.create({ [ISSUER]: [OTHER] })]) {
      expect(() => acceptedStatusListIssuers({ credentialIssuer: ISSUER }, map)).toThrow(new TypeError(NOT_A_MAP));
      expect(() => statusListExpectationFor(entry, { credentialIssuer: ISSUER }, map)).toThrow(new TypeError(NOT_A_MAP));
    }
    expect(() => acceptedStatusListIssuers({ credentialIssuer: ISSUER }, { [ISSUER]: OTHER } as never)).toThrow(
      new TypeError(`statusListIssuers["${ISSUER}"] must be an array of status-list issuer DIDs`),
    );
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

  it('accepts a list whose id is the URL it was fetched from, or one that states no id from the one issuer accepted', () => {
    expect(acceptStatusList(list(), expected)).toEqual({ valid: true });
    expect(acceptStatusList(noId, expected)).toEqual({ valid: true });
    expect(acceptStatusList({ ...noId, issuer: { id: ISSUER } }, expected)).toEqual({ valid: true });
    expect(acceptStatusList(noId, { ...expected, acceptedIssuers: [ISSUER, ISSUER], requireId: false })).toEqual({ valid: true });
  });

  it('rejects a list that states no id from any other accepted issuer, or when the reader requires one', () => {
    const either = { ...expected, acceptedIssuers: [ISSUER, OTHER] };
    expect(acceptStatusList(list({ issuer: OTHER }), either)).toEqual({ valid: true });
    expect(rejection(acceptStatusList({ ...noId, issuer: OTHER }, either))).toBe(NO_ID);
    const strict = { ...expected, requireId: true };
    expect(acceptStatusList(list(), strict)).toEqual({ valid: true });
    expect(rejection(acceptStatusList(noId, strict))).toBe(NO_ID);
  });

  // The rule itself decides when a list may leave out its id, so an expectation a caller builds or edits
  // cannot let one list stand in for another that a second accepted issuer keeps.
  it('rejects a list that states no id from its signer whenever another issuer is accepted, however the expectation is built', () => {
    const derived = statusListExpectationFor(expected, { credentialIssuer: ISSUER, trustedRootIssuer: OTHER });
    for (const handBuilt of [derived, { ...derived, requireId: false }, ...[[ISSUER, OTHER], [OTHER, ISSUER, ISSUER]].map(
      (acceptedIssuers) => ({ ...expected, acceptedIssuers }),
    )]) {
      expect(rejection(acceptStatusList(noId, handBuilt))).toBe(NO_ID);
    }
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
    const acceptedIssuers = Object.freeze([ISSUER, OTHER]);
    expect(acceptStatusList(frozen, Object.freeze({ ...expected, acceptedIssuers }))).toEqual({ valid: true });
    const context = Object.freeze({ credentialIssuer: ISSUER, trustedRootIssuer: OTHER });
    expect(acceptedStatusListIssuers(context, Object.freeze({ [ISSUER]: Object.freeze([OTHER]) }))).toEqual([ISSUER, OTHER]);
  });
});

describe('statusListExpectationFor', () => {
  const ROOT = 'did:web:root.example';
  const entry = { statusListCredential: LIST_URL, statusPurpose: 'suspension' };

  it('expects a list from an issuer acceptedStatusListIssuers names', () => {
    const context = { credentialIssuer: ISSUER, trustedRootIssuer: ROOT };
    expect(statusListExpectationFor(entry, context, { [ISSUER]: [OTHER] })).toStrictEqual({
      statusListCredential: LIST_URL,
      statusPurpose: 'suspension',
      acceptedIssuers: [ISSUER, ROOT, OTHER],
    });
    expect(statusListExpectationFor(entry, { credentialIssuer: ISSUER })).toStrictEqual({
      statusListCredential: LIST_URL,
      statusPurpose: 'suspension',
      acceptedIssuers: [ISSUER],
    });
  });

  it("reads the credential's own issuer's list that states no id only while that issuer is the one accepted for the credential", () => {
    const { id: _id, ...noId } = list();
    const read = (context: StatusCheckContext, statusListIssuers?: StatusListIssuers) =>
      rejection(
        acceptStatusList(noId, statusListExpectationFor({ ...entry, statusPurpose: 'revocation' }, context, statusListIssuers)),
      );
    expect(read({ credentialIssuer: ISSUER })).toBe('accepted');
    expect(read({ credentialIssuer: ISSUER, trustedRootIssuer: ISSUER }, { [ISSUER]: [ISSUER], [OTHER]: [ROOT] })).toBe('accepted');
    expect(read({ credentialIssuer: ISSUER }, { [ISSUER]: [] })).toBe('accepted');
    const NO_ID = `status list states no id, but must state the URL it was fetched from ("${LIST_URL}")`;
    expect(read({ credentialIssuer: ISSUER, trustedRootIssuer: ROOT })).toBe(NO_ID);
    expect(read({ credentialIssuer: ISSUER }, { [ISSUER]: [OTHER] })).toBe(NO_ID);
    expect(read({ credentialIssuer: ISSUER }, { [ISSUER]: [ISSUER, OTHER] })).toBe(NO_ID);
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
  it("quotes the list's issuer and each expected issuer; a list issuer that is not a string names no issuer", () => {
    expect(rejection(acceptStatusList(list({ issuer: LONG }), expected))).toBe(
      `status list issuer ${LONG_QUOTED} is not the expected issuer ("${ISSUER}")`,
    );
    for (const issuer of [NAMED, { id: NAMED }]) {
      expect(rejection(acceptStatusList(list({ issuer }), expected))).toBe('status list names no issuer');
    }
    const acceptedIssuers = [ISSUER, LONG, NAMED as string];
    expect(rejection(acceptStatusList(list({ issuer: OTHER }), { ...expected, acceptedIssuers }))).toBe(
      `status list issuer "${OTHER}" is not the expected issuer ("${ISSUER}" or ${LONG_QUOTED} or of type object)`,
    );
  });

  it('names at most three expected issuers, then how many more it accepts', () => {
    const many = Array.from({ length: 50 }, (_, i) => `did:web:${i}${'q'.repeat(100)}`);
    const quoted = (i: number) => `"did:web:${i}${'q'.repeat(64 - `did:web:${i}`.length)}"...`;
    const reason = rejection(acceptStatusList(list({ issuer: OTHER }), { ...expected, acceptedIssuers: many }));
    expect(reason).toBe(
      `status list issuer "${OTHER}" is not the expected issuer (${quoted(0)} or ${quoted(1)} or ${quoted(2)} and 47 more)`,
    );
    const four = rejection(acceptStatusList(list({ issuer: OTHER }), { ...expected, acceptedIssuers: [...many.slice(0, 3), ISSUER] }));
    expect(four).toBe(`status list issuer "${OTHER}" is not the expected issuer (${quoted(0)} or ${quoted(1)} or ${quoted(2)} and 1 more)`);
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
