/**
 * The status-list vectors that each turn on one respect of a list.
 *
 * `status-list/tampered-list` fails on its list's proof. It carries the revoked
 * credential and the signed list from `status-list/revoked-credential` with the
 * revoked bit cleared, so a verifier that reads the bits without checking the
 * list's proof reports the credential active and passes a vector it must reject.
 *
 * `status-list/foreign-issuer-list`, `status-list/purpose-mismatch-list`,
 * `status-list/purpose-array-2021-list` and `status-list/id-mismatch-list` each
 * carry one revoked credential and, at its list's URL, a list with its bit unset
 * and a proof that verifies, which is the issuer's list for it in all but one
 * respect: another DID issued it, it is of another purpose, it states its
 * purposes in an array, which a StatusList2021 list may not, or it states another
 * URL as its `id`. A verifier that checks only the list's proof reports the
 * credential active.
 *
 * `status-list/root-no-id-list` and `status-list/configured-issuer-no-id-list`
 * each carry a revoked credential and a list with its bit unset and a proof that
 * verifies, from an issuer other than the credential's that the vector has the
 * verifier accept: the chain's pinned root, or an issuer it is configured to
 * accept for the credential's issuer. The list states no `id`, which only the
 * credential's own issuer's list may leave out, and only when no other issuer
 * is accepted, so a verifier that reads it reports the credential active.
 *
 * `status-list/no-id-list` carries the active credential and its signed list,
 * re-issued without its `id`, and `status-list/purpose-array-list` an active
 * credential and its issuer's Bitstring Status List v1.0 list, which declares
 * the purposes `suspension` and `revocation`. Each list's proof verifies and the
 * credential's bit is unset, so a verifier that refuses the form fails a vector
 * it must pass.
 *
 * Every vector of the category names, as its server DID, the audience its
 * credential is bound to, and the subject of every list names the list the list
 * states, or the URL it is served at when it states none: each list a vector
 * carries is one its issuer could have signed. Every list carries the context,
 * the types and the date of the data model of its credential's entry, a
 * StatusList2021Credential or a BitstringStatusListCredential, and at least the
 * 131,072 entries Bitstring Status List v1.0 requires.
 */

import { describe, it, expect } from 'vitest';
import { loadVectors } from '../loader.js';
import { BitstringManager } from '../../src/delegation/bitstring.js';
import { statusListGzipCodec } from '../../src/utils/statuslist-gzip.js';
import { verifySignature } from '../../src/delegation/vc-verification-checks.js';
import { NodeCryptoProvider } from '../../src/providers/node-crypto.js';
import type { DelegationCredential, DIDDocument } from '../../src/index.js';
import { ReferenceConformanceAdapter } from '../reference-adapter.js';
import { ed25519SignatureVerifier } from '../crypto-kit.js';
import type { ConformanceVector, StatusListInput } from '../types.js';

interface List {
  credentialSubject: { encodedList: string } & Record<string, unknown>;
  [key: string]: unknown;
}
interface Credential {
  issuer: string;
  credentialSubject: { delegation: { constraints: { audience: string } } };
  credentialStatus: { type: string; statusListCredential: string; statusListIndex: string; statusPurpose: string };
}

const vectors = loadVectors();
const byId = (id: string): ConformanceVector => {
  const vector = vectors.find((v) => v.id === id);
  if (!vector) throw new Error(`missing vector ${id}`);
  return vector;
};
const inputOf = (id: string) => byId(id).input as StatusListInput;
const listOf = (input: StatusListInput): List => {
  const { statusListCredential } = (input.credential as Credential).credentialStatus;
  return input.statusLists[statusListCredential] as List;
};
/** The bit `list` holds at the index of the status entry of `input`'s credential. */
const bitIn = async (list: List, input: StatusListInput): Promise<boolean> => {
  const manager = await BitstringManager.decode(list.credentialSubject.encodedList, statusListGzipCodec, statusListGzipCodec);
  return manager.getBit(Number((input.credential as Credential).credentialStatus.statusListIndex));
};
const bitOf = (input: StatusListInput): Promise<boolean> => bitIn(listOf(input), input);
/** The list's proof, verified against the DID documents the vector supplies. */
const proofOf = (input: StatusListInput) =>
  verifySignature(
    listOf(input) as unknown as DelegationCredential,
    { resolve: async (did: string) => (input.didDocuments[did] as DIDDocument | undefined) ?? null },
    ed25519SignatureVerifier(new NodeCryptoProvider()),
  );
/**
 * The list each entry type points to, and the members it must not carry: a StatusList2021Credential,
 * in the VC Data Model 1.1, or a W3C Bitstring Status List v1.0 BitstringStatusListCredential, in the
 * VC Data Model 2.0, which dates a credential with `validFrom` in place of `issuanceDate`.
 */
const DATA_MODELS: Record<string, { list: Record<string, unknown>; absent: string[] }> = {
  StatusList2021Entry: {
    list: {
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'],
      type: ['VerifiableCredential', 'StatusList2021Credential'],
      issuanceDate: expect.any(String),
      credentialSubject: { type: 'StatusList2021' },
    },
    absent: [],
  },
  BitstringStatusListEntry: {
    list: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      validFrom: expect.any(String),
      credentialSubject: { type: 'BitstringStatusList' },
    },
    absent: ['issuanceDate'],
  },
};

describe('status-list/tampered-list', () => {
  const signed = inputOf('status-list/revoked-credential');
  const tampered = inputOf('status-list/tampered-list');

  it('is a negative vector carrying the revoked credential', () => {
    expect(byId('status-list/tampered-list').expected).toBe('fail');
    expect(tampered.credential).toEqual(signed.credential);
    expect(tampered.didDocuments).toEqual(signed.didDocuments);
  });

  it('changes nothing in the signed list but its encodedList', () => {
    const { credentialSubject: signedSubject, ...signedRest } = listOf(signed);
    const { credentialSubject: tamperedSubject, ...tamperedRest } = listOf(tampered);
    expect(tamperedRest).toEqual(signedRest);
    expect({ ...tamperedSubject, encodedList: '' }).toEqual({ ...signedSubject, encodedList: '' });
    expect(tamperedSubject.encodedList).not.toBe(signedSubject.encodedList);
  });

  it("reads the credential's bit as unset, where the signed list has it set", async () => {
    expect(await bitOf(signed)).toBe(true);
    expect(await bitOf(tampered)).toBe(false);
  });

  it("is rejected by the reference adapter on the list's proof", async () => {
    const result = await new ReferenceConformanceAdapter().verifyStatusList(tampered);
    expect(result.outcome).toBe('fail');
    expect(result.detail).toMatch(/status list .* proof rejected/);
  });
});

/**
 * Each binding vector, the list it would carry if that list could speak for its
 * credential (the one change undone), and the rejection the change must cause.
 */
const BINDING_VECTORS: [string, (list: List, credential: Credential) => List, RegExp][] = [
  [
    'status-list/foreign-issuer-list',
    (list, credential) => ({ ...list, issuer: credential.issuer }),
    /status list issuer .* is not the expected issuer/,
  ],
  [
    'status-list/purpose-mismatch-list',
    (list, credential) => ({
      ...list,
      credentialSubject: { ...list.credentialSubject, statusPurpose: credential.credentialStatus.statusPurpose },
    }),
    /status list statusPurpose mismatch/,
  ],
  [
    'status-list/purpose-array-2021-list',
    // Undone, the list states as one string the purpose its array shares with the entry, so a list
    // whose array lacks the entry's purpose is not undone: it differs in that respect as well.
    (list, credential) => {
      const purposes = list.credentialSubject.statusPurpose;
      const entry = credential.credentialStatus.statusPurpose;
      return {
        ...list,
        credentialSubject: { ...list.credentialSubject, statusPurpose: Array.isArray(purposes) && purposes.includes(entry) ? entry : purposes },
      };
    },
    /status list statusPurpose is an array, which only a BitstringStatusListCredential with a BitstringStatusList subject/,
  ],
  [
    'status-list/id-mismatch-list',
    (list, { credentialStatus: { statusListCredential: url } }) => ({
      ...list,
      id: url,
      credentialSubject: { ...list.credentialSubject, id: `${url}#list` },
    }),
    /status list id .* is not the URL it was fetched from/,
  ],
];

describe.each(BINDING_VECTORS)('%s', (id, undone, rejection) => {
  const input = inputOf(id);
  const credential = input.credential as Credential;
  const list = listOf(input);
  const { proof: _proof, ...unsigned } = list;

  it('is a negative vector carrying the same revoked credential as the other binding vectors', () => {
    expect(byId(id).expected).toBe('fail');
    for (const [other] of BINDING_VECTORS) expect(inputOf(other).credential).toEqual(credential);
    const revoked = inputOf('status-list/revoked-credential').credential as Credential;
    expect(credential.credentialStatus).toEqual(revoked.credentialStatus);
  });

  it('differs in one respect only from a list that could speak for the credential', () => {
    const speaking = undone(unsigned, credential);
    for (const other of BINDING_VECTORS) expect(undoneListOf(other)).toEqual(speaking);
    expect(unsigned).not.toEqual(speaking);
    expect(speaking).toMatchObject({
      id: credential.credentialStatus.statusListCredential,
      issuer: credential.issuer,
      credentialSubject: { statusPurpose: credential.credentialStatus.statusPurpose },
    });
  });

  it("reads the credential's bit as unset", async () => {
    expect(await bitOf(input)).toBe(false);
  });

  it("carries a proof that verifies against its issuer's DID document, which the vector supplies", async () => {
    expect(await proofOf(input)).toMatchObject({ valid: true });
  });

  it('is rejected by the reference adapter on that one change', async () => {
    const result = await new ReferenceConformanceAdapter().verifyStatusList(input);
    expect(result.outcome).toBe('fail');
    expect(result.detail).toMatch(rejection);
  });
});

/** A binding vector's list, unsigned and with its one change undone. */
function undoneListOf([id, undone]: (typeof BINDING_VECTORS)[number]): List {
  const input = inputOf(id);
  const { proof: _proof, ...unsigned } = listOf(input);
  return undone(unsigned, input.credential as Credential);
}

/** `id`'s list without its proof. */
function unsignedListOf(id: string): List {
  const { proof: _proof, ...unsigned } = listOf(inputOf(id));
  return unsigned;
}

/**
 * Each negative vector whose list an issuer other than the credential's signed, the issuer the
 * vector has the verifier accept for the credential, and the list the vector carries with its `id`
 * stated: a list from that issuer the verifier reads.
 */
const OTHER_SIGNER_VECTORS: [string, (input: StatusListInput) => string | undefined, () => List][] = [
  ['status-list/root-no-id-list', (input) => input.trustedRootIssuer, () => undoneListOf(BINDING_VECTORS[0]!)],
  [
    'status-list/configured-issuer-no-id-list',
    (input) => input.statusListIssuers?.[(input.credential as Credential).issuer]?.[0],
    () => unsignedListOf('status-list/foreign-issuer-list'),
  ],
];

describe.each(OTHER_SIGNER_VECTORS)('%s', (id, accepted, stating) => {
  const input = inputOf(id);
  const credential = input.credential as Credential;
  const url = credential.credentialStatus.statusListCredential;
  const { proof: _proof, ...unsigned } = listOf(input);

  it('is a negative vector whose list another issuer signed, which the vector has the verifier accept', () => {
    expect(byId(id).expected).toBe('fail');
    expect(unsigned.issuer).not.toBe(credential.issuer);
    expect(accepted(input)).toBe(unsigned.issuer);
  });

  it('states no id, and is in every other respect a list from that issuer which states its URL', () => {
    expect(unsigned).not.toHaveProperty('id');
    expect({ ...unsigned, id: url }).toEqual(stating());
  });

  it("reads the credential's bit as unset, where its issuer's signed list has it set", async () => {
    expect(await bitOf(input)).toBe(false);
    expect(await bitIn(listOf(inputOf('status-list/revoked-credential')), input)).toBe(true);
  });

  it("carries a proof that verifies against its issuer's DID document, which the vector supplies", async () => {
    expect(await proofOf(input)).toMatchObject({ valid: true });
  });

  it('is rejected by the reference adapter on the missing id, and on the issuer without the configuration', async () => {
    const adapter = new ReferenceConformanceAdapter();
    expect(await adapter.verifyStatusList(input)).toEqual({
      outcome: 'fail',
      detail: `Status check error: status list states no id, but must state the URL it was fetched from ("${url}")`,
    });
    const { trustedRootIssuer: _root, statusListIssuers: _issuers, ...unconfigured } = input;
    expect((await adapter.verifyStatusList(unconfigured)).detail).toMatch(/status list issuer .* is not the expected issuer/);
  });
});

/**
 * Each positive vector that re-issues the credential's signed list in another form, the form its
 * list takes, and the signed list it re-issues (that form undone).
 */
const FORM_VECTORS: [string, (list: List) => void, (list: List, credential: Credential) => List][] = [
  [
    'status-list/no-id-list',
    (list) => expect(list).not.toHaveProperty('id'),
    (list, { credentialStatus: { statusListCredential: url } }) => ({ ...list, id: url }),
  ],
];

describe.each(FORM_VECTORS)('%s', (id, form, undone) => {
  const active = inputOf('status-list/active-credential');
  const input = inputOf(id);
  const credential = input.credential as Credential;
  const { proof: _proof, ...unsigned } = listOf(input);
  const { proof: _signedProof, ...signed } = listOf(active);

  it('is a positive vector carrying the active credential', () => {
    expect(byId(id).expected).toBe('pass');
    expect(credential).toEqual(active.credential);
    expect(input.didDocuments).toEqual(active.didDocuments);
  });

  it("is the credential's signed list in another form, and in no other respect", () => {
    form(unsigned);
    expect(unsigned).not.toEqual(signed);
    expect(undone(unsigned, credential)).toEqual(signed);
  });

  it("reads the credential's bit as unset", async () => {
    expect(await bitOf(input)).toBe(false);
  });

  it("carries a proof that verifies against its issuer's DID document, which the vector supplies", async () => {
    expect(await proofOf(input)).toMatchObject({ valid: true });
  });

  it('is read by the reference adapter, which reports the credential active', async () => {
    const result = await new ReferenceConformanceAdapter().verifyStatusList(input);
    expect(result).toMatchObject({ outcome: 'pass' });
  });
});

describe('status-list/purpose-array-list', () => {
  const input = inputOf('status-list/purpose-array-list');
  const credential = input.credential as Credential;
  const issuer = (inputOf('status-list/active-credential').credential as Credential).issuer;

  it("is a positive vector carrying an active delegation from the category's issuer, with a Bitstring Status List entry", () => {
    expect(byId('status-list/purpose-array-list').expected).toBe('pass');
    expect(credential.issuer).toBe(issuer);
    expect(input.didDocuments).toEqual(inputOf('status-list/active-credential').didDocuments);
    expect(credential.credentialStatus).toMatchObject({ type: 'BitstringStatusListEntry', statusPurpose: 'revocation' });
  });

  it("carries its issuer's list for suspension and revocation, stating its URL as its id", () => {
    expect(listOf(input)).toMatchObject({
      id: credential.credentialStatus.statusListCredential,
      issuer,
      credentialSubject: { statusPurpose: ['suspension', 'revocation'] },
    });
  });

  it('states the array that status-list/purpose-array-2021-list states on a StatusList2021 list, where it is refused', () => {
    const refused = listOf(inputOf('status-list/purpose-array-2021-list'));
    expect(refused.type).toContain('StatusList2021Credential');
    expect(refused.credentialSubject.statusPurpose).toEqual(listOf(input).credentialSubject.statusPurpose);
  });

  it("reads the credential's bit as unset", async () => {
    expect(await bitOf(input)).toBe(false);
  });

  it("carries a proof that verifies against its issuer's DID document, which the vector supplies", async () => {
    expect(await proofOf(input)).toMatchObject({ valid: true });
  });

  it('is read by the reference adapter, which reports the credential active', async () => {
    expect(await new ReferenceConformanceAdapter().verifyStatusList(input)).toMatchObject({ outcome: 'pass' });
  });
});

/**
 * The reference adapter refusing the revoked credential's list, changed in one respect. A reason
 * quotes at most the first 64 characters of what the list states and names a value that is not a
 * string by its type. Only the list changes: the credential's issuer signed the entry.
 */
describe('the reference adapter, refusing a list', () => {
  const input = inputOf('status-list/revoked-credential');
  const credential = input.credential as Credential;
  const url = credential.credentialStatus.statusListCredential;
  const LONG = 'v'.repeat(100_000);
  const LONG_QUOTED = `"${'v'.repeat(64)}"...`;
  const named: [string, (list: List) => List, string][] = [
    ['issuer', (list) => ({ ...list, issuer: LONG }), `status list issuer ${LONG_QUOTED} is not the expected issuer ("${credential.issuer}")`],
    ['id', (list) => ({ ...list, id: LONG }), `status list id ${LONG_QUOTED} is not the URL it was fetched from ("${url}")`],
    [
      'id, when it is not a string,',
      (list) => ({ ...list, id: JSON.parse('{"toString":"x"}') as unknown }),
      `status list id of type object is not the URL it was fetched from ("${url}")`,
    ],
    [
      'statusPurpose',
      (list) => ({ ...list, credentialSubject: { ...list.credentialSubject, statusPurpose: LONG } }),
      `status list statusPurpose mismatch: the list's is ${LONG_QUOTED} and the entry's is "revocation"`,
    ],
  ];

  it.each(named)("names the list's %s as the rule quotes it", async (_member, change, reason) => {
    const changed = { ...input, statusLists: { ...input.statusLists, [url]: change(listOf(input)) } };
    const result = await new ReferenceConformanceAdapter().verifyStatusList(changed);
    expect(result).toEqual({ outcome: 'fail', detail: `Status check error: ${reason}` });
  });

  // Bitstring Status List v1.0 §2.2 lets a list state its purposes in an array only when it is typed
  // as one in both places it names, so a list typed so in one place alone is held to one string.
  const typedInOnePlace: [string, (list: List) => List][] = [
    ['its type alone', (list) => ({ ...list, type: ['VerifiableCredential', 'BitstringStatusListCredential'] })],
    ["its subject's type alone", (list) => ({ ...list, credentialSubject: { ...list.credentialSubject, type: 'BitstringStatusList' } })],
  ];

  it.each(typedInOnePlace)('holds a list typed as a Bitstring Status List in %s to one string', async (_place, typed) => {
    const serving = (list: List) => ({ ...input, statusLists: { ...input.statusLists, [url]: list } });
    const signed = listOf(input);
    const array = typed({ ...signed, credentialSubject: { ...signed.credentialSubject, statusPurpose: ['suspension', 'revocation'] } });
    expect(await new ReferenceConformanceAdapter().verifyStatusList(serving(array))).toEqual({
      outcome: 'fail',
      detail:
        'Status check error: status list statusPurpose is an array, which only a BitstringStatusListCredential with a ' +
        `BitstringStatusList subject may state (the entry's is "revocation")`,
    });
    // Stating one string, the list passes the rule, and is refused only on the proof the change broke.
    expect(await new ReferenceConformanceAdapter().verifyStatusList(serving(typed(signed)))).toEqual({
      outcome: 'fail',
      detail: expect.stringMatching(/^Status check error: status list .* proof rejected/),
    });
  });
});

describe('the status-list category', () => {
  const inputs = vectors.filter((v) => v.category === 'status-list').map((v) => v.input as StatusListInput);

  it("names, as each vector's server DID, the audience its credential is bound to", () => {
    expect(inputs).not.toHaveLength(0);
    for (const input of inputs) {
      const { audience } = (input.credential as Credential).credentialSubject.delegation.constraints;
      expect(input.serverDid).toBe(audience);
    }
  });

  it('names in each list subject the list itself names, or the URL it is served at when it states no id', () => {
    for (const input of inputs) {
      for (const [url, list] of Object.entries(input.statusLists) as [string, List][]) {
        expect(list.credentialSubject.id).toBe(`${(list.id as string | undefined) ?? url}#list`);
      }
    }
  });

  // Bitstring Status List v1.0 §2.2 requires at least 16KB of uncompressed bitstring, and its §3.2
  // validation refuses a list of fewer than 131,072 entries, so a shorter list fails a verifier
  // that follows it.
  it("carries lists of at least 131,072 entries, each with the context, types and date of its credential entry's data model", async () => {
    for (const input of inputs) {
      const { list: model, absent } = DATA_MODELS[(input.credential as Credential).credentialStatus.type]!;
      for (const list of Object.values(input.statusLists) as List[]) {
        expect(list).toMatchObject(model);
        for (const member of absent) expect(list).not.toHaveProperty(member);
        const bits = await BitstringManager.decode(list.credentialSubject.encodedList, statusListGzipCodec, statusListGzipCodec);
        expect(bits.getSize()).toBeGreaterThanOrEqual(131_072);
      }
    }
  });
});
