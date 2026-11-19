import { describe, expect, it } from 'vitest';
import { loadVectors } from '../loader.js';
import { ReferenceConformanceAdapter } from '../reference-adapter.js';
import type { ConformanceVector, StatusListInput } from '../types.js';
import { BitstringManager, isIndexSet } from '../../src/delegation/bitstring.js';
import { statusListGzipCodec } from '../../src/utils/statuslist-gzip.js';
import { parseStatusListIndex } from '../../src/utils/statuslist-bits.js';

const indexNames = ['index-suffix', 'index-fraction', 'index-space', 'index-number'];
const keeperNames = ['pinned-root-list', 'root-list-at-issuer-url', 'configured-service-list', 'configured-origin-list',
  'lookalike-origin-list', 'unconfigured-service-list', 'service-list-at-unbound-url', 'issuer-list-at-bound-url',
  'configured-over-root-list'];
const names = [...keeperNames, 'owner-root-alias-no-id', 'pinned-root-own-no-id', 'pinned-root-no-id-for-delegate', 'owner-no-id-at-pinned-root-url', ...indexNames, 'index-leading-zeros',
  'status-size-two-bits', 'status-size-zero', 'status-size-one'];
const vectors = loadVectors();
const vectorOf = (name: string): ConformanceVector => {
  const vector = vectors.find((item) => item.id === `status-list/${name}`);
  if (!vector) throw new Error(`missing vector status-list/${name}`);
  return vector;
};

describe('positive authority and strict index contract', () => {
  it.each(names)('%s', async (name) => {
    const vector = vectorOf(name);
    const result = await new ReferenceConformanceAdapter().verifyStatusList(vector.input as StatusListInput);
    expect(result.outcome).toBe(vector.expected);
  });

  it("refuses the credential issuer's list without an id at the URL the pinned root's credential names, for its signer", async () => {
    const input = vectorOf('owner-no-id-at-pinned-root-url').input as StatusListInput;
    const [url] = Object.keys(input.statusLists);
    expect(input.trustedRootStatusList).toBe(url);
    expect(await new ReferenceConformanceAdapter().verifyStatusList(input)).toEqual({
      outcome: 'fail',
      detail:
        `Status check error: status list issuer "${(input.credential as { issuer: string }).issuer}" does not keep this list's URL: ` +
        `"${input.trustedRootIssuer}" does, as the pinned root whose own credential names it`,
    });
  });

  it("reads the credential issuer's list without an id where that issuer is also the pinned root and its credential's URL is not named", async () => {
    const input = vectorOf('owner-root-alias-no-id').input as StatusListInput;
    expect(input.trustedRootIssuer).toBe((input.credential as { issuer: string }).issuer);
    expect(input).not.toHaveProperty('trustedRootStatusList');
    expect(Object.values(input.statusLists)[0]).not.toHaveProperty('id');
  });

  it("reads the pinned root's list without an id for the root's own credential, and refuses the same list for a delegate's", async () => {
    const own = vectorOf('pinned-root-own-no-id').input as StatusListInput;
    const delegates = vectorOf('pinned-root-no-id-for-delegate').input as StatusListInput;
    const [url] = Object.keys(own.statusLists);
    expect(own.trustedRootIssuer).toBe((own.credential as { issuer: string }).issuer);
    expect(own.trustedRootStatusList).toBe(url);
    expect(Object.values(own.statusLists)[0]).not.toHaveProperty('id');
    // The neighbour differs in the credential alone, which another party issued.
    const { credential: _own, ...rest } = own;
    const { credential, ...delegatesRest } = delegates;
    expect(delegatesRest).toEqual(rest);
    expect((credential as { issuer: string }).issuer).not.toBe(own.trustedRootIssuer);
    expect((credential as { credentialStatus: { statusListCredential: string } }).credentialStatus.statusListCredential).toBe(url);
    expect(await new ReferenceConformanceAdapter().verifyStatusList(delegates)).toEqual({
      outcome: 'fail',
      detail: `Status check error: status list states no id, but must state the URL it was fetched from ("${url}")`,
    });
  });

  // The adapter takes the index through the library's parser, so its refusal is the parser's.
  it.each(indexNames)('%s is refused with the reason the index parser gives', async (name) => {
    const input = vectorOf(name).input as StatusListInput;
    const index: unknown = (input.credential as { credentialStatus: { statusListIndex: unknown } }).credentialStatus.statusListIndex;
    let refusal = '';
    try {
      parseStatusListIndex(index);
    } catch (error) {
      refusal = (error as Error).message;
    }
    expect(refusal).toMatch(/^Invalid statusListIndex /);
    expect(await new ReferenceConformanceAdapter().verifyStatusList(input)).toEqual({
      outcome: 'fail',
      detail: `Status check error: ${refusal}`,
    });
  });
});

/**
 * The keeper vectors share one credential, one list URL and a clear list, and differ in who signed
 * the list and in the configuration, so each verdict is the keeper rule's alone: the reference
 * adapter refuses each negative one for its signer, naming the keeper and why it keeps the URL.
 */
describe('the one keeper of a status-list URL', () => {
  const inputOf = (name: string) => vectorOf(name).input as StatusListInput;
  const signerOf = (input: StatusListInput) => (Object.values(input.statusLists)[0] as { issuer: string }).issuer;
  const issuerOf = (input: StatusListInput) => (input.credential as { issuer: string }).issuer;

  it('holds a clear list, stating its id, in every keeper vector, so nothing but the signer decides', async () => {
    for (const name of keeperNames) {
      const input = inputOf(name);
      const [[url, list]] = Object.entries(input.statusLists) as [[string, { id: string; credentialSubject: { encodedList: string } }]];
      expect(list.id, name).toBe(url);
      expect(await isIndexSet(list.credentialSubject.encodedList, 7), name).toBe(false);
    }
  });

  it.each([
    ['root-list-at-issuer-url', 'credential', 'the issuer of the credential'],
    ['lookalike-origin-list', 'credential', 'the issuer of the credential'],
    ['unconfigured-service-list', 'credential', 'the issuer of the credential'],
    ['service-list-at-unbound-url', 'credential', 'the issuer of the credential'],
    ['issuer-list-at-bound-url', 'service', 'the issuer statusListIssuers binds this URL to'],
    ['configured-over-root-list', 'service', 'the issuer statusListIssuers binds this URL to'],
  ] as const)('%s is refused for its signer, the URL being kept by the %s issuer', async (name, keptBy, as) => {
    const input = inputOf(name);
    const keeper = keptBy === 'credential' ? issuerOf(input) : Object.keys(input.statusListIssuers ?? {})[0]!;
    expect(signerOf(input)).not.toBe(keeper);
    expect(await new ReferenceConformanceAdapter().verifyStatusList(input)).toEqual({
      outcome: 'fail',
      detail: `Status check error: status list issuer "${signerOf(input)}" does not keep this list's URL: "${keeper}" does, as ${as}`,
    });
  });

  it('pairs each refusal with a vector that reads the same list or the same configuration', () => {
    // The root's list is read where its credential names the URL, and refused where it names another or the configuration binds the URL.
    expect(inputOf('root-list-at-issuer-url').statusLists).toEqual(inputOf('pinned-root-list').statusLists);
    expect(inputOf('configured-over-root-list').statusLists).toEqual(inputOf('pinned-root-list').statusLists);
    expect(inputOf('configured-over-root-list').trustedRootStatusList).toBe(inputOf('pinned-root-list').trustedRootStatusList);
    // The service's list is read at a bound URL or origin, and refused where the binding is another URL, a look-alike origin, or absent.
    for (const name of ['configured-origin-list', 'lookalike-origin-list', 'unconfigured-service-list', 'service-list-at-unbound-url']) {
      expect(inputOf(name).statusLists, name).toEqual(inputOf('configured-service-list').statusLists);
    }
    expect(inputOf('issuer-list-at-bound-url').statusListIssuers).toEqual(inputOf('configured-service-list').statusListIssuers);
    const [url] = Object.keys(inputOf('configured-service-list').statusLists);
    const [origin] = Object.values(inputOf('configured-origin-list').statusListIssuers ?? {})[0]!;
    const [lookalike] = Object.values(inputOf('lookalike-origin-list').statusListIssuers ?? {})[0]!;
    expect(url!.startsWith(`${origin}/`)).toBe(true);
    expect(url!.startsWith(lookalike!) && !url!.startsWith(`${lookalike}/`)).toBe(true);
  });
});

describe('the size of a status entry', () => {
  const entryOf = (input: StatusListInput) =>
    (input.credential as { credentialStatus: { statusListCredential: string; statusSize?: unknown } }).credentialStatus;
  /** Whether bit `index` is set in the list the vector serves for its credential. */
  const bitOf = (input: StatusListInput, index: number) => {
    const list = input.statusLists[entryOf(input).statusListCredential] as { credentialSubject: { encodedList: string } };
    return isIndexSet(list.credentialSubject.encodedList, index);
  };

  it('status-size-two-bits holds an entry of two bits at index 7 whose value is set, with bit 7 clear', async () => {
    const input = vectorOf('status-size-two-bits').input as StatusListInput;
    expect(entryOf(input).statusSize).toBe(2);
    expect([await bitOf(input, 7), await bitOf(input, 14), await bitOf(input, 15)]).toEqual([false, true, true]);
    expect(await new ReferenceConformanceAdapter().verifyStatusList(input)).toEqual({
      outcome: 'fail',
      detail: "Status check error: the entry's statusSize is 2, and only an entry of one bit is read",
    });
  });

  it('status-size-zero holds a statusSize that is not greater than zero, over a clear list', async () => {
    const input = vectorOf('status-size-zero').input as StatusListInput;
    expect(entryOf(input).statusSize).toBe(0);
    expect(await bitOf(input, 7)).toBe(false);
    expect(await new ReferenceConformanceAdapter().verifyStatusList(input)).toEqual({
      outcome: 'fail',
      detail: "Status check error: the entry's statusSize (0) is not an integer greater than zero",
    });
  });

  it('status-size-one states the size an entry has when it states none, and is read at its index', async () => {
    const input = vectorOf('status-size-one').input as StatusListInput;
    expect(entryOf(input).statusSize).toBe(1);
    expect([await bitOf(input, 7), await bitOf(input, 14), await bitOf(input, 15)]).toEqual([false, true, true]);
  });
});

/**
 * How a list is written and how many entries it holds (SPEC.md §6.6 and §6.7, suite >= 1.12.0). Each
 * vector serves the credential issuer's own list, so only the encoding, the length or the index decides.
 */
describe('the encoding and length of a status list', () => {
  const inputOf = (name: string) => vectorOf(name).input as StatusListInput;
  const listOf = (name: string) =>
    Object.values(inputOf(name).statusLists)[0] as { type: string[]; credentialSubject: { encodedList: string } };
  const indexOf = (name: string) =>
    (inputOf(name).credential as { credentialStatus: { statusListIndex: string } }).credentialStatus.statusListIndex;
  const entriesOf = async (encodedList: string) =>
    (await BitstringManager.decode(encodedList, statusListGzipCodec, statusListGzipCodec)).getSize();

  it('legacy-encoding-2021 serves a StatusList2021 list in padded base64 with no multibase prefix', async () => {
    const { type, credentialSubject } = listOf('legacy-encoding-2021');
    expect(type).toContain('StatusList2021Credential');
    expect(credentialSubject.encodedList).toMatch(/^H4sI[A-Za-z0-9+/]*[+/][A-Za-z0-9+/]*=+$/);
    const written = `u${Buffer.from(credentialSubject.encodedList, 'base64').toString('base64url')}`;
    expect(await entriesOf(written)).toBe(262144);
    expect(await isIndexSet(credentialSubject.encodedList, 7)).toBe(false);
  });

  it('index-past-minimum names entry 131,072 of a list of 262,144, clear there and set at 0', async () => {
    const { encodedList } = listOf('index-past-minimum').credentialSubject;
    expect(indexOf('index-past-minimum')).toBe('131072');
    expect(await entriesOf(encodedList)).toBe(262144);
    expect([await isIndexSet(encodedList, 131072), await isIndexSet(encodedList, 0)]).toEqual([false, true]);
  });

  it('index-past-end names the same entry of a list of 131,072, past its end', async () => {
    const { encodedList } = listOf('index-past-end').credentialSubject;
    expect(indexOf('index-past-end')).toBe('131072');
    expect(await entriesOf(encodedList)).toBe(131072);
    await expect(isIndexSet(encodedList, 131072)).rejects.toThrow('Bit index 131072 out of range for the status list');
  });

  it('short-list serves a list of 16 entries, clear at the index 7 its credential names', async () => {
    const { encodedList } = listOf('short-list').credentialSubject;
    expect(indexOf('short-list')).toBe('7');
    expect(await entriesOf(encodedList)).toBe(16);
    expect(await isIndexSet(encodedList, 7)).toBe(false);
  });
});
