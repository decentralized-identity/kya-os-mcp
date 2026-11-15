import { describe, expect, it } from 'vitest';
import { loadVectors } from '../loader.js';
import { ReferenceConformanceAdapter } from '../reference-adapter.js';
import type { ConformanceVector, StatusListInput } from '../types.js';
import { isIndexSet } from '../../src/delegation/bitstring.js';
import { parseStatusListIndex } from '../../src/utils/statuslist-bits.js';

const indexNames = ['index-suffix', 'index-fraction', 'index-space', 'index-number'];
const names = ['pinned-root-list', 'configured-service-list', 'unconfigured-service-list',
  'wrong-direction-service-map', 'owner-root-alias-no-id', 'owner-no-id-at-pinned-root-url', ...indexNames, 'index-leading-zeros',
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

  it("refuses the credential issuer's list without an id at the pinned root's URL for its missing id", async () => {
    const input = vectorOf('owner-no-id-at-pinned-root-url').input as StatusListInput;
    const [url] = Object.keys(input.statusLists);
    expect(await new ReferenceConformanceAdapter().verifyStatusList(input)).toEqual({
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
