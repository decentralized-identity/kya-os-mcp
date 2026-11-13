import { describe, expect, it } from 'vitest';
import { loadVectors } from '../loader.js';
import { ReferenceConformanceAdapter } from '../reference-adapter.js';
import type { ConformanceVector, StatusListInput } from '../types.js';
import { parseStatusListIndex } from '../../src/utils/statuslist-bits.js';

const indexNames = ['index-suffix', 'index-fraction', 'index-space', 'index-number'];
const names = ['pinned-root-list', 'configured-service-list', 'unconfigured-service-list',
  'wrong-direction-service-map', 'owner-root-alias-no-id', 'owner-no-id-at-pinned-root-url', ...indexNames, 'index-leading-zeros'];
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
