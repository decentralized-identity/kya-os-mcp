/**
 * `status-list/tampered-list` has to fail for one reason only: its list's proof.
 * It carries the revoked credential and the signed list from
 * `status-list/revoked-credential` with the revoked bit cleared, so a verifier
 * that reads the bits without checking the list's proof reports the credential
 * active and passes a vector it must reject.
 */

import { describe, it, expect } from 'vitest';
import { loadVectors } from '../loader.js';
import { BitstringManager } from '../../src/delegation/bitstring.js';
import { conformanceCompressor, conformanceDecompressor } from '../crypto-kit.js';
import { ReferenceConformanceAdapter } from '../reference-adapter.js';
import type { ConformanceVector, StatusListInput } from '../types.js';

interface List {
  credentialSubject: { encodedList: string } & Record<string, unknown>;
  [key: string]: unknown;
}
interface Credential {
  credentialStatus: { statusListCredential: string; statusListIndex: string };
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
const bitOf = async (input: StatusListInput): Promise<boolean> => {
  const manager = await BitstringManager.decode(
    listOf(input).credentialSubject.encodedList,
    conformanceCompressor,
    conformanceDecompressor,
  );
  return manager.getBit(Number((input.credential as Credential).credentialStatus.statusListIndex));
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
