import { describe, expect, it } from 'vitest';
import { proofKeyRelationshipVectors } from '../proof-key-relationship-vectors.js';
import { ReferenceConformanceAdapter } from '../reference-adapter.js';
import { runConformance } from '../runner.js';

describe('proof key retrieval conformance', () => {
  it('retrieves the key and verifies the signed artifact for every relationship case', async () => {
    const file = await proofKeyRelationshipVectors();
    const report = await runConformance(new ReferenceConformanceAdapter(), file.vectors);
    expect(report.results.filter(result => !result.ok)).toEqual([]);
  });

  it('does not accept bad relationship vectors just because their signatures are valid', async () => {
    const file = await proofKeyRelationshipVectors();
    const report = await runConformance(new ReferenceConformanceAdapter(), file.vectors.map(vector => {
      const input = structuredClone(vector.input) as { proof: { meta: { did: string; kid: string } }; didDocuments: Record<string, unknown>; keyId?: string };
      const good = (file.vectors[0]!.input as typeof input).didDocuments;
      input.didDocuments = good;
      input.keyId = input.proof.meta.kid;
      return { ...vector, input, expected: 'pass' as const };
    }));
    expect(report.results.filter(result => !result.ok)).toEqual([]);
  });
});
