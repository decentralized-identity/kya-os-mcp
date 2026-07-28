/**
 * Conformance harness TDD/regression test.
 *
 * The reference implementation MUST pass 100% of positive vectors and reject
 * 100% of negative vectors. This test runs the bundled vectors through the
 * reference adapter — the same path `npm run conformance` and CI use — and fails
 * the build on ANY mismatch, so a regression in a verify primitive surfaces here.
 */

import { describe, it, expect } from 'vitest';
import { loadVectors } from '../loader.js';
import { runConformance } from '../runner.js';
import { ReferenceConformanceAdapter } from '../reference-adapter.js';
import type { VectorCategory } from '../types.js';

const REQUIRED_CATEGORIES: VectorCategory[] = [
  'signed-proof',
  'delegation-chain',
  'status-list',
  'did-key-resolution',
  'did-web-resolution',
  'card-proof',
  'entity-card',
  'audit-integrity',
  'negotiation',
];

describe('KYA-OS conformance — reference implementation', () => {
  const vectors = loadVectors();

  it('covers every required category with both positive and negative vectors', () => {
    for (const category of REQUIRED_CATEGORIES) {
      const inCategory = vectors.filter((v) => v.category === category);
      expect(inCategory.length, `category ${category} has vectors`).toBeGreaterThan(0);
      expect(
        inCategory.some((v) => v.expected === 'pass'),
        `category ${category} has a positive vector`,
      ).toBe(true);
      expect(
        inCategory.some((v) => v.expected === 'fail'),
        `category ${category} has a negative vector`,
      ).toBe(true);
    }
  });

  it('passes 100% of positive vectors and rejects 100% of negative vectors', async () => {
    const report = await runConformance(new ReferenceConformanceAdapter(), vectors);
    const mismatches = report.results.filter((r) => !r.ok);
    // Surface a readable diff if anything fails.
    expect(
      mismatches.map((m) => `${m.id}: expected ${m.expected}, got ${m.actual} (${m.detail ?? ''})`),
    ).toEqual([]);
    expect(report.allMatched).toBe(true);
    expect(report.passed).toBe(vectors.length);
  });

  it('the runner exits clean only when every vector matches (allMatched invariant)', async () => {
    const report = await runConformance(new ReferenceConformanceAdapter(), vectors);
    expect(report.failed).toBe(0);
  });
});
