import { describe, expect, it } from 'vitest';
import {
  AUDIT_ASSURANCE_PROFILES,
  assertAuditCapabilities,
  type AuditCapabilities,
} from '../assurance.js';

function capabilities(overrides: Partial<AuditCapabilities> = {}): AuditCapabilities {
  return {
    profile: 'AAP-2',
    recorderTopology: 'self-hosted',
    delivery: 'required',
    journalDurability: 'durable',
    atomicAppend: true,
    sourceHighWater: false,
    merkleCheckpoints: false,
    independentObservation: false,
    supportingAnchors: [],
    evidenceRetention: 'separate',
    ...overrides,
  };
}

describe('audit assurance capabilities', () => {
  it('defines orthogonal AAP-0 through AAP-4 profiles', () => {
    expect(Object.keys(AUDIT_ASSURANCE_PROFILES)).toEqual([
      'AAP-0',
      'AAP-1',
      'AAP-2',
      'AAP-3',
      'AAP-4',
    ]);
  });

  it('accepts a truthful chained profile', () => {
    expect(() => assertAuditCapabilities(capabilities())).not.toThrow();
  });

  it('rejects an ephemeral journal claiming AAP-2', () => {
    expect(() =>
      assertAuditCapabilities(capabilities({ journalDurability: 'ephemeral' })),
    ).toThrow(/durable journal/i);
  });

  it('fails closed on every capability understatement per profile level', () => {
    expect(() => assertAuditCapabilities(capabilities({ profile: 'AAP-0' }))).not.toThrow();
    expect(() => assertAuditCapabilities(
      capabilities({ profile: 'AAP-1', recorderTopology: 'none' }),
    )).toThrow(/recorder or verified mirror/);
    expect(() => assertAuditCapabilities(
      capabilities({ profile: 'AAP-1', journalDurability: 'none' }),
    )).toThrow(/recorder or verified mirror/);
    expect(() => assertAuditCapabilities(
      capabilities({ profile: 'AAP-1', journalDurability: 'ephemeral' }),
    )).not.toThrow();
    expect(() => assertAuditCapabilities(capabilities({ atomicAppend: false })))
      .toThrow(/atomic append/);
    expect(() => assertAuditCapabilities(capabilities({ delivery: 'best-effort' })))
      .toThrow(/best-effort/);
    expect(() => assertAuditCapabilities(
      capabilities({ profile: 'AAP-3', merkleCheckpoints: true }),
    )).toThrow(/Merkle checkpoints and source high-water/);
    expect(() => assertAuditCapabilities(
      capabilities({ profile: 'AAP-3', sourceHighWater: true }),
    )).toThrow(/Merkle checkpoints and source high-water/);
    expect(() => assertAuditCapabilities(capabilities({
      profile: 'AAP-4', merkleCheckpoints: true, sourceHighWater: true,
    }))).toThrow(/independent observation/);
    expect(() => assertAuditCapabilities(capabilities({
      profile: 'AAP-4',
      merkleCheckpoints: true,
      sourceHighWater: true,
      independentObservation: true,
    }))).toThrow(/supporting checkpoint receipt/);
    expect(() => assertAuditCapabilities(capabilities({
      profile: 'AAP-4',
      merkleCheckpoints: true,
      sourceHighWater: true,
      independentObservation: true,
      supportingAnchors: ['worm'],
    }))).not.toThrow();
  });

  it('does not treat a WORM or timestamp receipt as independent observation', () => {
    expect(() =>
      assertAuditCapabilities(
        capabilities({
          profile: 'AAP-4',
          merkleCheckpoints: true,
          sourceHighWater: true,
          supportingAnchors: ['worm', 'rfc3161'],
          independentObservation: false,
        }),
      ),
    ).toThrow(/independent observation/i);
  });
});
