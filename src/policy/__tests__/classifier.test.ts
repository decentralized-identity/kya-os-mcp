import { describe, it, expect } from 'vitest';
import { RiskClassifier } from '../classifier.js';

const c = new RiskClassifier();

describe('RiskClassifier', () => {
  it('merges partial hints over the heuristic base, ignoring undefined hint fields', () => {
    const hinted = new RiskClassifier({
      hints: {
        'vault.getSecrets': { severity: 'high', blastRadius: undefined },
        'db.drop': {
          reversibility: 'reversible', blastRadius: 'record', severity: 'low',
        },
      },
    });
    // Partial hint: heuristic read base with only the defined field overridden.
    const partial = hinted.classify({ toolName: 'vault.getSecrets', namespace: 'prod' });
    expect(partial).toEqual({
      reversibility: 'reversible', blastRadius: 'record', severity: 'high',
    });
    // Complete hint wins outright, even over a destructive verb.
    const complete = hinted.classify({ toolName: 'db.drop', namespace: 'prod' });
    expect(complete).toEqual({
      reversibility: 'reversible', blastRadius: 'record', severity: 'low',
    });
  });

  it('flags destructive verbs as irreversible/high (catastrophic in prod)', () => {
    const prod = c.classify({ toolName: 'db.drop', namespace: 'prod' });
    expect(prod.reversibility).toBe('irreversible');
    expect(prod.severity).toBe('catastrophic');

    const nonProd = c.classify({ toolName: 'db.delete', namespace: 'scratch' });
    expect(nonProd.reversibility).toBe('irreversible');
    expect(nonProd.severity).toBe('high');
  });

  it('treats reads as reversible/low', () => {
    expect(c.classify({ toolName: 'repo.read', namespace: 'x' }).severity).toBe('low');
    expect(c.classify({ toolName: 'files.list', namespace: 'x' }).reversibility).toBe('reversible');
  });

  it('classifies unknown verbs as unknown (fail-closed upstream)', () => {
    const r = c.classify({ toolName: 'frobnicate', namespace: 'x' });
    expect(r.severity).toBe('unknown');
    expect(r.reversibility).toBe('unknown');
  });

  it('honors a complete per-tool hint override', () => {
    const ch = new RiskClassifier({
      hints: { 'safe.delete': { reversibility: 'reversible', blastRadius: 'record', severity: 'low' } },
    });
    const r = ch.classify({ toolName: 'safe.delete', namespace: 'prod' });
    expect(r.severity).toBe('low');
    expect(r.reversibility).toBe('reversible');
  });
});
