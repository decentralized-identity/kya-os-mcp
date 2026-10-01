import { describe, it, expect } from 'vitest';
import { DefaultPolicyEngine } from '../default-engine.js';
import type { PolicyRequest, RiskAssessment } from '../types.js';

function req(over: Partial<RiskAssessment> & { scopeMatched?: boolean; humanApprovals?: string[] } = {}): PolicyRequest {
  const { scopeMatched = true, humanApprovals = [], ...risk } = over;
  return {
    principal: { agentDid: 'did:example:agent' },
    action: { toolName: 't' },
    resource: { namespace: 'n' },
    context: {
      delegatedScopes: [],
      scopeMatched,
      humanApprovals,
      reversibility: 'reversible',
      blastRadius: 'record',
      severity: 'low',
      ...risk,
    },
  };
}

describe('DefaultPolicyEngine', () => {
  const engine = new DefaultPolicyEngine();

  it('denies when scope is not matched', async () => {
    expect((await engine.evaluate(req({ scopeMatched: false }))).decision).toBe('deny');
  });

  it('denies unclassified (unknown) actions — fail-closed', async () => {
    expect((await engine.evaluate(req({ severity: 'unknown' }))).decision).toBe('deny');
    expect((await engine.evaluate(req({ reversibility: 'unknown' }))).decision).toBe('deny');
  });

  it('requires step-up for irreversible/catastrophic actions with no approvals', async () => {
    const d = await engine.evaluate(req({ reversibility: 'irreversible', severity: 'catastrophic' }));
    expect(d.decision).toBe('step_up');
    if (d.decision === 'step_up') expect(d.quorum.n).toBe(1);
  });

  it('allows a dangerous action once quorum is met', async () => {
    const d = await engine.evaluate(
      req({ severity: 'catastrophic', reversibility: 'irreversible', humanApprovals: ['did:example:approver'] }),
    );
    expect(d.decision).toBe('allow');
  });

  it('allows an in-scope reversible low-severity action', async () => {
    expect((await engine.evaluate(req())).decision).toBe('allow');
  });

  it('honors a configured quorum greater than 1', async () => {
    const e2 = new DefaultPolicyEngine({ stepUpQuorum: 2 });
    const one = await e2.evaluate(
      req({ reversibility: 'irreversible', severity: 'high', humanApprovals: ['did:a'] }),
    );
    expect(one.decision).toBe('step_up');
    const two = await e2.evaluate(
      req({ reversibility: 'irreversible', severity: 'high', humanApprovals: ['did:a', 'did:b'] }),
    );
    expect(two.decision).toBe('allow');
  });

  describe('step-up quorum counts distinct, allowed approvers', () => {
    const destructive = (humanApprovals: string[] = []) =>
      req({ reversibility: 'irreversible', severity: 'catastrophic', humanApprovals });

    it('counts distinct approvers: a duplicated approver does not satisfy n = 2', async () => {
      const engine = new DefaultPolicyEngine({ stepUpQuorum: 2 });
      expect((await engine.evaluate(destructive(['did:alice', 'did:alice']))).decision).toBe('step_up');
      expect((await engine.evaluate(destructive(['did:alice', 'did:bob', 'did:alice']))).decision).toBe('allow');
    });

    it('counts only approvers on the stepUpApprovers allowlist', async () => {
      const engine = new DefaultPolicyEngine({ stepUpQuorum: 1, stepUpApprovers: ['did:admin'] });
      const outsider = await engine.evaluate(destructive(['did:mallory']));
      expect(outsider).toMatchObject({ decision: 'step_up', quorum: { n: 1, approvers: ['did:admin'] } });
      expect((await engine.evaluate(destructive(['did:mallory', 'did:admin']))).decision).toBe('allow');
    });
  });
});
