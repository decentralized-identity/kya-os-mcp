import type { PolicyEngine } from './engine.js';
import type { PolicyRequest, PolicyDecision } from './types.js';

export interface DefaultPolicyConfig {
  /** Distinct approvals required for a step-up. Default 1. */
  stepUpQuorum?: number;
  /** Allowed approver DIDs; empty/undefined = any identity may approve. */
  stepUpApprovers?: string[];
}

/**
 * Zero-dependency reference PolicyEngine. Fail-closed:
 *  - scope not matched          → deny
 *  - unclassified (unknown)     → deny
 *  - irreversible/high/catastrophic → step_up (or allow once quorum met)
 *  - otherwise                  → allow
 *
 * The quorum counts DISTINCT approver DIDs from `context.humanApprovals`, and
 * only those on `stepUpApprovers` when it is set. Feed `humanApprovals` from
 * `verifyApprovalQuorum(...).approvers`, never from unverified input.
 *
 * Production deployments are expected to swap in an OPA/Rego or Cedar adapter;
 * this engine encodes the same fail-closed posture as a sensible default.
 */
export class DefaultPolicyEngine implements PolicyEngine {
  constructor(private readonly cfg: DefaultPolicyConfig = {}) {}

  async evaluate(req: PolicyRequest): Promise<PolicyDecision> {
    const { severity, reversibility, scopeMatched, humanApprovals } = req.context;

    if (!scopeMatched) {
      return { decision: 'deny', reason: 'scope_not_matched' };
    }
    if (severity === 'unknown' || reversibility === 'unknown') {
      return { decision: 'deny', reason: 'unclassified_high_risk' };
    }

    const dangerous =
      reversibility === 'irreversible' ||
      severity === 'catastrophic' ||
      severity === 'high';

    if (dangerous) {
      const n = this.cfg.stepUpQuorum ?? 1;
      // Distinct DIDs only, and only allowlisted ones when an allowlist is set:
      // one approver named twice is not two approvals.
      const allowed = this.cfg.stepUpApprovers ?? [];
      const approvers = new Set(
        humanApprovals.filter((did) => allowed.length === 0 || allowed.includes(did)),
      );
      if (approvers.size >= n) {
        return { decision: 'allow' };
      }
      return {
        decision: 'step_up',
        quorum: { n, approvers: allowed },
        reason: 'destructive_action_requires_approval',
      };
    }

    return { decision: 'allow' };
  }
}
