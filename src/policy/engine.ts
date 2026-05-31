import type { PolicyRequest, PolicyDecision } from './types.js';

/**
 * Policy-as-Code decision port. KYA-OS owns the fact/context projection
 * (PolicyRequest) and the step-up orchestration; the engine renders the
 * allow / deny / step_up decision. Implement this interface to back the gate
 * with OPA/Rego, Cedar, or any other policy evaluator. A zero-dependency
 * DefaultPolicyEngine ships in this package.
 */
export interface PolicyEngine {
  evaluate(req: PolicyRequest): Promise<PolicyDecision>;
}
