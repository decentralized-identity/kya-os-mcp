import type { PolicyRequest, RiskAssessment } from './types.js';

/**
 * Resolved facts a host gathers before projecting a {@link PolicyRequest}.
 *
 * Intentionally decoupled from any one transport: the bundled middleware
 * resolves these from a delegation credential, but a gateway (or any other
 * host) can resolve them however it likes and reuse the same projection, so
 * every caller presents an identical request contract to the PolicyEngine.
 */
export interface PolicyRequestInput {
  /** The acting agent and, when known, the accountable party behind it. */
  principal: { agentDid: string; responsibleParty?: string };
  /** The resolved action (tool) being invoked. */
  action: { toolName: string };
  /** The resource the action targets. */
  resource: { namespace: string };
  /** Scopes the delegation chain grants the agent. */
  delegatedScopes: string[];
  /** Whether a prior step already matched the action to a delegated scope. */
  scopeMatched: boolean;
  /** Risk classification of the action. */
  risk: RiskAssessment;
  /** Approver DIDs gathered after a step-up round-trip. Defaults to none. */
  humanApprovals?: string[];
  /** Remaining CRISP budget, when a budget applies. */
  budgetRemaining?: number;
}

/**
 * Assemble resolved facts into the neutral {@link PolicyRequest} a PolicyEngine
 * evaluates. Pure and transport-agnostic: callers resolve the facts (principal,
 * scopes, risk) however their host dictates, and this renders the canonical
 * request shape — keeping the contract presented to the engine identical across
 * the bundled middleware, a gateway, and any other host.
 *
 * `responsibleParty` and `budgetRemaining` are emitted only when supplied, so
 * the request never carries undefined optional keys; `humanApprovals` defaults
 * to an empty list (the first-pass, pre-approval state).
 */
export function buildPolicyRequest(input: PolicyRequestInput): PolicyRequest {
  return {
    principal: {
      agentDid: input.principal.agentDid,
      ...(input.principal.responsibleParty
        ? { responsibleParty: input.principal.responsibleParty }
        : {}),
    },
    action: { toolName: input.action.toolName },
    resource: { namespace: input.resource.namespace },
    context: {
      delegatedScopes: input.delegatedScopes,
      scopeMatched: input.scopeMatched,
      humanApprovals: input.humanApprovals ?? [],
      ...input.risk,
      ...(input.budgetRemaining !== undefined
        ? { budgetRemaining: input.budgetRemaining }
        : {}),
    },
  };
}
