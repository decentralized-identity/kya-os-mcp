/**
 * Policy subsystem types (KYA-OS Policy-as-Code seam).
 *
 * KYA-OS projects a stable fact/context shape; a pluggable PolicyEngine renders
 * the decision. These types are the contract — engine implementations (built-in,
 * or adapters for OPA/Rego, Cedar, etc.) consume PolicyRequest and return
 * PolicyDecision.
 */

export type Reversibility =
  | 'reversible'
  | 'reversible-with-effort'
  | 'irreversible'
  | 'unknown';

export type BlastRadius =
  | 'record'
  | 'resource'
  | 'collection'
  | 'tenant'
  | 'environment'
  | 'global'
  | 'unknown';

export type Severity = 'none' | 'low' | 'medium' | 'high' | 'catastrophic' | 'unknown';

export interface RiskAssessment {
  reversibility: Reversibility;
  blastRadius: BlastRadius;
  severity: Severity;
}

export interface PolicyRequest {
  principal: { agentDid: string; responsibleParty?: string };
  action: { toolName: string };
  resource: { namespace: string };
  context: {
    /** Union of delegation.scopes ∪ constraints.scopes ∪ matched crisp scopes. */
    delegatedScopes: string[];
    /** Live CRISP budget remaining, if a budget applies. */
    budgetRemaining?: number;
    /** Whether the delegated scope already authorized this action. */
    scopeMatched: boolean;
    /** Approver DIDs collected after a step-up round-trip (empty on first pass). */
    humanApprovals: string[];
  } & RiskAssessment;
}

export type PolicyDecision =
  | { decision: 'allow' }
  | { decision: 'deny'; reason: string }
  | { decision: 'step_up'; quorum: { n: number; approvers: string[] }; reason: string };
