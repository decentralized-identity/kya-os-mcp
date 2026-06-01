import type { NeedsAuthorizationError } from '../types/protocol.js';
import type { VerifyDelegationResult } from '../auth/types.js';
import type { AuthorizationRequirement, ToolProtection } from './requirement.js';

/**
 * Parameters handed to an adapter when it initiates an authorization flow for a
 * protected tool. The adapter turns these into a `needs_authorization`
 * challenge the agent surfaces to the user.
 */
export interface FlowParams {
  /** The protection (tool + requirement) that triggered the flow. */
  protection: ToolProtection;
  /** The agent DID requesting access. */
  agentDid: string;
  /** Where the authorization server should return control after consent. */
  redirectUri: string;
  /** Opaque value echoed back to correlate the result with this request. */
  state: string;
}

/**
 * The authorization-server port.
 *
 * One adapter per authorization *method* (`type`). KYA-OS owns the neutral
 * requirement/result vocabulary; an adapter renders the method-specific
 * behavior: decide whether it applies, produce a challenge, verify a result.
 * Implement this to back authorization with a generic OIDC provider (a
 * reference adapter ships in this package), or any downstream identity system.
 * The shape mirrors the policy seam: a small, neutral interface with a
 * reference implementation and pluggable downstream adapters.
 */
export interface AuthorizationServerAdapter {
  /** The {@link AuthorizationRequirement} discriminant this adapter handles. */
  readonly type: AuthorizationRequirement['type'];

  /** Whether this adapter must run for the given tool protection. */
  isRequired(protection: ToolProtection): boolean;

  /** Produce a `needs_authorization` challenge for an unmet requirement. */
  initiateFlow(params: FlowParams): Promise<NeedsAuthorizationError>;

  /** Verify a returned authorization result into a delegation outcome. */
  verifyAuthorization(flowState: string, result: unknown): Promise<VerifyDelegationResult>;
}

/**
 * Shared dispatch predicate: a protection is handled by the adapter whose
 * `type` equals the protection's requirement discriminant. Every adapter's
 * `isRequired` is built on this, so dispatch stays consistent across adapters
 * (DRY) and the registry can route a protection to exactly one adapter.
 */
export function requirementMatchesAdapter(
  adapterType: AuthorizationRequirement['type'],
  protection: ToolProtection,
): boolean {
  return protection.requirement.type === adapterType;
}
