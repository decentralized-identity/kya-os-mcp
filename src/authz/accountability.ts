import type { DelegationCredentialSubject } from '../types/protocol.js';
import type { PolicyRequestInput } from '../policy/projection.js';

/**
 * The accountability chain behind an agent action: agent -> accountable admin
 * -> user -> intent. It is a read-only projection of a delegation credential
 * subject, assembled so policy enforcement has auditable provenance for who is
 * answerable for an action.
 *
 * `accountableAdminDid` is the organization/responsible-admin rung. Today it is
 * sourced from the credential `controller`; when a dedicated org-admin identity
 * lands it will be populated from there instead. `orgRootDid` is a
 * forward-compatible slot that stays undefined until the Org Root DID work
 * exists — defined now so the contract is stable for downstream consumers.
 */
export interface AccountabilityContext {
  /** The agent acting (delegation subject). */
  agentDid: string;
  /** The accountable admin / responsible party, when known. */
  accountableAdminDid?: string;
  /** The end user on whose behalf the agent acts, when known. */
  userDid?: string;
  /** The organization root identity. Forward-compatible; unpopulated today. */
  orgRootDid?: string;
  /** The delegated scopes — the coarse statement of intent. */
  scopes: string[];
}

/** Project the accountability chain from a delegation credential subject. */
export function projectAccountability(
  subject: DelegationCredentialSubject,
): AccountabilityContext {
  const { delegation } = subject;
  const context: AccountabilityContext = {
    agentDid: delegation.subjectDid,
    scopes: delegation.scopes ?? [],
  };
  if (delegation.controller) context.accountableAdminDid = delegation.controller;
  if (delegation.userDid) context.userDid = delegation.userDid;
  // orgRootDid intentionally left undefined until Org Root DID exists.
  return context;
}

/**
 * Map an accountability context onto the policy principal so a PolicyEngine can
 * gate on accountability. The accountable admin becomes `responsibleParty`,
 * which is emitted only when present (matching buildPolicyRequest's contract).
 */
export function accountabilityToPolicyPrincipal(
  context: AccountabilityContext,
): PolicyRequestInput['principal'] {
  return {
    agentDid: context.agentDid,
    ...(context.accountableAdminDid
      ? { responsibleParty: context.accountableAdminDid }
      : {}),
  };
}
