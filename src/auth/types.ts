/**
 * Authorization types for the auth module.
 *
 * Minimal interfaces required by the auth handshake.
 */

import type { DelegationRecord, NeedsAuthorizationError } from '../types/protocol.js';
import type { RefusalCode } from '../refusal-codes.js';

/**
 * What a `DelegationVerifier` answers. A refusal may carry its `code`, a code of `REFUSAL_CODES`,
 * which the handshake hands to the operator beside its reason; one that states none, or a string
 * that is no code of the catalog, is `delegation_invalid`. Its `transient` is taken from the code.
 */
export interface VerifyDelegationResult {
  valid: boolean;
  delegation?: DelegationRecord;
  credential?: {
    agent_did: string;
    user_did: string;
    scopes: string[];
    authorization: {
      type:
        | 'oauth'
        | 'oauth2'
        | 'password'
        | 'credential'
        | 'webauthn'
        | 'siwe'
        | 'none';
      provider?: string;
      credentialType?: string;
      rpId?: string;
      userVerification?: 'required' | 'preferred' | 'discouraged';
      chainId?: number;
      domain?: string;
    };
    [key: string]: unknown;
  };
  reason?: string;
  cached?: boolean;
  /**
   * The code of a refusal. Typed `string`, so a code read from a variable or from JSON compiles;
   * the handshake reads only a code of `REFUSAL_CODES`.
   */
  code?: string;
  /** Not read: the handshake takes whether a refusal is transient from its code. */
  transient?: boolean;
}

export interface DelegationVerifier {
  verify(agentDid: string, scopes: string[]): Promise<VerifyDelegationResult>;
}

/** An agent's reputation as the reputation service reports it: `score` is `null` for an agent it has no history of. */
export interface AgentReputation {
  agentDid: string;
  score: number | null;
  totalInteractions: number;
  successRate: number;
  riskLevel: 'low' | 'medium' | 'high' | 'unknown';
  updatedAt: number;
}

/**
 * What `verifyOrHints` comes to: whether the agent is authorized, with the delegation that
 * authorizes it, or else the authorization error to send the client, with a reason for the operator.
 */
export interface VerifyOrHintsResult {
  authorized: boolean;
  delegation?: DelegationRecord;
  credential?: {
    agent_did: string;
    user_did: string;
    scopes: string[];
    authorization: {
      type:
        | 'oauth'
        | 'oauth2'
        | 'password'
        | 'credential'
        | 'webauthn'
        | 'siwe'
        | 'none';
      provider?: string;
      credentialType?: string;
      rpId?: string;
      userVerification?: 'required' | 'preferred' | 'discouraged';
      chainId?: number;
      domain?: string;
    };
    [key: string]: unknown;
  };
  authError?: NeedsAuthorizationError;
  reputation?: AgentReputation;
  reason?: string;
  /**
   * The code of the delegation verifier's refusal, when it refused: the code its answer stated,
   * `delegation_invalid` when it stated none, or `runtime_error` when its answer could not be read
   * or it threw, unless what it threw is a `RefusalError`, whose code it is.
   * For the operator, as `reason` is: `authError`, which the client receives, does not carry it.
   */
  code?: RefusalCode;
  /** Whether {@link code} is transient: the same agent may be authorized when it asks again. */
  transient?: boolean;
}
