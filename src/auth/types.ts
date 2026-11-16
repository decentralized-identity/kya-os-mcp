/**
 * Authorization types for the auth module.
 *
 * Minimal interfaces required by the auth handshake.
 */

import type { DelegationRecord } from '../types/protocol.js';
import type { RefusalCoding } from '../delegation/vc-verifier.types.js';

/**
 * What a `DelegationVerifier` answers, and what the handshake reads it as. A refusal may carry its
 * `code`, a code of `REFUSAL_CODES`, which the handshake hands to the operator beside its reason;
 * one that states none is `delegation_invalid`. Its `transient` is taken from the code.
 */
export interface VerifyDelegationResult extends RefusalCoding {
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
}

export interface DelegationVerifier {
  verify(agentDid: string, scopes: string[]): Promise<VerifyDelegationResult>;
}
