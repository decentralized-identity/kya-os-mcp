/**
 * Delegation Issuer Factory
 *
 * Creates a DelegationCredentialIssuer from an identity config.
 * Supports two credential formats:
 *   - Embedded proof (Ed25519Signature2020) — VC as JSON with proof attached
 *   - VC-JWT — compact JWT string (header.payload.signature)
 *
 * Used by both consent-server.ts and tests.
 *
 * Related Spec: MCP-I §3.1 (VC structure), §4.1 (DelegationRecord)
 */

import { DelegationCredentialIssuer } from '../../../src/delegation/vc-issuer.js';
import type { VCSigningFunction } from '../../../src/delegation/vc-issuer.js';
import type { Proof } from '../../../src/types/protocol.js';
import type { CryptoProvider } from '../../../src/providers/base.js';
import { base64urlEncodeFromBytes } from '../../../src/utils/base64.js';
import { createUnsignedVCJWT, completeVCJWT } from '../../../src/delegation/utils.js';

export type DelegationFormat = 'embedded-proof' | 'vc-jwt';

export interface AgentIdentityConfig {
  did: string;
  kid: string;
  privateKey: string;
  publicKey: string;
}

export interface DelegationIssuerFactory {
  issuer: DelegationCredentialIssuer;
  identity: AgentIdentityConfig;
  /**
   * Issue a delegation as a VC-JWT string.
   * Uses createUnsignedVCJWT → Ed25519 sign → completeVCJWT,
   * matching the pattern used by mcp-i-cloudflare's consent service.
   */
  issueAsJWT: (delegation: Parameters<DelegationCredentialIssuer['createAndIssueDelegation']>[0], options?: Parameters<DelegationCredentialIssuer['createAndIssueDelegation']>[1]) => Promise<string>;
}

export function createDelegationIssuerFromIdentity(
  crypto: CryptoProvider,
  identity: AgentIdentityConfig,
): DelegationIssuerFactory {
  const signingFunction: VCSigningFunction = async (
    canonicalVC: string,
    _issuerDid: string,
    kid: string,
  ): Promise<Proof> => {
    const data = new TextEncoder().encode(canonicalVC);
    const sigBytes = await crypto.sign(data, identity.privateKey);
    const proofValue = base64urlEncodeFromBytes(sigBytes);
    return {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: kid,
      proofPurpose: 'assertionMethod',
      proofValue,
    };
  };

  const issuer = new DelegationCredentialIssuer(
    {
      getDid: () => identity.did,
      getKeyId: () => identity.kid,
      getPrivateKey: () => identity.privateKey,
    },
    signingFunction,
  );

  const issueAsJWT: DelegationIssuerFactory['issueAsJWT'] = async (params, options) => {
    const vc = await issuer.createAndIssueDelegation(params, options);
    const vcWithoutProof = { ...vc } as Record<string, unknown>;
    delete vcWithoutProof['proof'];

    const { signingInput } = createUnsignedVCJWT(vcWithoutProof, { keyId: identity.kid });
    const sigBytes = await crypto.sign(new TextEncoder().encode(signingInput), identity.privateKey);
    const signature = base64urlEncodeFromBytes(sigBytes);
    return completeVCJWT(signingInput, signature);
  };

  return { issuer, identity, issueAsJWT };
}
