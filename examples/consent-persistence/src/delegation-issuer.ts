/**
 * Delegation Issuer Factory (shared with examples/consent-basic).
 *
 * Creates a DelegationCredentialIssuer from an identity config. The consent
 * server uses it to mint the delegation VC that backs an approved grant.
 *
 * Related Spec: KYA-OS §3.1 (VC structure), §4.1 (DelegationRecord)
 */

import {
  DelegationCredentialIssuer,
  base64urlEncodeFromBytes,
  type VCSigningFunction,
  type Proof,
  type CryptoProvider,
} from '@kya-os/mcp';

export interface AgentIdentityConfig {
  did: string;
  kid: string;
  privateKey: string;
  publicKey: string;
}

export interface DelegationIssuerFactory {
  issuer: DelegationCredentialIssuer;
  identity: AgentIdentityConfig;
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
    return {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: kid,
      proofPurpose: 'assertionMethod',
      proofValue: base64urlEncodeFromBytes(sigBytes),
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

  return { issuer, identity };
}
