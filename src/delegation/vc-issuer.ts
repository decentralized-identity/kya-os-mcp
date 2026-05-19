/**
 * Delegation Credential Issuer (Platform-Agnostic)
 *
 * Issues W3C Verifiable Credentials for delegations with Ed25519 signatures.
 * Follows the Python POC design (Delegation-Service.md:136-163) where
 * delegations are issued AS W3C VCs.
 *
 * Related Spec: KYA-OS §4.1, §4.2, W3C VC Data Model 1.1
 */

import type {
  DelegationCredential,
  DelegationRecord,
  CredentialStatus,
  Proof,
} from '../types/protocol.js';
import { wrapDelegationAsVC } from '../types/protocol.js';
import { canonicalizeJSON } from './utils.js';

export interface IssueDelegationOptions {
  id?: string;
  issuanceDate?: string;
  expirationDate?: string;
  credentialStatus?: CredentialStatus;
  additionalContexts?: string[];
}

export interface VCSigningFunction {
  (canonicalVC: string, issuerDid: string, kid: string): Promise<Proof>;
}

export interface IdentityProvider {
  getDid(): string;
  getKeyId(): string;
  getPrivateKey(): string;
}

export class DelegationCredentialIssuer {
  constructor(
    private identity: IdentityProvider,
    private signingFunction: VCSigningFunction
  ) {}

  async issueDelegationCredential(
    delegation: DelegationRecord,
    options: IssueDelegationOptions = {}
  ): Promise<DelegationCredential> {
    let unsignedVC = wrapDelegationAsVC(delegation, {
      id: options.id,
      issuanceDate: options.issuanceDate,
      expirationDate: options.expirationDate,
      credentialStatus: options.credentialStatus,
    });

    if (options.additionalContexts && options.additionalContexts.length > 0) {
      const existingContexts = unsignedVC['@context'] as Array<string | Record<string, unknown>>;
      unsignedVC = {
        ...unsignedVC,
        '@context': [...existingContexts, ...options.additionalContexts],
      };
    }

    const canonicalVC = this.canonicalizeVC(unsignedVC);

    const proof = await this.signingFunction(
      canonicalVC,
      this.identity.getDid(),
      this.identity.getKeyId()
    );

    return {
      ...unsignedVC,
      proof,
    } as DelegationCredential;
  }

  /**
   * Create and issue a delegation credential in one step.
   *
   * Constructs a DelegationRecord from the provided parameters and wraps it
   * in a signed W3C Verifiable Credential.
   *
   * @param params - Delegation parameters including issuer/subject DIDs, constraints, etc.
   * @param options - Optional VC issuance options (id, dates, status, contexts)
   * @returns Signed W3C Delegation Credential
   */
  async createAndIssueDelegation(
    params: {
      id: string;
      issuerDid: string;
      subjectDid: string;
      controller?: string;
      parentId?: string;
      constraints: DelegationRecord['constraints'];
      status?: DelegationRecord['status'];
      metadata?: Record<string, unknown>;
    },
    options: IssueDelegationOptions = {}
  ): Promise<DelegationCredential> {
    const now = Date.now();

    const delegation: DelegationRecord = {
      id: params.id,
      issuerDid: params.issuerDid,
      subjectDid: params.subjectDid,
      controller: params.controller,
      vcId: options.id || `urn:uuid:${params.id}`,
      parentId: params.parentId,
      constraints: params.constraints,
      signature: '',
      status: params.status || 'active',
      createdAt: now,
      metadata: params.metadata,
    };

    return this.issueDelegationCredential(delegation, options);
  }

  private canonicalizeVC(vc: Omit<DelegationCredential, 'proof'>): string {
    return canonicalizeJSON(vc);
  }

  getIssuerDid(): string {
    return this.identity.getDid();
  }

  getIssuerKeyId(): string {
    return this.identity.getKeyId();
  }
}

export function createDelegationIssuer(
  identity: IdentityProvider,
  signingFunction: VCSigningFunction
): DelegationCredentialIssuer {
  return new DelegationCredentialIssuer(identity, signingFunction);
}
