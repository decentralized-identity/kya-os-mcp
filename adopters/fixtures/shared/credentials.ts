/**
 * Delegation credentials in the two forms the library verifies. The MCP gate's form is issued by
 * `DelegationCredentialIssuer` with an embedded `Ed25519Signature2020` proof, and checked by the
 * signature verifier an adopter gives `DelegationCredentialVerifier`, written as the library's
 * examples write it. The Entity Card form, a VC 2.0 and ZCAP-LD hop, is signed `eddsa-jcs-2022` by
 * `signDelegationCredential`.
 */
import {
  DelegationCredentialIssuer,
  base64urlDecodeToBytes,
  base64urlEncodeFromBytes,
  bytesToBase64,
  canonicalizeJSON,
  type CredentialStatus,
  type DelegationCredential,
  type SignatureVerificationFunction,
  type VCSigningFunction,
} from '@kya-os/mcp';
import {
  DELEGATION_CONTEXT_V2,
  KYA_OS_DELEGATION_CONTEXT,
  ZCAP_CONTEXT,
  signDelegationCredential,
  type DelegationCredential as CardDelegationCredential,
} from '@kya-os/mcp/card';
import { crypto, type Party } from './keys.js';

/**
 * When every credential a fixture issues expires: one hour after the fixture starts, the same
 * instant for all, so no re-delegation outlives its parent.
 */
const EXPIRES = new Date(Date.now() + 60 * 60 * 1000).toISOString();

/** What one delegation grants, and to whom. */
export interface DelegationTerms {
  /** The delegation's id, which a re-delegation names as its `parentId`. */
  id: string;
  subjectDid: string;
  scopes: string[];
  /** The DID of the server the delegation is for, which every re-delegation must name. */
  audience?: string;
  parentId?: string;
  credentialStatus?: CredentialStatus;
}

/** Signs the canonical credential with the party's key, as an `Ed25519Signature2020` proof under `assertionMethod`. */
function signingFunctionOf(party: Party): VCSigningFunction {
  return async (canonicalVC, _issuerDid, kid) => {
    const signature = await crypto.sign(new TextEncoder().encode(canonicalVC), party.privateKey);
    return {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: kid,
      proofPurpose: 'assertionMethod',
      proofValue: base64urlEncodeFromBytes(signature),
    };
  };
}

/** A delegation `issuer` signs, valid until {@link EXPIRES}. */
export function issueDelegation(issuer: Party, terms: DelegationTerms): Promise<DelegationCredential> {
  const delegationIssuer = new DelegationCredentialIssuer(
    { getDid: () => issuer.did, getKeyId: () => issuer.kid, getPrivateKey: () => issuer.privateKey },
    signingFunctionOf(issuer),
  );
  return delegationIssuer.createAndIssueDelegation(
    {
      id: terms.id,
      issuerDid: issuer.did,
      subjectDid: terms.subjectDid,
      constraints: { scopes: terms.scopes, ...(terms.audience !== undefined ? { audience: terms.audience } : {}) },
      ...(terms.parentId !== undefined ? { parentId: terms.parentId } : {}),
    },
    {
      expirationDate: EXPIRES,
      ...(terms.credentialStatus !== undefined ? { credentialStatus: terms.credentialStatus } : {}),
    },
  );
}

/**
 * The `signatureVerifier` of a `DelegationCredentialVerifier`: the embedded Ed25519 signature over
 * the canonical credential without its proof, checked with the key the verifier resolved.
 */
export const ed25519SignatureVerifier: SignatureVerificationFunction = async (vc, publicKeyJwk) => {
  const proofValue = vc.proof?.proofValue;
  const x = (publicKeyJwk as { x?: unknown } | undefined)?.x;
  if (typeof proofValue !== 'string') return { valid: false, reason: 'the proof has no proofValue' };
  if (typeof x !== 'string') return { valid: false, reason: 'the key has no Ed25519 x' };
  const { proof: _proof, ...unsigned } = vc;
  const data = new TextEncoder().encode(canonicalizeJSON(unsigned));
  const valid = await crypto.verify(data, base64urlDecodeToBytes(proofValue), bytesToBase64(base64urlDecodeToBytes(x)));
  return valid ? { valid } : { valid, reason: 'the signature does not verify' };
};

/** A status entry for a revocation bit, in the shape both credential forms take. */
export type RevocationEntry = {
  type: 'BitstringStatusListEntry';
  statusPurpose: 'revocation';
  statusListIndex: string;
  statusListCredential: string;
}

/** A `BitstringStatusListEntry` for the revocation bit at `index` of the list at `url`. */
export function revocationEntry(url: string, index: number): RevocationEntry {
  return {
    type: 'BitstringStatusListEntry',
    statusPurpose: 'revocation',
    statusListIndex: String(index),
    statusListCredential: url,
  };
}

/** What one Entity Card delegation hop grants, and to whom. */
export interface HopTerms {
  /** The capability's id, which a hop below names as its `parentCapability`. */
  id: string;
  invoker: string;
  /** The resource the chain is for: the verifier's own DID. */
  invocationTarget: string;
  /** The root's is the resource itself; any other hop's is its parent's `id`. */
  parentCapability: string;
  allowedAction: string[];
  credentialStatus?: RevocationEntry;
}

/** An Entity Card delegation hop `issuer` signs, valid until {@link EXPIRES}. */
export function signCardHop(issuer: Party, terms: HopTerms): Promise<CardDelegationCredential> {
  return signDelegationCredential(
    {
      '@context': [DELEGATION_CONTEXT_V2, ZCAP_CONTEXT, KYA_OS_DELEGATION_CONTEXT],
      type: ['VerifiableCredential', 'DelegationCredential'],
      issuer: issuer.did,
      validUntil: EXPIRES,
      credentialSubject: {
        id: terms.id,
        invoker: terms.invoker,
        parentCapability: terms.parentCapability,
        invocationTarget: terms.invocationTarget,
        allowedAction: terms.allowedAction,
      },
      ...(terms.credentialStatus !== undefined ? { credentialStatus: terms.credentialStatus } : {}),
    },
    issuer.signer,
  );
}
