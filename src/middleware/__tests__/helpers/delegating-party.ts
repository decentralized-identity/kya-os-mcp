/**
 * Test helper: a party with a fresh did:key identity that can be delegated
 * to, and can issue a delegation credential of its own.
 */
import { NodeCryptoProvider } from '../../../__tests__/utils/node-crypto-provider.js';
import { DelegationCredentialIssuer } from '../../../delegation/vc-issuer.js';
import type { ProofAgentIdentity } from '../../../proof/generator.js';
import type { DelegationCredential, Proof } from '../../../types/protocol.js';
import { base64urlEncodeFromBytes } from '../../../utils/base64.js';
import { generateDidKeyFromBase64, didKeyFragment } from '../../../utils/did-helpers.js';
import { SCOPE } from './delegated-call.js';

const crypto = new NodeCryptoProvider();

/** A party that can be delegated to and can delegate on. */
export interface Party extends ProofAgentIdentity {
  privateKey: string;
  issuer: DelegationCredentialIssuer;
}

export async function party(): Promise<Party> {
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  const kid = `${did}#${didKeyFragment(did)}`;
  const sign = async (canonicalVC: string, _issuerDid: string, keyId: string): Promise<Proof> => ({
    type: 'Ed25519Signature2020',
    created: new Date().toISOString(),
    verificationMethod: keyId,
    proofPurpose: 'assertionMethod',
    proofValue: base64urlEncodeFromBytes(
      await crypto.sign(new TextEncoder().encode(canonicalVC), keyPair.privateKey),
    ),
  });
  return {
    did,
    kid,
    ...keyPair,
    issuer: new DelegationCredentialIssuer(
      { getDid: () => did, getKeyId: () => kid, getPrivateKey: () => keyPair.privateKey },
      sign,
    ),
  };
}

let serial = 0;

/**
 * One hop: `from` delegates `scopes` to `to`, under `parent` when it
 * re-delegates. Each hop has an id of its own unless it is given one.
 */
export function delegate(
  from: Party,
  to: string,
  options: {
    scopes?: string[];
    parent?: DelegationCredential;
    audience?: string;
    id?: string;
    metadata?: Record<string, unknown>;
  } = {},
): Promise<DelegationCredential> {
  return from.issuer.createAndIssueDelegation({
    id: options.id ?? `del-${(serial += 1)}`,
    issuerDid: from.did,
    subjectDid: to,
    ...(options.parent ? { parentId: options.parent.credentialSubject.delegation.id } : {}),
    constraints: {
      scopes: options.scopes ?? [SCOPE],
      ...(options.audience !== undefined ? { audience: options.audience } : {}),
      notAfter: Math.floor(Date.now() / 1000) + 3600,
    },
    ...(options.metadata !== undefined ? { metadata: options.metadata } : {}),
  });
}
