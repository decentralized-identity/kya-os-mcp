/**
 * Test helper: a party with a fresh did:key identity that can be delegated
 * to, and can issue a delegation credential of its own.
 */
import { createRealSigningFunction } from '../../../__tests__/audit/helpers/crypto-helpers.js';
import { nodeCrypto } from '../../../__tests__/utils/node-crypto-provider.js';
import { DelegationCredentialIssuer } from '../../../delegation/vc-issuer.js';
import type { ProofAgentIdentity } from '../../../proof/generator.js';
import type { DelegationCredential } from '../../../types/protocol.js';
import { generateDidKeyFromBase64, didKeyFragment } from '../../../utils/did-helpers.js';
import { SCOPE } from './delegated-call.js';

/** A party that can be delegated to and can delegate on. */
export interface Party extends ProofAgentIdentity {
  privateKey: string;
  issuer: DelegationCredentialIssuer;
}

/**
 * A party whose DID is the did:key of a fresh key. It signs the credentials
 * it issues with the signing function the other credential tests share,
 * which makes the Data Integrity proof a credential carries.
 */
export async function party(): Promise<Party> {
  const { publicKey, privateKey } = await nodeCrypto.generateKeyPair();
  const did = generateDidKeyFromBase64(publicKey);
  const kid = `${did}#${didKeyFragment(did)}`;
  const sign = createRealSigningFunction(nodeCrypto, {
    did,
    kid,
    publicKey,
    privateKey,
    type: 'development',
    createdAt: new Date().toISOString(),
  });
  return {
    did,
    kid,
    publicKey,
    privateKey,
    issuer: new DelegationCredentialIssuer(
      { getDid: () => did, getKeyId: () => kid, getPrivateKey: () => privateKey },
      sign,
    ),
  };
}

let serial = 0;

/**
 * One hop: `from` delegates `scopes` to `to`, under `parent` when it
 * re-delegates, stating that parent's digest when `commits` is set. Each hop
 * has an id of its own unless it is given one.
 */
export function delegate(
  from: Party,
  to: string,
  options: {
    scopes?: string[];
    parent?: DelegationCredential;
    commits?: boolean;
    audience?: string;
    id?: string;
    metadata?: Record<string, unknown>;
  } = {},
): Promise<DelegationCredential> {
  const issued = options.commits && options.parent ? { parent: options.parent } : {};
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
  }, issued);
}

/**
 * `original` issued again by `issuer`, its own issuer, under the same credential id and the same
 * delegation id, granting `scopes`: another credential that every name of the first also names.
 */
export function reissued(issuer: Party, original: DelegationCredential, { scopes }: { scopes: string[] }): Promise<DelegationCredential> {
  const { id, issuerDid, subjectDid, parentId, constraints } = original.credentialSubject.delegation;
  return issuer.issuer.createAndIssueDelegation(
    { id, issuerDid, subjectDid, ...(parentId === undefined ? {} : { parentId }), constraints: { ...constraints, scopes } },
    { id: original.id },
  );
}
