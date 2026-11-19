/**
 * Delegation credentials (SPEC.md §6.2) as every vector generator signs them: the package's own
 * `wrapDelegationAsVC` over a delegation record, with a fixed issuance date, signed by the issuer
 * as `signVC` (./crypto-kit.ts) signs. Nothing in one depends on when it is minted, so a generator
 * with fixed keys writes the same credential on every run.
 */

import { wrapDelegationAsVC, type CredentialStatus, type DelegationCredential } from '../src/index.js';
import type { NodeCryptoProvider } from '../src/providers/node-crypto.js';
import { signVC, type SigningParty } from './crypto-kit.js';
import type { CredentialOptions } from './delegation-binding-kit.js';

/** A delegation to sign: who delegates which scopes to whom, under which id, bound to which audience. */
export interface SignedDelegationArgs extends CredentialOptions {
  issuer: SigningParty;
  subjectDid: string;
  id: string;
  parentId?: string;
  /**
   * What the delegation states as the digest of its parent credential (SPEC §6.2), where it states
   * anything. Any value: a vector may state one that is no digest.
   */
  parentCredentialDigest?: unknown;
  scopes: string[];
  audience: string | string[];
  status?: 'active' | 'revoked';
  credentialStatus?: CredentialStatus;
}

/** The credential `args` describes, created at `createdAtSeconds` and signed by its issuer. */
export async function signedDelegation(
  crypto: NodeCryptoProvider,
  args: SignedDelegationArgs,
  createdAtSeconds: number,
): Promise<DelegationCredential> {
  const unsigned = wrapDelegationAsVC(
    {
      id: args.id,
      issuerDid: args.issuer.did,
      subjectDid: args.subjectDid,
      vcId: args.vcId ?? `urn:uuid:${args.id}`,
      parentId: args.parentId,
      ...('parentCredentialDigest' in args ? { parentCredentialDigest: args.parentCredentialDigest as string } : {}),
      constraints: { scopes: args.scopes, audience: args.audience },
      signature: '',
      status: args.status ?? 'active',
      createdAt: createdAtSeconds * 1000,
      ...(args.metadata === undefined ? {} : { metadata: args.metadata }),
    },
    {
      issuanceDate: '2026-01-01T00:00:00.000Z',
      ...(args.credentialStatus ? { credentialStatus: args.credentialStatus } : {}),
    },
  );
  for (const [key, value] of args.members ?? []) {
    Object.defineProperty(unsigned, key, { value, enumerable: true, writable: true, configurable: true });
  }
  const { privateKey, kid } = args.issuer;
  const proof = await signVC(crypto, unsigned as Record<string, unknown>, privateKey, kid, args.canonicalize);
  return { ...unsigned, proof } as DelegationCredential;
}
