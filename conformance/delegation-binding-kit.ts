/**
 * What the delegation-binding vectors (`signed-proof/delegation-*`, SPEC.md
 * §7.8, suite 1.5.0 or later) are minted with.
 *
 * The generator holds what every vector file shares: its parties and their
 * keys, credentials as their issuers sign them, and the server's proofs at
 * the suite's fixed time. It hands them in as a {@link Mint}. The
 * {@link BindingKit} adds what the vectors of every §7.8 rule have in common:
 * the parties to one chain, the call every proof is of, and a credential's
 * reference and a chain's digest as the package derives them.
 */

import { canonicalize } from 'json-canonicalize';
import {
  delegationChainDigest,
  delegationRefOf,
  digestDelegationChain,
  DELEGATION_CREDENTIAL_DIGEST_DOMAIN,
  type DelegationCredential,
  type DetachedProof,
  type ProofOptions,
  type ReceivedCredential,
  type Sha256,
  type ToolRequest,
  type ToolResponse,
} from '../src/index.js';
import type { SignedProofInput } from './types.js';

/** What a credential holds, or how it is signed, where a vector needs other than the generator's defaults. */
export interface CredentialOptions {
  /** Members of the delegation's own `metadata`, which its issuer signs. */
  metadata?: Record<string, unknown>;
  /** The credential's own `id`, where it is not `urn:uuid:<id>`. */
  vcId?: string;
  /**
   * Members of the credential itself, which its issuer signs. Each is set as
   * an own data member, so one named `__proto__` is a member, not a prototype.
   */
  members?: ReadonlyArray<readonly [string, unknown]>;
  /** How the issuer writes what it signs, where that is not the package's RFC 8785. */
  canonicalize?: (unsigned: Record<string, unknown>) => string;
}

/** A credential to mint: who delegates which scopes to whom, under which id. */
export interface CredentialArgs<P> extends CredentialOptions {
  issuer: P;
  subjectDid: string;
  id: string;
  parentId?: string;
  scopes: string[];
}

/**
 * The generator's means of minting. A party is the generator's own (`P`):
 * the vectors read its DID, and hand it back to be signed for.
 */
export interface Mint<P extends { did: string }> {
  /** The server's public key, which every vector gives the verifier. */
  publicKeyJwk: SignedProofInput['publicKeyJwk'];
  /** The suite's fixed time, in epoch seconds: every proof is signed at it and verified at it. */
  now: number;
  /** SHA-256, as the package's digests take it. */
  hash: Sha256;
  /** A new party: an Ed25519 key pair, and the did:key it goes by. */
  party(): Promise<P>;
  /** A delegation credential (SPEC §6.2) bound to the server, signed by its issuer. */
  credential(args: CredentialArgs<P>): Promise<DelegationCredential>;
  /** A §6.2 credential as a compact VC-JWT, signed by `issuer`. */
  vcJwt(issuer: P, credential: DelegationCredential): Promise<string>;
  /** The server's proof of a call, minted with `options` and signed at the suite's fixed time. */
  proof(request: ToolRequest, response: ToolResponse | undefined, options: ProofOptions): Promise<DetachedProof>;
  /** `meta` signed with the server's key under the JWS header `header`, which need not be the server's own. */
  signedUnder(meta: DetachedProof['meta'], header: Record<string, unknown>): Promise<DetachedProof>;
}

/**
 * What the vectors of every §7.8 rule share: the parties to one chain (the
 * user delegates to the orchestrator, and the orchestrator to the worker),
 * the call every proof is of, and how a credential and a chain are read.
 */
export class BindingKit<P extends { did: string }> {
  /** The call every proof is of. */
  readonly request: ToolRequest = {
    method: 'tools/call',
    params: { name: 'records.read', arguments: { recordId: 'r-1' } },
  };
  /** What the server returned when it allowed the call. */
  readonly response: ToolResponse = { data: [{ type: 'text', text: 'released r-1' }] };

  private constructor(
    readonly mint: Mint<P>,
    readonly user: P,
    readonly orchestrator: P,
    readonly worker: P,
  ) {}

  /** A kit on `mint`, with the parties to the chain minted, the user first. */
  static async of<P extends { did: string }>(mint: Mint<P>): Promise<BindingKit<P>> {
    const [user, orchestrator, worker] = await Promise.all([mint.party(), mint.party(), mint.party()]);
    return new BindingKit(mint, user, orchestrator, worker);
  }

  /** The reference a credential that shows an id goes by (`delegationRef`). */
  async reference(credential: unknown): Promise<string> {
    const reference = await delegationRefOf(credential, this.mint.hash);
    if (reference === undefined) throw new Error('expected a credential that shows an id');
    return reference;
  }

  /** The digest of a chain, root first (`delegationChainDigest`). */
  async chainDigest(chain: readonly ReceivedCredential[]): Promise<string> {
    return (await digestDelegationChain(chain, this.mint.hash)).chain;
  }

  /** A credential the user delegates to the orchestrator for `records:read`, under `id`. */
  credential(id: string, options: CredentialOptions = {}): Promise<DelegationCredential> {
    return this.mint.credential({
      issuer: this.user,
      subjectDid: this.orchestrator.did,
      id,
      scopes: ['records:read'],
      ...options,
    });
  }

  /** An allowed call's proof, minted with `options`. */
  allowed(options: ProofOptions): Promise<DetachedProof> {
    return this.mint.proof(this.request, this.response, options);
  }

  /** A refusal's proof: it binds no response, and states the call denied for `reason`. */
  refused(reason: string, options: ProofOptions): Promise<DetachedProof> {
    return this.mint.proof(this.request, undefined, { outcome: 'denied', reason, ...options });
  }

  /** An allowed call's proof that binds `credential` as a chain of one, and names it. */
  async boundAlone(credential: ReceivedCredential): Promise<DetachedProof> {
    return this.allowed({
      delegationRef: await this.reference(credential),
      delegationChainDigest: await this.chainDigest([credential]),
    });
  }

  /**
   * An authentic proof from a server that refuses nothing: it names
   * `credential`, and binds it as a chain of one by its {@link lenientDigest}.
   */
  async lenientProof(credential: DelegationCredential): Promise<DetachedProof> {
    const { hash } = this.mint;
    return this.allowed({
      delegationRef: await this.reference(credential),
      delegationChainDigest: await delegationChainDigest([await lenientDigest(credential, hash)], hash),
    });
  }

  /** A vector's input: `proof`, verified with the server's key at the suite's fixed time, against `expected`. */
  inputOf(proof: DetachedProof, expected: SignedProofInput['expected']): SignedProofInput {
    return { proof, publicKeyJwk: this.mint.publicKeyJwk, now: this.mint.now, skewSeconds: 300, expected };
  }
}

/**
 * The digest an implementation that refuses nothing takes of a credential
 * object: the construction of §7.8 by hand, with another canonicalizer, one
 * that counts no nesting and refuses no integer above 2^53 - 1.
 */
export async function lenientDigest(credential: DelegationCredential, hash: Sha256): Promise<string> {
  const { proof, ...unsigned } = credential;
  const signedFormJcs = canonicalize({ credential: unsigned, signature: proof?.proofValue } as never);
  return hash(new TextEncoder().encode(`${DELEGATION_CREDENTIAL_DIGEST_DOMAIN}\0${signedFormJcs}`));
}

/** The payload of a compact JWS, as text. */
export function payloadText(jws: string): string {
  return Buffer.from(jws.split('.')[1]!, 'base64url').toString('utf8');
}
