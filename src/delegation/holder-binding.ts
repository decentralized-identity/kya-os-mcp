/**
 * Holder binding — enforce that a request proof is bound to the delegation subject.
 *
 * A delegation credential names a subject DID and grants it authority. On its
 * own that credential is a *bearer* token: anyone who obtains the string can
 * present it. Holder binding closes that gap (spec §11.8 theft-replay residual)
 * by requiring the caller to prove possession of the subject DID's key on the
 * request itself.
 *
 * For a `did:key` subject the proof is exact and needs no new credential fields:
 * the DID *is* the public key, so "the proof verifies against the subject DID's
 * key" is equivalent to "the caller holds the subject's private key". This module
 * derives the subject key straight from the DID and verifies the request proof
 * against it. A proof signed by any other key — a thief replaying a stolen
 * credential — cannot verify and is rejected.
 * A request proof is EdDSA, so only an Ed25519 `did:key` can be bound: a
 * subject that is a `did:key` of any other key, or one that does not decode,
 * is reported `unbound`, never deferred, so a caller that enforces binding
 * refuses it rather than take it as a bearer.
 *
 * `did:web` (and other non-`did:key`) subjects do not encode their key in the
 * DID and may rotate or hold several keys, so phase-1 cannot pin "the" key for
 * them. They are reported {@link HolderBindingStatus | not_applicable} so the
 * caller can defer them to cnf-based binding (phase 2) instead of rejecting
 * legitimate traffic. Callers MUST surface that gap (e.g. log it) rather than
 * treat `not_applicable` as success.
 *
 * A proof covers the call, not the delegation beside it, so a proof may also
 * name the delegation it was made for (`./named-delegation.ts`), and is then
 * bound only beside that one.
 */

import { extractPublicKeyFromDidKey, publicKeyToJwk } from './did-key-resolver.js';
import { getDidMethod, didKeyFragment } from '../utils/did-helpers.js';
import { ProofGenerator } from '../proof/generator.js';
import { isKyaOsControlArg, withoutControlArgs } from '../proof/covered-request.js';
import { base64urlEncodeFromBytes } from '../utils/base64.js';
import type { ProofVerifier } from '../proof/verifier.js';
import type { ToolRequest, ToolResponse, ProofAgentIdentity } from '../proof/generator.js';
import type { DetachedProof } from '../types/protocol.js';
import type { CryptoProvider } from '../providers/base.js';
import type { Ed25519JWK } from '../utils/crypto-service.js';
import { namesAnotherDelegation, namesOfDelegationChain, type PresentedDelegation } from './named-delegation.js';

// The control-arg predicate, and the copy of a call without its control args,
// live with the request-hash rules they feed; they are re-exported here, where
// the package entry point imports them.
export { isKyaOsControlArg, withoutControlArgs };
export type { PresentedDelegation };

/**
 * The canonical request a holder-binding proof binds: the tool name plus the
 * caller's business arguments, with protocol control args stripped. SHARED by
 * the client (when minting the proof) and the PEP (when verifying it) so the two
 * cannot drift — the request hash is computed over the identical shape on both
 * sides regardless of which control args rode along.
 *
 * This is the legacy shape 1.x clients sign. The PEP's verifier also accepts a
 * proof over the SPEC §7.3 `tools/call` request for the same call, so a client
 * that follows the specification is bound too.
 */
export function toHolderBindingRequest(
  toolName: string,
  args: Record<string, unknown>,
): ToolRequest {
  return { method: toolName, params: withoutControlArgs(args) };
}

export interface GenerateRequestProofInput {
  /** The agent (delegation subject) identity holding the signing key. */
  identity: ProofAgentIdentity;
  /** Crypto provider used to sign and to mint the per-request nonce. */
  crypto: CryptoProvider;
  /** The tool being called. */
  toolName: string;
  /** The tool arguments (control args are stripped before binding). */
  args: Record<string, unknown>;
  /** The server DID the call is addressed to. */
  audience: string;
  /** The handshake session id, when one exists. */
  sessionId?: string;
  /**
   * The delegation chain the call is made under, root first, the credential sent as
   * `_kyaos_delegation` last, each as it is sent: a credential object, or a VC-JWT string. A
   * credential with no parent is a chain of one. When given, the proof names it by the two members
   * of SPEC §7.8, its last credential's `delegationRef` and the chain's `delegationChainDigest`,
   * and the gate refuses the proof beside any other delegation, so a party on the path cannot put
   * another delegation of the agent's in its place. The chain must be the one the server
   * evaluates: where the server resolves the credential's ancestors (`resolveDelegationChain`),
   * every one of them.
   */
  delegationChain?: readonly unknown[];
}

/**
 * Mint the `_kyaos_proof` a key-bearing agent attaches to an outbound tool call
 * — the client half of holder binding. It is a request-only detached proof (no
 * response yet) signed by the agent's key over {@link toHolderBindingRequest},
 * naming the delegation it is made under when `delegationChain` is given.
 * A fresh nonce is generated per call so the PEP's replay cache rejects reuse.
 *
 * @throws {TypeError} for a `delegationChain` that is empty, and
 *   `NoSignedFormError` for one holding a value with no signed form (SPEC §7.8)
 */
export async function generateRequestProof(
  input: GenerateRequestProofInput,
): Promise<DetachedProof> {
  const { identity, crypto, toolName, args, audience, sessionId, delegationChain } = input;
  const named = delegationChain === undefined
    ? {}
    : await namesOfDelegationChain(delegationChain, (bytes) => crypto.hash(bytes));
  const generator = new ProofGenerator(identity, crypto);
  const request = toHolderBindingRequest(toolName, args);
  const nonce = base64urlEncodeFromBytes(await crypto.randomBytes(16));
  const now = Math.floor(Date.now() / 1000);
  // `sessionId` is optional on the way in (a request proof can precede any
  // handshake), but `meta.sessionId` is a REQUIRED non-empty string in the
  // proof schema. Defaulting to '' therefore minted a proof that could never
  // verify: `assertHolderBinding` rejected the LEGITIMATE holder as
  // INVALID_PROOF_STRUCTURE, indistinguishably from a thief. Mint a per-proof
  // id instead, so the sessionless case (the stateless MCP core) works.
  const boundSessionId = sessionId ?? `req-${base64urlEncodeFromBytes(await crypto.randomBytes(9))}`;
  return generator.generateProof(request, undefined, {
    sessionId: boundSessionId,
    audience,
    nonce,
    timestamp: now,
    createdAt: now,
    lastActivity: now,
    ttlMinutes: 30,
    identityState: 'anonymous',
  }, named);
}

/**
 * Stable, client-facing error code for a failed holder binding. Distinct from
 * the verifier's granular codes (which are kept in {@link HolderBindingResult.cause}
 * for server-side diagnosis) so a binding failure presents one reason to callers
 * and never leaks why the proof was rejected.
 */
export const HOLDER_BINDING_ERROR = 'holder_binding_failed';

/**
 * - `bound` — subject is a did:key and the proof verifies against its key: the
 *   caller is the holder. Allow.
 * - `unbound` — subject is a did:key but the proof failed (wrong key, tampered
 *   request, stale, or replayed). Reject — this is the theft-replay closure.
 *   It is also the status of a did:key that encodes no Ed25519 key, which no
 *   proof could be checked with.
 * - `not_applicable` — subject is not a did:key, so phase-1 cannot bind it.
 *   Defer to cnf-based binding (phase 2); the caller decides how to treat it.
 */
export type HolderBindingStatus = 'bound' | 'unbound' | 'not_applicable';

/**
 * Whether phase-1 holder binding applies to this subject. True for every did:key
 * (the DID encodes the key), whether or not its key is one a proof can be checked
 * with. The PEP uses this to decide between *enforcing* a proof (did:key) and
 * *deferring* to cnf binding (did:web and others), so it never rejects
 * legitimate traffic it cannot yet bind, and never lets through as a bearer a
 * did:key subject that it cannot bind.
 */
export function isHolderBindingApplicable(subjectDid: string): boolean {
  return getDidMethod(subjectDid) === 'key';
}

export interface AssertHolderBindingInput {
  /** The per-request detached proof presented by the caller. */
  proof: DetachedProof;
  /** The delegation subject DID the proof must be bound to. */
  subjectDid: string;
  /**
   * The request the proof must bind (content binding). A proof over either
   * shape of this call, the legacy one or the SPEC §7.3 `tools/call` request,
   * is accepted.
   */
  request: ToolRequest;
  /**
   * The response the proof binds, when the proof carries one. Inbound request
   * proofs are request-only and omit this.
   */
  response?: ToolResponse;
  /**
   * The audience the proof must be addressed to — the recipient server's DID
   * (RFC 8707 "to-whom" binding). When set, `proof.meta.audience` must equal it
   * (or be one of the array, for DID rotation / multi-DID servers); a proof
   * minted for another server is rejected, closing confused-deputy replay across
   * servers. Omit to skip the audience check (back-compatible).
   */
  expectedAudience?: string | string[];
  /** The existing verifier — supplies signature, nonce, timestamp and content checks. */
  proofVerifier: ProofVerifier;
  /**
   * The delegation the call presented, as the server read it. When set, a proof that names a
   * delegation (SPEC §7.8: `delegationRef`, `delegationChainDigest`) is bound only if it names this
   * one, so a delegation swapped in beside the proof is refused. A proof that names none is held to
   * nothing more. Omit it where no delegation was presented (back-compatible).
   */
  delegation?: PresentedDelegation;
}

export interface HolderBindingResult {
  status: HolderBindingStatus;
  /** Human-readable explanation (present whenever status is not `bound`). */
  reason?: string;
  /** {@link HOLDER_BINDING_ERROR} when status is `unbound`. */
  errorCode?: typeof HOLDER_BINDING_ERROR;
  /** Underlying verifier error code, for server-side diagnosis only. */
  cause?: string;
}

/**
 * Assert that `proof` is a holder-of-key proof for `subjectDid` over `request`.
 *
 * @see module documentation for the did:key / did:web split and the security
 *   property each branch enforces.
 */
export async function assertHolderBinding(
  input: AssertHolderBindingInput,
): Promise<HolderBindingResult> {
  const { proof, subjectDid, request, response, expectedAudience, proofVerifier } = input;

  // Phase-1 scope: did:key subjects only — the DID encodes the key, so holding
  // the key is being the subject. Anything else is deferred to cnf binding.
  if (!isHolderBindingApplicable(subjectDid)) {
    return {
      status: 'not_applicable',
      reason:
        `Holder binding (phase 1) covers did:key subjects only; ` +
        `"${getDidMethod(subjectDid) ?? 'unknown'}" is deferred to cnf-based binding`,
    };
  }
  // A did:key of another key, or one that does not decode, can never be bound.
  const subjectKeyBytes = extractPublicKeyFromDidKey(subjectDid);
  if (!subjectKeyBytes) {
    return {
      status: 'unbound',
      errorCode: HOLDER_BINDING_ERROR,
      reason: 'The did:key subject does not encode an Ed25519 key, the only key a request proof is checked with',
      cause: 'unsupported_subject_key',
    };
  }

  // Fail closed on a structurally malformed proof (e.g. the {} a caller
  // substitutes when a string proof fails to parse) — never throw out of the
  // gate, which would surface as an internal error instead of a binding failure.
  if (typeof proof?.meta !== 'object' || proof.meta === null) {
    return {
      status: 'unbound',
      errorCode: HOLDER_BINDING_ERROR,
      reason: 'Malformed proof: missing meta',
    };
  }

  // Pre-crypto consistency: the proof must self-declare the delegation subject.
  // Cheap, and gives a precise reason before the signature check.
  if (proof.meta.did !== subjectDid) {
    return {
      status: 'unbound',
      errorCode: HOLDER_BINDING_ERROR,
      reason: 'Proof subject does not match the delegation subject',
    };
  }

  // Audience binding (RFC 8707): the proof must be addressed to THIS server. A
  // proof minted for another server cannot be replayed here. Checked before the
  // signature so a misdirected proof fails fast without burning its nonce.
  if (expectedAudience !== undefined) {
    const allowed = Array.isArray(expectedAudience) ? expectedAudience : [expectedAudience];
    if (!allowed.includes(proof.meta.audience)) {
      return {
        status: 'unbound',
        errorCode: HOLDER_BINDING_ERROR,
        reason: 'Proof audience does not match this server',
        cause: 'audience_mismatch',
      };
    }
  }

  // The delegation: a proof that names one is good only beside it. Checked
  // before the signature, as the audience is, so a proof a party on the path
  // put beside another delegation fails without burning its nonce.
  if (input.delegation !== undefined) {
    let other: boolean;
    try {
      other = await namesAnotherDelegation(proof.meta, input.delegation);
    } catch {
      return {
        status: 'unbound',
        errorCode: HOLDER_BINDING_ERROR,
        reason: 'The delegation the request proof names could not be compared with the one presented',
        cause: 'delegation_unchecked',
      };
    }
    if (other) {
      return {
        status: 'unbound',
        errorCode: HOLDER_BINDING_ERROR,
        reason: 'Request proof names another delegation than the one presented',
        cause: 'delegation_mismatch',
      };
    }
  }

  // The binding itself: verify the proof against the SUBJECT DID's key. The
  // verifier reconstructs the signed payload from proof.meta (sub/iss = subject),
  // so a proof signed by any other key cannot verify here — defeating a
  // stolen-credential replay — and a tampered request fails content binding.
  // Tag the key with the subject's canonical did:key verification-method id.
  // The verifier's kid check (publicKeyJwk.kid === proof.meta.kid) then enforces
  // that the proof's kid is the subject's verification method — a proof citing
  // any other kid is rejected before the signature is even checked. The key
  // material (x) still comes from the DID, so the signature is the real binding.
  const subjectKey = publicKeyToJwk(subjectKeyBytes) as Ed25519JWK;
  subjectKey.kid = `${subjectDid}#${didKeyFragment(subjectDid)}`;
  const verification = await proofVerifier.verifyProof(proof, subjectKey, {
    request,
    ...(response !== undefined ? { response } : {}),
  });
  if (!verification.valid) {
    return {
      status: 'unbound',
      errorCode: HOLDER_BINDING_ERROR,
      reason: 'Request proof is not bound to the delegation subject',
      ...(verification.errorCode !== undefined ? { cause: verification.errorCode } : {}),
    };
  }

  return { status: 'bound' };
}
