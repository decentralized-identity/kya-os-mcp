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
 *
 * `did:web` (and other non-`did:key`) subjects do not encode their key in the
 * DID and may rotate or hold several keys, so phase-1 cannot pin "the" key for
 * them. They are reported {@link HolderBindingStatus | not_applicable} so the
 * caller can defer them to cnf-based binding (phase 2) instead of rejecting
 * legitimate traffic. Callers MUST surface that gap (e.g. log it) rather than
 * treat `not_applicable` as success.
 */

import { extractPublicKeyFromDidKey, publicKeyToJwk } from './did-key-resolver.js';
import { getDidMethod, didKeyFragment } from '../utils/did-helpers.js';
import { ProofGenerator } from '../proof/generator.js';
import { base64urlEncodeFromBytes } from '../utils/base64.js';
import type { ProofVerifier } from '../proof/verifier.js';
import type { ToolRequest, ToolResponse, ProofAgentIdentity } from '../proof/generator.js';
import type { DetachedProof } from '../types/protocol.js';
import type { CryptoProvider } from '../providers/base.js';
import type { Ed25519JWK } from '../utils/crypto-service.js';

/**
 * The control-arg key prefix. Args beginning with this are protocol envelope
 * (`_kyaos_delegation`, `_kyaos_proof`, `_kyaos_approvals`), not the caller's
 * tool intent, so they are excluded from the holder-binding request hash.
 */
const KYAOS_CONTROL_PREFIX = '_kyaos';

/**
 * Whether an argument key is reserved KYA-OS protocol envelope (`_kyaos*`:
 * `_kyaos_delegation`, `_kyaos_proof`, `_kyaos_approvals`, …) rather than caller
 * tool intent. The SINGLE predicate behind both the holder-binding request hash
 * and the middleware's handler-arg stripping, so the set excluded from the bound
 * hash and the set withheld from the handler cannot drift — a proof binds exactly
 * the call the handler runs.
 */
export function isKyaOsControlArg(key: string): boolean {
  return key.startsWith(KYAOS_CONTROL_PREFIX);
}

/**
 * The canonical request a holder-binding proof binds: the tool name plus the
 * caller's business arguments, with protocol control args stripped. SHARED by
 * the client (when minting the proof) and the PEP (when verifying it) so the two
 * cannot drift — the request hash is computed over the identical shape on both
 * sides regardless of which control args rode along.
 */
export function toHolderBindingRequest(
  toolName: string,
  args: Record<string, unknown>,
): ToolRequest {
  const params: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    if (!isKyaOsControlArg(k)) params[k] = v;
  }
  return { method: toolName, params };
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
}

/**
 * Mint the `_kyaos_proof` a key-bearing agent attaches to an outbound tool call
 * — the client half of holder binding. It is a request-only detached proof (no
 * response yet) signed by the agent's key over {@link toHolderBindingRequest}.
 * A fresh nonce is generated per call so the PEP's replay cache rejects reuse.
 */
export async function generateRequestProof(
  input: GenerateRequestProofInput,
): Promise<DetachedProof> {
  const { identity, crypto, toolName, args, audience, sessionId } = input;
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
  });
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
 * - `not_applicable` — subject is not a did:key, so phase-1 cannot bind it.
 *   Defer to cnf-based binding (phase 2); the caller decides how to treat it.
 */
export type HolderBindingStatus = 'bound' | 'unbound' | 'not_applicable';

/**
 * Whether phase-1 holder binding can bind this subject. True only for did:key
 * (the DID encodes the key). The PEP uses this to decide between *enforcing* a
 * proof (did:key) and *deferring* to cnf binding (did:web and others), so it
 * never rejects legitimate traffic it cannot yet bind.
 */
export function isHolderBindingApplicable(subjectDid: string): boolean {
  return extractPublicKeyFromDidKey(subjectDid) !== null;
}

export interface AssertHolderBindingInput {
  /** The per-request detached proof presented by the caller. */
  proof: DetachedProof;
  /** The delegation subject DID the proof must be bound to. */
  subjectDid: string;
  /** The request the proof must bind (content binding). */
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
  const subjectKeyBytes = extractPublicKeyFromDidKey(subjectDid);
  if (!subjectKeyBytes) {
    return {
      status: 'not_applicable',
      reason:
        `Holder binding (phase 1) covers did:key subjects only; ` +
        `"${getDidMethod(subjectDid) ?? 'unknown'}" is deferred to cnf-based binding`,
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
