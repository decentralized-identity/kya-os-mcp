/**
 * What a proof binds and signs: the canonical hashes of the request and response it covers, the
 * comparison of what a verifier received with them, and the JWS payload a proof's meta signs. The
 * signer (`./generator.ts`) and the verifier (`./verifier.ts`) share these, so the two cannot
 * drift; `./generator.ts` re-exports them, so imports from there are unchanged.
 */

import { canonicalizeJsonBytes } from '../utils/canonical-json.js';
import {
  RESPONSE_PROOF_PROFILE_BODY,
  RESPONSE_PROOF_PROFILE_ENVELOPE,
  type ProofMeta,
  type ResponseProofProfile,
} from '../types/protocol.js';
import type { ContentBindingMismatch } from './binding.js';
import { alternateRequestShapes, withoutTopLevelMeta } from './covered-request.js';
import type { ToolRequest, ToolResponse } from './generator.js';

/**
 * Compute the canonical request/response hashes that bind a proof to a specific
 * invocation. This is the SINGLE source of truth for that hashing, used by both
 * the signer (`ProofGenerator`) and the verifier (`ProofVerifier`), so the two
 * cannot drift. `requestHash` = SHA-256 over RFC 8785 `canonicalize({method,params})`.
 *
 * `responseHash` (omitted when there is no response body, e.g. denial /
 * step-up proofs) depends on the response-proof profile:
 * - body (default): SHA-256 over `canonicalize(response.data)`: the response
 *   BODY only (the MCP `content` array by convention).
 * - envelope: `response.data` is the ENTIRE MCP result object; hashing covers it
 *   with the top-level `_meta` member removed (SPEC §7.3), mirroring the
 *   request side's `{method, params minus _meta}` rule. `_meta` stays
 *   intermediary-mutable and is where the proof itself is attached, so
 *   exclusion is what keeps attach-after-sign sound. Non-object `data` is
 *   canonicalized as-is, so the function stays total and signer/verifier
 *   symmetric on every input.
 *
 * Note: RFC 8785 (via json-canonicalize) drops object members whose value is
 * `undefined`, so a field set to `undefined` hashes identically to that field
 * being absent. Bind only over values that are actually present; never rely on
 * the presence of an `undefined`-valued key to distinguish two payloads.
 *
 * @param hash - a byte → `sha256:<hex>` function (bind a `CryptoProvider.hash`)
 * @param profile - response-proof profile selecting the response
 *   canonicalization; the verifier derives it from the proof's `prf` claim
 */
export async function computeCanonicalHashes(
  request: ToolRequest,
  response: ToolResponse | undefined,
  hash: (bytes: Uint8Array) => Promise<string>,
  profile: ResponseProofProfile = RESPONSE_PROOF_PROFILE_BODY,
): Promise<{ requestHash: string; responseHash?: string }> {
  const canonicalRequest = {
    method: request.method,
    ...(request.params ? { params: request.params } : {}),
  };
  const requestHash = await hash(
    canonicalizeJsonBytes(canonicalRequest),
  );
  if (response === undefined) {
    return { requestHash };
  }
  const responseHash = await hash(
    canonicalizeJsonBytes(canonicalResponseBody(response.data, profile)),
  );
  return { requestHash, responseHash };
}

/**
 * The profile-selected response material that `responseHash` covers. The body profile hashes
 * `data` verbatim; the envelope profile removes the top-level `_meta` member from an object
 * envelope (and only from an object: arrays and primitives pass through, so
 * the mapping is total and identical for signer and verifier). Every other member stays, one
 * named `__proto__` included ({@link withoutTopLevelMeta}).
 */
function canonicalResponseBody(
  data: unknown,
  profile: ResponseProofProfile,
): unknown {
  if (
    profile !== RESPONSE_PROOF_PROFILE_ENVELOPE ||
    data === null ||
    typeof data !== 'object' ||
    Array.isArray(data)
  ) {
    return data;
  }
  return withoutTopLevelMeta(data as Record<string, unknown>);
}

/**
 * Every `requestHash` a verifier accepts for `request`: the hash of `request`
 * as given (the {@link computeCanonicalHashes} rule producers sign with), then
 * the hashes of the same call's other shapes, so that a caller holding either
 * the legacy `{ method: <tool name>, params: <arguments> }` shape or the
 * `tools/call` request as sent can verify a proof minted over either (SPEC
 * §7.3). Each candidate describes the same tool name and business arguments,
 * so none admits a proof over a different call.
 */
export async function acceptedRequestHashes(
  request: ToolRequest,
  hash: (bytes: Uint8Array) => Promise<string>,
): Promise<string[]> {
  const hashes = new Set<string>();
  for (const shape of [request, ...alternateRequestShapes(request)]) {
    hashes.add((await computeCanonicalHashes(shape, undefined, hash)).requestHash);
  }
  return [...hashes];
}

/**
 * Compare the request (and response) a verifier actually received with the
 * hashes a proof binds; `undefined` means they match. Shared by `ProofVerifier`
 * and `ProofGenerator.verifyProof` so both apply one fail-closed rule.
 *
 * The request matches when `meta.requestHash` is any of
 * {@link acceptedRequestHashes}; the hash of the request as given is tried
 * first, and the other shapes only when it differs.
 *
 * `meta.responseHash` is the ONLY thing that binds the response body,
 * including a needs_authorization challenge's `authorizationUrl`, so it is
 * checked whenever the proof carries one. Gating the comparison on a response
 * being supplied would pass a caller who supplies only the request while a
 * swapped URL went unverified (the `requestHash` is identical for a genuine and
 * a MITM'd challenge). So: a proof that binds a response must be given one, and
 * a proof that binds none must not be. The response profile comes from the
 * proof's own signature-covered `prf` claim, never from configuration.
 */
export async function findContentBindingMismatch(
  meta: Pick<ProofMeta, 'requestHash' | 'responseHash' | 'prf'>,
  expected: { request: ToolRequest; response?: ToolResponse },
  hash: (bytes: Uint8Array) => Promise<string>,
): Promise<ContentBindingMismatch | undefined> {
  const { requestHash, responseHash } = await computeCanonicalHashes(
    expected.request,
    expected.response,
    hash,
    meta.prf ?? RESPONSE_PROOF_PROFILE_BODY,
  );
  if (
    meta.requestHash !== requestHash &&
    !(await acceptedRequestHashes(expected.request, hash)).includes(meta.requestHash)
  ) {
    return 'request';
  }
  const bindsResponse = meta.responseHash !== undefined;
  if (bindsResponse !== (expected.response !== undefined)) {
    return bindsResponse ? 'response-missing' : 'response-unexpected';
  }
  if (bindsResponse && meta.responseHash !== responseHash) return 'response';
  return undefined;
}

/**
 * Build the exact JWS payload object a proof signs over, from its `ProofMeta`.
 * SINGLE source of truth for the payload SHAPE: the signer
 * (`ProofGenerator.generateJWS`) serializes it and the verifier
 * (`ProofVerifier.buildCanonicalPayload`) reconstructs it from received meta,
 * so a claim added in one place can never silently go uncovered in the other.
 * Serialization is always RFC 8785 (`canonicalizeJson`), never `JSON.stringify`.
 */
export function buildProofJwsPayload(meta: ProofMeta): Record<string, unknown> {
  return {
    // Standard JWT claims (RFC 7519)
    aud: meta.audience,
    sub: meta.did,
    iss: meta.did,

    // KYA-OS proof claims
    requestHash: meta.requestHash,
    // responseHash is absent on denial / step-up proofs (no response).
    ...(meta.responseHash !== undefined && { responseHash: meta.responseHash }),
    ts: meta.ts,
    nonce: meta.nonce,
    sessionId: meta.sessionId,

    // Optional claims (only include if present)
    ...(meta.scopeId && { scopeId: meta.scopeId }),
    ...(meta.delegationRef && { delegationRef: meta.delegationRef }),
    ...(meta.delegationChainDigest && { delegationChainDigest: meta.delegationChainDigest }),
    ...(meta.clientDid && { clientDid: meta.clientDid }),
    ...(meta.outcome && { outcome: meta.outcome }),
    ...(meta.reason && { reason: meta.reason }),
    // Profile discriminator (envelope-profile proofs only), covered by the signature so it
    // cannot be stripped to downgrade the proof to body-only semantics.
    ...(meta.prf && { prf: meta.prf }),
  };
}
