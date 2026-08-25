/**
 * Proof Generation — Platform-agnostic Protocol Reference
 *
 * Handles JCS canonicalization, SHA-256 digest generation, and Ed25519 JWS
 * signing (compact format) according to KYA-OS requirements 5.1, 5.2, 5.3, 5.6.
 *
 * This module is the authoritative proof implementation. All platform adapters
 * (Node.js, Cloudflare Workers) inject a CryptoProvider and delegate here.
 */

import { CompactSign, importPKCS8 } from 'jose';
import { canonicalizeJson, canonicalizeJsonBytes } from '../utils/canonical-json.js';
import {
  RESPONSE_PROOF_PROFILE_V1,
  RESPONSE_PROOF_PROFILE_V2,
  type DetachedProof,
  type ProofMeta,
  type ResponseProofProfile,
  type SessionContext,
} from '../types/protocol.js';
import type { CryptoProvider } from '../providers/base.js';
import { CryptoService, type Ed25519JWK } from '../utils/crypto-service.js';
import { base64ToBytes, base64urlEncodeFromBytes, bytesToBase64 } from '../utils/base64.js';
import { ED25519_PKCS8_DER_HEADER, ED25519_KEY_SIZE } from '../utils/ed25519-constants.js';

/**
 * Canonical reverse-DNS `_meta` key under which KYA-OS attaches its detached
 * proof. MCP 2026-07-28 (SEP-414) makes `_meta` shared, reverse-DNS–namespaced
 * real estate — it also carries `io.modelcontextprotocol/*` and W3C trace
 * context keys — so KYA-OS namespaces its own payload rather than owning bare
 * `proof`.
 *
 * SINGLE SOURCE OF TRUTH: every emit site (middleware) and verify site
 * (`extractProofFromMeta` / `validateMetaStructure`) references this constant,
 * so renaming the namespace — e.g. once KYA-OS registers as an MCP Extension
 * under SEP-2133 — is a one-line change. Named for its ROLE (the response
 * proof), so it cannot be misread as a version sibling of the request proof's
 * `org.kya-os/request-proof`. See SPEC §7.5-§7.6.
 */
export const KYA_OS_PROOF_META_KEY = 'org.kya-os/response-proof';

/**
 * The prior namespaced key (`org.kya-os/proof`), canonical from 1.1 until the
 * role-named rename. Reads as a lineage sibling of the request proof's
 * versioned key, which it is not — the two carry different objects — hence the
 * rename. For one major version verifiers MUST keep accepting a proof
 * published here; producers emit {@link KYA_OS_PROOF_META_KEY} and MAY mirror
 * here for older verifiers. When several keys are present the newest canonical
 * form wins.
 */
export const LEGACY_NAMESPACED_PROOF_META_KEY = 'org.kya-os/proof';

/**
 * Legacy bare `_meta.proof` key — the legacy `_meta.proof` mirror; drop at 2.0.
 * For one major version verifiers MUST keep accepting a proof published here
 * (back-compat); producers SHOULD emit under {@link KYA_OS_PROOF_META_KEY}. When
 * both keys are present the namespaced key wins. The mirror is emitted by default
 * for the whole 1.x line (see `emitLegacyProofKey`) and removed at 2.0. SPEC §7.6.
 */
export const LEGACY_PROOF_META_KEY = 'proof';

export interface ProofAgentIdentity {
  did: string;
  kid: string;
  /**
   * The Ed25519 signing key. Either the base64-encoded raw private key (the
   * historical form), or a `CryptoKey` handle — including a **non-extractable**
   * WebCrypto key (e.g. a passkey-PRF-derived or HSM/KMS-fronted key). Passing a
   * handle keeps secret key material inside the caller's trust boundary and
   * hands the library only a signer, per SPEC §4.5 ("implementations that …
   * hold agent secret keys … are non-conformant") and the KMS/HSM signer-hook
   * guidance. Either form produces an equally valid, verifier-accepted proof.
   */
  privateKey: string | CryptoKey;
  publicKey: string;
}

export interface ToolRequest {
  method: string;
  params?: unknown;
}

export interface ToolResponse {
  data: unknown;
  meta?: {
    proof?: DetachedProof;
    [key: string]: unknown;
  };
}

export interface ProofOptions {
  scopeId?: string;
  delegationRef?: string;
  clientDid?: string;
  outcome?: 'allowed' | 'denied' | 'step_up_required' | 'needs_authorization';
  reason?: string;
  /**
   * Response-proof profile to mint under. Default
   * {@link RESPONSE_PROOF_PROFILE_V1} (body-only coverage, wire-identical to
   * pre-v2 proofs). Under {@link RESPONSE_PROOF_PROFILE_V2} the caller passes
   * the ENTIRE MCP result object as `response.data`; hashing covers it with the
   * top-level `_meta` member removed, and the proof carries a signature-covered
   * `prf` claim naming the profile. This is a minting OPTION, not a proof
   * claim — verification always derives the profile from the proof's own `prf`.
   */
  profile?: ResponseProofProfile;
}

// Re-exported so proof consumers can import the profile vocabulary from the
// module that mints and hashes proofs, without reaching into types/protocol.
export { RESPONSE_PROOF_PROFILE_V1, RESPONSE_PROOF_PROFILE_V2 };
export type { ResponseProofProfile };

/**
 * Compute the canonical request/response hashes that bind a proof to a specific
 * invocation. This is the SINGLE source of truth for that hashing — used by both
 * the signer (`ProofGenerator`) and the verifier (`ProofVerifier`), so the two
 * cannot drift. `requestHash` = SHA-256 over RFC 8785 `canonicalize({method,params})`.
 *
 * `responseHash` (omitted when there is no response body, e.g. denial /
 * step-up proofs) depends on the response-proof profile:
 * - v1 (default): SHA-256 over `canonicalize(response.data)` — the response
 *   BODY only (the MCP `content` array by convention).
 * - v2: `response.data` is the ENTIRE MCP result object; hashing covers it
 *   with the top-level `_meta` member removed (SPEC §7.3), mirroring the
 *   request side's `{method, params minus _meta}` rule. `_meta` stays
 *   intermediary-mutable and is where the proof itself is attached, so
 *   exclusion is what keeps attach-after-sign sound. Non-object `data` is
 *   canonicalized as-is — the function stays total and signer/verifier
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
  profile: ResponseProofProfile = RESPONSE_PROOF_PROFILE_V1,
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
 * The profile-selected response material that `responseHash` covers. v1 hashes
 * `data` verbatim; v2 removes the top-level `_meta` member from an object
 * envelope (and only from an object — arrays and primitives pass through, so
 * the mapping is total and identical for signer and verifier).
 */
function canonicalResponseBody(
  data: unknown,
  profile: ResponseProofProfile,
): unknown {
  if (
    profile !== RESPONSE_PROOF_PROFILE_V2 ||
    data === null ||
    typeof data !== 'object' ||
    Array.isArray(data)
  ) {
    return data;
  }
  const envelope: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data)) {
    if (key !== '_meta') envelope[key] = value;
  }
  return envelope;
}

/**
 * Build the exact JWS payload object a proof signs over, from its `ProofMeta`.
 * SINGLE source of truth for the payload SHAPE — the signer
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
    ...(meta.clientDid && { clientDid: meta.clientDid }),
    ...(meta.outcome && { outcome: meta.outcome }),
    ...(meta.reason && { reason: meta.reason }),
    // Profile discriminator (v2 proofs only) — covered by the signature so it
    // cannot be stripped to downgrade the proof to v1 semantics.
    ...(meta.prf && { prf: meta.prf }),
  };
}

export class ProofGenerator {
  private identity: ProofAgentIdentity;
  private cryptoProvider: CryptoProvider;

  constructor(identity: ProofAgentIdentity, cryptoProvider: CryptoProvider) {
    this.identity = identity;
    this.cryptoProvider = cryptoProvider;
  }

  /**
   * Generate a detached proof for an MCP tool call.
   *
   * Creates a JWS (JSON Web Signature) that binds the tool request and response
   * to the agent's identity and current session context.
   *
   * @param request - The MCP tool request (method + params)
   * @param response - The tool response data
   * @param session - The current session context from handshake
   * @param options - Optional proof metadata (scopeId, delegationRef, clientDid)
   * @returns Detached proof containing JWS and proof metadata
   * @throws {Error} If JWS generation fails (invalid key, crypto error)
   */
  async generateProof(
    request: ToolRequest,
    response: ToolResponse | undefined,
    session: SessionContext,
    options: ProofOptions = {}
  ): Promise<DetachedProof> {
    // `profile` is a minting option, not a proof claim — destructure it out so
    // the spread below can never leak a `profile` key into the signed meta. The
    // claim form is `prf`, set only for v2 (v1 stays byte-identical on the wire).
    const { profile = RESPONSE_PROOF_PROFILE_V1, ...metaOptions } = options;
    const hashes = await this.generateCanonicalHashes(request, response, profile);
    const proofNonce = base64urlEncodeFromBytes(
      await this.cryptoProvider.randomBytes(16),
    );

    const meta: ProofMeta = {
      did: this.identity.did,
      kid: this.identity.kid,
      ts: Math.floor(Date.now() / 1000),
      nonce: proofNonce,
      audience: session.audience,
      sessionId: session.sessionId,
      requestHash: hashes.requestHash,
      ...(hashes.responseHash !== undefined
        ? { responseHash: hashes.responseHash }
        : {}),
      ...(profile === RESPONSE_PROOF_PROFILE_V2
        ? { prf: RESPONSE_PROOF_PROFILE_V2 }
        : {}),
      ...metaOptions,
    };

    const jws = await this.generateJWS(meta);

    return { jws, meta };
  }

  /**
   * Compute the canonical request hash for an invocation, independent of any
   * response. Used to bind step-up approval grants to a specific action.
   */
  async hashRequest(request: ToolRequest): Promise<string> {
    return (await this.generateCanonicalHashes(request)).requestHash;
  }

  private async generateCanonicalHashes(
    request: ToolRequest,
    response?: ToolResponse,
    profile?: ResponseProofProfile,
  ): Promise<{ requestHash: string; responseHash?: string }> {
    return computeCanonicalHashes(
      request,
      response,
      (bytes) => this.cryptoProvider.hash(bytes),
      profile,
    );
  }

  /**
   * Resolve the identity's signing key into the form jose signs with. A base64
   * string is imported as a PKCS#8 key (the historical path); a `CryptoKey`
   * handle — including a non-extractable one (passkey-PRF- or HSM/KMS-fronted)
   * — is used as-is. Either way the caller never has to materialize secret key
   * bytes for the library, per SPEC §4.5.
   */
  private async resolveSigningKey(): Promise<CryptoKey> {
    const key = this.identity.privateKey;
    return typeof key === 'string'
      ? importPKCS8(this.formatPrivateKeyAsPEM(key), 'EdDSA')
      : key;
  }

  private async generateJWS(meta: ProofMeta): Promise<string> {
    try {
      // jose's CompactSign owns the JWS signing-input construction, so
      // canonicalization stays inside the library and the signing input is the
      // same regardless of how the signing key was supplied.
      const privateKey = await this.resolveSigningKey();

      // Shared payload shape (buildProofJwsPayload) — the verifier reconstructs
      // this exact object from received meta, so the two cannot drift.
      const payload = buildProofJwsPayload(meta);

      // Use canonicalized JSON (RFC 8785) for deterministic payload serialization.
      // This ensures signature verification succeeds regardless of JSON key ordering.
      const canonicalPayload = canonicalizeJson(payload);
      const payloadBytes = new TextEncoder().encode(canonicalPayload);

      const jws = await new CompactSign(payloadBytes)
        .setProtectedHeader({
          alg: 'EdDSA',
          kid: this.identity.kid,
        })
        .sign(privateKey);

      return jws;
    } catch (error) {
      throw new Error(
        `Failed to generate JWS: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private formatPrivateKeyAsPEM(base64PrivateKey: string): string {
    const keyData = base64ToBytes(base64PrivateKey);

    // Extract raw 32-byte seed
    const rawKey = keyData.subarray(0, ED25519_KEY_SIZE);

    // Build full PKCS#8 key: header + raw key
    const fullKey = new Uint8Array(ED25519_PKCS8_DER_HEADER.length + rawKey.length);
    fullKey.set(ED25519_PKCS8_DER_HEADER);
    fullKey.set(rawKey, ED25519_PKCS8_DER_HEADER.length);

    const base64Key = bytesToBase64(fullKey);
    const formattedKey = base64Key.match(/.{1,64}/g)?.join('\n') ?? base64Key;

    return (
      '-----BEGIN PRIVATE KEY-----\n' +
      formattedKey +
      '\n-----END PRIVATE KEY-----'
    );
  }

  async verifyProof(
    proof: DetachedProof,
    request: ToolRequest,
    response?: ToolResponse
  ): Promise<boolean> {
    try {
      // The profile is always derived from the proof's own signature-covered
      // `prf` claim — never from generator configuration — so a v2 proof is
      // checked with envelope hashing and a v1 proof with body hashing.
      const expectedHashes = await this.generateCanonicalHashes(
        request,
        response,
        proof.meta.prf ?? RESPONSE_PROOF_PROFILE_V1,
      );

      if (proof.meta.requestHash !== expectedHashes.requestHash) {
        return false;
      }
      if (proof.meta.responseHash !== undefined) {
        if (
          expectedHashes.responseHash === undefined ||
          proof.meta.responseHash !== expectedHashes.responseHash
        ) {
          return false;
        }
      }

      const publicKeyJwk = this.base64PublicKeyToJWK(this.identity.publicKey);
      const cryptoService = new CryptoService(this.cryptoProvider);

      return cryptoService.verifyJWS(proof.jws, publicKeyJwk, {
        expectedKid: this.identity.kid,
        alg: 'EdDSA',
      });
    } catch {
      return false;
    }
  }

  private base64PublicKeyToJWK(publicKeyBase64: string): Ed25519JWK {
    const publicKeyBytes = base64ToBytes(publicKeyBase64);

    if (publicKeyBytes.length !== ED25519_KEY_SIZE) {
      throw new Error(`Invalid Ed25519 public key length: ${publicKeyBytes.length}`);
    }

    return {
      kty: 'OKP',
      crv: 'Ed25519',
      x: base64urlEncodeFromBytes(publicKeyBytes),
      kid: this.identity.kid,
    };
  }
}

export async function createProofResponse(
  request: ToolRequest,
  data: unknown,
  identity: ProofAgentIdentity,
  session: SessionContext,
  cryptoProvider: CryptoProvider,
  options: ProofOptions = {}
): Promise<ToolResponse> {
  const response: ToolResponse = { data };
  const proofGenerator = new ProofGenerator(identity, cryptoProvider);
  const proof = await proofGenerator.generateProof(request, response, session, options);
  response.meta = { proof };
  return response;
}

export function extractCanonicalData(
  request: ToolRequest,
  response: ToolResponse
): {
  request: unknown;
  response: unknown;
} {
  return {
    request: {
      method: request.method,
      ...(request.params ? { params: request.params } : {}),
    },
    response: response.data,
  };
}
