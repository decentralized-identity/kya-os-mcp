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
import { canonicalizeJson } from '../utils/canonical-json.js';
import {
  RESPONSE_PROOF_PROFILE_BODY,
  RESPONSE_PROOF_PROFILE_ENVELOPE,
  validateDetachedProof,
  type DetachedProof,
  type ProofMeta,
  type ResponseProofProfile,
  type SessionContext,
} from '../types/protocol.js';
import type { CryptoProvider } from '../providers/base.js';
import { CryptoService, type Ed25519JWK } from '../utils/crypto-service.js';
import {
  buildProofJwsPayload,
  computeCanonicalHashes,
  findContentBindingMismatch,
  signedProofMeta,
} from './payload.js';
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

/**
 * A request as a proof binds it: `method` and `params`. 1.x producers pass a
 * tool call as `{ method: <tool name>, params: <arguments> }`; verifiers also
 * take the `tools/call` request as sent (SPEC §7.3, see
 * {@link acceptedRequestHashes}).
 */
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
  /** Digest of the delegation chain the call was decided under (SPEC §7.8). */
  delegationChainDigest?: string;
  clientDid?: string;
  outcome?: 'allowed' | 'denied' | 'step_up_required' | 'needs_authorization';
  reason?: string;
  /**
   * Response-proof profile to mint under. Default
   * {@link RESPONSE_PROOF_PROFILE_BODY} (body-only coverage, wire-identical to
   * earlier releases). Under {@link RESPONSE_PROOF_PROFILE_ENVELOPE} the caller passes
   * the ENTIRE MCP result object as `response.data`; hashing covers it with the
   * top-level `_meta` member removed, and the proof carries a signature-covered
   * `prf` claim naming the profile. This is a minting OPTION, not a proof
   * claim — verification always derives the profile from the proof's own `prf`.
   */
  profile?: ResponseProofProfile;
}

/**
 * Internal option key: a `requestHash` already computed over the request, so
 * a proof can be minted later without keeping the request itself. A symbol,
 * so it is not part of {@link ProofOptions} and never rides a string-keyed
 * options object; exported from this module only, not from the package
 * entry points. The value must be what {@link ProofGenerator.hashRequest}
 * returns for the request the proof is about.
 */
export const PRECOMPUTED_REQUEST_HASH: unique symbol = Symbol('kya-os.precomputed-request-hash');

/**
 * The members of a proof's meta the generator sets itself, from its identity, the session, the
 * request and response, and `profile`: never from an option of the same name.
 */
const GENERATOR_SET_MEMBERS = [
  'did', 'kid', 'ts', 'nonce', 'audience', 'sessionId', 'requestHash', 'responseHash', 'prf',
] as const satisfies ReadonlyArray<keyof ProofMeta>;

/**
 * Internal option key: parameters the proof's JWS protected header carries beside `alg` and `kid`,
 * which they never replace. The header is part of the signing input, so the signature covers them,
 * and a verifier that does not know one ignores it (RFC 7515 §4). A symbol, as
 * {@link PRECOMPUTED_REQUEST_HASH} is, and exported from this module only: a request proof states
 * its delegation this way (`../delegation/stated-delegation.ts`).
 */
export const PROTECTED_HEADER_PARAMETERS: unique symbol = Symbol('kya-os.protected-header-parameters');

/** {@link ProofOptions} with the internal precomputed request hash and protected header parameters. */
export interface InternalProofOptions extends ProofOptions {
  [PRECOMPUTED_REQUEST_HASH]?: string;
  [PROTECTED_HEADER_PARAMETERS]?: Readonly<Record<string, string>>;
}

// Re-exported so proof consumers can import the profile vocabulary from the
// module that mints and hashes proofs, without reaching into types/protocol.
export { RESPONSE_PROOF_PROFILE_BODY, RESPONSE_PROOF_PROFILE_ENVELOPE };
export type { ResponseProofProfile };

export {
  acceptedRequestHashes,
  buildProofJwsPayload,
  computeCanonicalHashes,
  findContentBindingMismatch,
} from './payload.js';

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
   * @param options - Optional proof metadata (scopeId, delegationRef, delegationChainDigest, clientDid)
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
    // claim form is `prf`, set only for the envelope profile (the body profile stays byte-identical on the wire).
    const { profile = RESPONSE_PROOF_PROFILE_BODY, ...metaOptions } = options;
    // The members the generator sets, `prf` among them, which derives ONLY from
    // `profile`, always win. TypeScript keeps them out of ProofOptions, but a
    // plain-JS caller could still pass one: strip each, so no value of the
    // caller's can ride the spread into the signed payload in its place, and no
    // `responseHash` binds a response the generator was not given.
    for (const member of GENERATOR_SET_MEMBERS) Reflect.deleteProperty(metaOptions, member);
    // A request hash computed earlier, when the caller no longer holds the
    // request; never copied into the meta.
    const precomputed = (options as InternalProofOptions)[PRECOMPUTED_REQUEST_HASH];
    Reflect.deleteProperty(metaOptions, PRECOMPUTED_REQUEST_HASH);
    // Parameters for the protected header, which is signed; never copied into the meta either.
    const headerParameters = (options as InternalProofOptions)[PROTECTED_HEADER_PARAMETERS];
    Reflect.deleteProperty(metaOptions, PROTECTED_HEADER_PARAMETERS);
    const hashes = await this.generateCanonicalHashes(request, response, profile);
    if (precomputed !== undefined) hashes.requestHash = precomputed;
    const proofNonce = base64urlEncodeFromBytes(
      await this.cryptoProvider.randomBytes(16),
    );

    // Only what the signature covers goes into the meta (`signedProofMeta`): an option the
    // schema does not name, or an optional claim given as "", never reaches it.
    const meta: ProofMeta = signedProofMeta({
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
      ...(profile === RESPONSE_PROOF_PROFILE_ENVELOPE
        ? { prf: RESPONSE_PROOF_PROFILE_ENVELOPE }
        : {}),
      ...metaOptions,
    });

    const jws = await this.generateJWS(meta, headerParameters);

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

  private async generateJWS(meta: ProofMeta, headerParameters: Readonly<Record<string, string>> = {}): Promise<string> {
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

      // `alg` and `kid` come first and are the generator's own, whatever else the header is given.
      const own = { alg: 'EdDSA', kid: this.identity.kid };
      const jws = await new CompactSign(payloadBytes)
        .setProtectedHeader({ ...own, ...headerParameters, ...own })
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

  /**
   * Check that a proof was signed by this generator's identity over `request`
   * and, when the proof binds one, `response`. Every `meta` member it reads is
   * checked through the signature: it reads only the meta the signature covers
   * (`signedProofMeta`), the JWS is verified against the payload rebuilt from
   * that, and a payload it embeds must be that one. A proof that binds a
   * response fails without one, and a proof that binds none fails with one.
   * `request` may be given in either shape (see {@link acceptedRequestHashes}).
   *
   * This checks the artifact only, with no freshness or replay state; verify
   * proofs received over the wire with `ProofVerifier.verifyProof`.
   */
  async verifyProof(
    proof: DetachedProof,
    request: ToolRequest,
    response?: ToolResponse
  ): Promise<boolean> {
    try {
      if (!validateDetachedProof(proof).success) return false;
      const meta = signedProofMeta(proof.meta);
      // iss/sub cover meta.did; the protected header's kid is pinned below.
      if (meta.did !== this.identity.did || meta.kid !== this.identity.kid) {
        return false;
      }

      const mismatch = await findContentBindingMismatch(
        meta,
        { request, ...(response !== undefined ? { response } : {}) },
        (bytes) => this.cryptoProvider.hash(bytes),
      );
      if (mismatch !== undefined) return false;

      const publicKeyJwk = this.base64PublicKeyToJWK(this.identity.publicKey);
      const cryptoService = new CryptoService(this.cryptoProvider);

      return await cryptoService.verifyJWS(proof.jws, publicKeyJwk, {
        detachedPayload: canonicalizeJson(buildProofJwsPayload(meta)),
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
