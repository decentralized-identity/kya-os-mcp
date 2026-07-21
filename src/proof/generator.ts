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
import type {
  DetachedProof,
  ProofMeta,
  SessionContext,
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
 * under SEP-2133 — is a one-line change. See SPEC §7.6.
 */
export const KYA_OS_PROOF_META_KEY = 'org.kya-os/proof';

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
}

/**
 * Compute the canonical request/response hashes that bind a proof to a specific
 * invocation. This is the SINGLE source of truth for that hashing — used by both
 * the signer (`ProofGenerator`) and the verifier (`ProofVerifier`), so the two
 * cannot drift. `requestHash` = SHA-256 over RFC 8785 `canonicalize({method,params})`;
 * `responseHash` = SHA-256 over `canonicalize(response.data)` (omitted when there
 * is no response body, e.g. denial / step-up proofs).
 *
 * Note: RFC 8785 (via json-canonicalize) drops object members whose value is
 * `undefined`, so a field set to `undefined` hashes identically to that field
 * being absent. Bind only over values that are actually present; never rely on
 * the presence of an `undefined`-valued key to distinguish two payloads.
 *
 * @param hash - a byte → `sha256:<hex>` function (bind a `CryptoProvider.hash`)
 */
export async function computeCanonicalHashes(
  request: ToolRequest,
  response: ToolResponse | undefined,
  hash: (bytes: Uint8Array) => Promise<string>,
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
    canonicalizeJsonBytes(response.data),
  );
  return { requestHash, responseHash };
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
    const hashes = await this.generateCanonicalHashes(request, response);
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
      ...options,
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
    response?: ToolResponse
  ): Promise<{ requestHash: string; responseHash?: string }> {
    return computeCanonicalHashes(request, response, (bytes) =>
      this.cryptoProvider.hash(bytes),
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

      const payload = {
        aud: meta.audience,
        sub: meta.did,
        iss: meta.did,
        requestHash: meta.requestHash,
        ...(meta.responseHash !== undefined && { responseHash: meta.responseHash }),
        ts: meta.ts,
        nonce: meta.nonce,
        sessionId: meta.sessionId,
        ...(meta.scopeId && { scopeId: meta.scopeId }),
        ...(meta.delegationRef && { delegationRef: meta.delegationRef }),
        ...(meta.clientDid && { clientDid: meta.clientDid }),
        ...(meta.outcome && { outcome: meta.outcome }),
        ...(meta.reason && { reason: meta.reason }),
      };

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
      const expectedHashes = await this.generateCanonicalHashes(request, response);

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
