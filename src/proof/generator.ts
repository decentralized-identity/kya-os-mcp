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
import { canonicalize } from 'json-canonicalize';
import type {
  DetachedProof,
  ProofMeta,
  CanonicalHashes,
  SessionContext,
} from '../types/protocol.js';
import type { CryptoProvider } from '../providers/base.js';
import { CryptoService, type Ed25519JWK } from '../utils/crypto-service.js';
import { base64ToBytes, base64urlEncodeFromBytes, bytesToBase64 } from '../utils/base64.js';
import { ED25519_PKCS8_DER_HEADER, ED25519_KEY_SIZE } from '../utils/ed25519-constants.js';

export interface ProofAgentIdentity {
  did: string;
  kid: string;
  privateKey: string;
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
    response: ToolResponse,
    session: SessionContext,
    options: ProofOptions = {}
  ): Promise<DetachedProof> {
    const hashes = await this.generateCanonicalHashes(request, response);

    const meta: ProofMeta = {
      did: this.identity.did,
      kid: this.identity.kid,
      ts: Math.floor(Date.now() / 1000),
      nonce: session.nonce,
      audience: session.audience,
      sessionId: session.sessionId,
      requestHash: hashes.requestHash,
      responseHash: hashes.responseHash,
      ...options,
    };

    const jws = await this.generateJWS(meta);

    return { jws, meta };
  }

  private async generateCanonicalHashes(
    request: ToolRequest,
    response: ToolResponse
  ): Promise<CanonicalHashes> {
    const canonicalRequest = {
      method: request.method,
      ...(request.params ? { params: request.params } : {}),
    };
    const canonicalResponse = response.data;

    const requestHash = await this.generateSHA256Hash(canonicalRequest);
    const responseHash = await this.generateSHA256Hash(canonicalResponse);

    return { requestHash, responseHash };
  }

  private async generateSHA256Hash(data: unknown): Promise<string> {
    const canonicalJson = this.canonicalizeJSON(data);
    const encoded = new TextEncoder().encode(canonicalJson);
    return this.cryptoProvider.hash(encoded);
  }

  private canonicalizeJSON(obj: unknown): string {
    return canonicalize(obj as Parameters<typeof canonicalize>[0]);
  }

  private async generateJWS(meta: ProofMeta): Promise<string> {
    try {
      const privateKeyPem = this.formatPrivateKeyAsPEM(this.identity.privateKey);
      const privateKey = await importPKCS8(privateKeyPem, 'EdDSA');

      const payload = {
        aud: meta.audience,
        sub: meta.did,
        iss: meta.did,
        requestHash: meta.requestHash,
        responseHash: meta.responseHash,
        ts: meta.ts,
        nonce: meta.nonce,
        sessionId: meta.sessionId,
        ...(meta.scopeId && { scopeId: meta.scopeId }),
        ...(meta.delegationRef && { delegationRef: meta.delegationRef }),
        ...(meta.clientDid && { clientDid: meta.clientDid }),
      };

      // Use canonicalized JSON (RFC 8785) for deterministic payload serialization.
      // This ensures signature verification succeeds regardless of JSON key ordering.
      const canonicalPayload = canonicalize(payload as Parameters<typeof canonicalize>[0]);
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
    response: ToolResponse
  ): Promise<boolean> {
    try {
      const expectedHashes = await this.generateCanonicalHashes(request, response);

      if (
        proof.meta.requestHash !== expectedHashes.requestHash ||
        proof.meta.responseHash !== expectedHashes.responseHash
      ) {
        return false;
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
