/**
 * Shared Test Helpers for Audit Tests
 *
 * Provides real (non-mocked) crypto, clock, and signing utilities
 * for round-trip and boundary testing. All helpers use NodeCryptoProvider
 * for actual Ed25519 operations.
 */

import * as zlib from 'node:zlib';
import { NodeCryptoProvider } from '../../utils/node-crypto-provider.js';
import { MemoryIdentityProvider, MemoryNonceCacheProvider } from '../../../providers/memory.js';
import { ClockProvider } from '../../../providers/base.js';
import type { AgentIdentity } from '../../../providers/base.js';
import type { Proof } from '../../../types/protocol.js';
import type { VCSigningFunction } from '../../../delegation/vc-issuer.js';
import type { SignatureVerificationFunction } from '../../../delegation/vc-verifier.js';
import { canonicalizeJSON } from '../../../delegation/utils.js';
import type { CompressionFunction, DecompressionFunction } from '../../../delegation/bitstring.js';
import { StatusList2021Manager } from '../../../delegation/statuslist-manager.js';
import { MemoryStatusListStorage } from '../../../delegation/storage/memory-statuslist-storage.js';

// ── Crypto ──────────────────────────────────────────────────────

export function createRealCryptoProvider(): NodeCryptoProvider {
  return new NodeCryptoProvider();
}

export async function createRealIdentity(crypto: NodeCryptoProvider): Promise<AgentIdentity> {
  const provider = new MemoryIdentityProvider(crypto);
  return provider.getIdentity();
}

// ── Clock Providers ─────────────────────────────────────────────
// RealClockProvider is the shipped SystemClockProvider (re-exported below).

/**
 * Clock provider with a controllable "now" for precise boundary testing.
 * `setNow(ms)` moves the clock to an exact millisecond.
 */
export class ControllableClockProvider extends ClockProvider {
  private currentMs: number;

  constructor(nowMs: number = Date.now()) {
    super();
    this.currentMs = nowMs;
  }

  setNow(ms: number): void {
    this.currentMs = ms;
  }

  advance(ms: number): void {
    this.currentMs += ms;
  }

  now(): number {
    return this.currentMs;
  }

  isWithinSkew(timestampMs: number, skewSeconds: number): boolean {
    return Math.abs(this.currentMs - timestampMs) <= skewSeconds * 1000;
  }

  hasExpired(expiresAt: number): boolean {
    return this.currentMs > expiresAt;
  }

  calculateExpiry(ttlSeconds: number): number {
    return this.currentMs + ttlSeconds * 1000;
  }

  format(timestamp: number): string {
    return new Date(timestamp).toISOString();
  }
}

// ── Signing & Verification ──────────────────────────────────────

/**
 * Creates a real VCSigningFunction that produces Ed25519Signature2020 proofs.
 * The signature is over the canonicalized VC (the `canonicalVC` string passed in).
 */
export function createRealSigningFunction(
  crypto: NodeCryptoProvider,
  identity: AgentIdentity
): VCSigningFunction {
  return async (canonicalVC: string, issuerDid: string, kid: string): Promise<Proof> => {
    const data = new TextEncoder().encode(canonicalVC);
    const signature = await crypto.sign(data, identity.privateKey);
    const proofValue = Buffer.from(signature).toString('base64url');

    return {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: kid,
      proofPurpose: 'assertionMethod',
      proofValue,
    };
  };
}

/**
 * Creates a real SignatureVerificationFunction for the VC verifier.
 * Strips `proof`, canonicalizes, and verifies the Ed25519 signature.
 */
export function createRealSignatureVerifier(
  crypto: NodeCryptoProvider
): SignatureVerificationFunction {
  return async (vc, publicKeyJwk) => {
    try {
      const jwk = publicKeyJwk as { x?: string };
      if (!jwk.x) {
        return { valid: false, reason: 'Missing public key x coordinate' };
      }

      // Decode the public key from base64url (JWK x parameter)
      const publicKeyBase64 = Buffer.from(jwk.x, 'base64url').toString('base64');

      // Strip proof and canonicalize
      const vcWithoutProof = { ...vc } as Record<string, unknown>;
      delete vcWithoutProof['proof'];
      const canonicalVC = canonicalizeJSON(vcWithoutProof);
      const data = new TextEncoder().encode(canonicalVC);

      // Extract signature from proof
      const proofValue = vc.proof?.proofValue;
      if (!proofValue) {
        return { valid: false, reason: 'Missing proofValue' };
      }

      const signature = Buffer.from(proofValue as string, 'base64url');
      const isValid = await crypto.verify(data, new Uint8Array(signature), publicKeyBase64);

      return { valid: isValid, reason: isValid ? undefined : 'Signature verification failed' };
    } catch (error) {
      return {
        valid: false,
        reason: `Verification error: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  };
}

// ── Compression (real gzip via Node.js zlib) ────────────────────

export const nodeCompressor: CompressionFunction = {
  compress(data: Uint8Array): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      zlib.gzip(Buffer.from(data), (err, result) => {
        if (err) reject(err);
        else resolve(new Uint8Array(result));
      });
    });
  },
};

export const nodeDecompressor: DecompressionFunction = {
  decompress(data: Uint8Array): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      zlib.gunzip(Buffer.from(data), (err, result) => {
        if (err) reject(err);
        else resolve(new Uint8Array(result));
      });
    });
  },
};

// ── StatusList2021 Manager (real) ───────────────────────────────

export interface RealStatusListSetup {
  manager: StatusList2021Manager;
  storage: MemoryStatusListStorage;
}

export function createRealStatusListManager(
  crypto: NodeCryptoProvider,
  identity: AgentIdentity,
  options?: { statusListBaseUrl?: string; defaultListSize?: number }
): RealStatusListSetup {
  const storage = new MemoryStatusListStorage();
  const signingFunction = createRealSigningFunction(crypto, identity);

  const identityProvider = {
    getDid: () => identity.did,
    getKeyId: () => identity.kid,
  };

  const manager = new StatusList2021Manager(
    storage,
    identityProvider,
    signingFunction,
    nodeCompressor,
    nodeDecompressor,
    options
  );

  return { manager, storage };
}

// ── Re-exports for convenience ──────────────────────────────────

export { MemoryNonceCacheProvider } from '../../../providers/memory.js';
export { MemoryIdentityProvider } from '../../../providers/memory.js';
export { MemoryDelegationGraphStorage } from '../../../delegation/storage/memory-graph-storage.js';
export { MemoryStatusListStorage } from '../../../delegation/storage/memory-statuslist-storage.js';

// RealClockProvider / RealFetchProvider were byte-for-byte duplicates of the
// shipped providers; alias them so the audit tests exercise the real package
// code (did:key resolution is identical; these tests never call fetch()).
export { SystemClockProvider as RealClockProvider } from '../../../providers/system-clock.js';
export { RuntimeFetchProvider as RealFetchProvider } from '../../../providers/runtime-fetch.js';
