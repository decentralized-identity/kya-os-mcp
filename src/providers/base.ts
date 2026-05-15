/**
 * Base Provider Classes
 *
 * Abstract classes that define the provider interfaces for
 * platform-specific implementations.
 */

import type { DIDDocument } from '../delegation/vc-verifier.js';
import type { StatusList2021Credential, DelegationRecord } from '../types/protocol.js';

export abstract class CryptoProvider {
  abstract sign(data: Uint8Array, privateKey: string): Promise<Uint8Array>;
  abstract verify(data: Uint8Array, signature: Uint8Array, publicKey: string): Promise<boolean>;
  abstract generateKeyPair(): Promise<{ privateKey: string; publicKey: string }>;
  /**
   * Compute SHA-256 hash of data.
   * Returns "sha256:<hex>" format for cross-platform parity.
   */
  abstract hash(data: Uint8Array): Promise<string>;
  abstract randomBytes(length: number): Promise<Uint8Array>;
}

export abstract class ClockProvider {
  abstract now(): number;
  abstract isWithinSkew(timestamp: number, skewSeconds: number): boolean;
  abstract hasExpired(expiresAt: number): boolean;
  abstract calculateExpiry(ttlSeconds: number): number;
  abstract format(timestamp: number): string;
}

export abstract class FetchProvider {
  abstract resolveDID(did: string): Promise<DIDDocument | null>;
  abstract fetchStatusList(url: string): Promise<StatusList2021Credential | null>;
  abstract fetchDelegationChain(id: string): Promise<DelegationRecord[]>;
  abstract fetch(url: string, options?: unknown): Promise<Response>;
}

export abstract class StorageProvider {
  abstract get(key: string): Promise<string | null>;
  abstract set(key: string, value: string): Promise<void>;
  abstract delete(key: string): Promise<void>;
  abstract exists(key: string): Promise<boolean>;
  abstract list(prefix?: string): Promise<string[]>;
}

export abstract class NonceCacheProvider {
  abstract has(nonce: string, agentDid?: string): Promise<boolean>;
  abstract add(nonce: string, ttlSeconds: number, agentDid?: string): Promise<void>;
  abstract cleanup(): Promise<void>;
  abstract destroy(): Promise<void>;
}

/**
 * Generic identity bundle backing the MCP-I protocol primitives.
 *
 * Holds the DID, verification-method id, and key material for any
 * subject the protocol speaks about (agents, servers, users, services).
 * The wire format (delegations, proofs, status lists) is subject-
 * agnostic, so the in-memory representation is too.
 *
 * `privateKey` is optional because verifier-only deployments hold
 * only public material — the private key lives elsewhere (HSM, wallet,
 * delegated issuer). Issuance flows that need to sign should narrow
 * to {@link AgentIdentity} or check `privateKey` explicitly.
 */
export interface Identity {
  /** Subject DID (e.g. `did:key:...`, `did:web:...`). */
  did: string;
  /** Verification-method id (`<did>#<fragment>`). */
  kid: string;
  /** Public key material as base64-encoded raw bytes (Ed25519: 32 bytes). */
  publicKey: string;
  /** Private key material as base64-encoded raw bytes. Absent on verifier-only holders. */
  privateKey?: string;
  /** ISO-8601 creation timestamp. */
  createdAt: string;
  /** Free-form, implementation-defined metadata. */
  metadata?: Record<string, unknown>;
}

/**
 * Agent-flavoured {@link Identity} used by MCP server implementations.
 *
 * Adds the agent-lifecycle fields (`type`) and re-tightens `privateKey`
 * to required, since servers issue and sign on behalf of the agent
 * and therefore always hold private material in this context.
 */
export interface AgentIdentity extends Identity {
  privateKey: string;
  type: 'development' | 'production';
}

export abstract class IdentityProvider {
  abstract getIdentity(): Promise<AgentIdentity>;
  abstract saveIdentity(identity: AgentIdentity): Promise<void>;
  abstract rotateKeys(): Promise<AgentIdentity>;
  abstract deleteIdentity(): Promise<void>;
}
