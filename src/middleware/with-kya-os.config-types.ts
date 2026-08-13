/**
 * KYA-OS Middleware — configuration input types.
 *
 * The identity / session / delegation configuration a caller passes to
 * `withKyaOs` / `createKyaOsMiddleware`. Split from the API-surface types
 * (`./with-kya-os.types.ts`), which re-exports these so importers are unchanged.
 */

import type { FetchProvider, NonceCacheProvider } from "../providers/base.js";
import type { AuditLogProvider } from "../providers/audit-log.js";
import type { AuditTrailService } from "../audit/service.js";
import type { AuditAssuranceProfile, AuditCapabilities } from "../audit/assurance.js";

export interface KyaOsAuditTrail {
  record: AuditTrailService['record'];
  /** Must match `capabilities.profile`; profiles above AAP-0 require capabilities. */
  auditProfile?: AuditAssuranceProfile;
  capabilities?: AuditCapabilities;
  /** Opt in to recording bounded tool names; omitted by the privacy-minimal default. */
  includeToolNames?: boolean;
}
import type { GrantStore } from "../providers/grant-store.js";
import type { SessionConfig } from "../session/manager.js";
import type {
  DIDResolver,
  StatusListResolver,
} from "../delegation/vc-verifier.js";
import type { DIDResolverRegistry } from "../delegation/did-resolver-registry.js";
import type { RevocationChecker } from "../delegation/chain-enforcement.js";
import type { DelegationCredential } from "../types/protocol.js";

export interface KyaOsIdentityConfig {
  did: string;
  kid: string;
  /**
   * The Ed25519 signing key: a base64 raw private key, or a `CryptoKey` handle
   * — including a non-extractable one (passkey-PRF- or HSM/KMS-fronted). The key
   * is used only to sign per-request proofs (via {@link ProofGenerator}), so a
   * handle lets a deployment keep secret key material inside its trust boundary
   * end-to-end, per SPEC §4.5. See {@link ProofAgentIdentity.privateKey}.
   */
  privateKey: string | CryptoKey;
  publicKey: string;
  agentName?: string;
}

export const KYA_OS_ACTIONS = ["handshake", "identity", "reputation"] as const;
export type KyaOsAction = (typeof KYA_OS_ACTIONS)[number];

export interface KyaOsDelegationConfig {
  /**
   * Optional custom DID resolver. If it returns null, middleware falls back to
   * built-in did:key resolution and fetch-backed did:web resolution.
   */
  didResolver?: DIDResolver;
  /**
   * Optional fetch provider used for did:web resolution.
   * If omitted, middleware falls back to the runtime global fetch when available.
   */
  fetchProvider?: FetchProvider;
  /**
   * Optional DID method resolver registry. Entries are keyed by DID method
   * (for example, "cheqd") and are checked before the built-in did:key and
   * did:web fallback. Factory entries receive the active fetch provider.
   */
  didResolvers?: DIDResolverRegistry;
  /**
   * Resolver for StatusList2021 checks. Credentials with credentialStatus are
   * rejected when no resolver is configured.
   */
  statusListResolver?: StatusListResolver;
  /**
   * Resolve ancestor credentials for a delegated chain. The returned array may
   * contain only ancestors (root -> parent) or the full chain (root -> leaf).
   */
  resolveDelegationChain?: (
    leafCredential: DelegationCredential,
  ) => Promise<DelegationCredential[]>;
  /**
   * Graph-backed ancestor-revocation check. When provided, the chain walk also
   * verifies the leaf is not revoked via a cascade-revoked ANCESTOR — caught
   * independently of how `resolveDelegationChain` hydrated the chain (it walks
   * the delegation graph + StatusList). `CascadingRevocationManager` is the
   * reference adapter. Omit to keep the prior per-credential-status behavior.
   */
  revocationChecker?: RevocationChecker;
  /**
   * Holder-of-key enforcement for inbound calls (spec §11.8). A valid delegation
   * is a *bearer* credential; holder binding additionally requires the caller to
   * present a per-request proof (`_kyaos_proof`) signed by the delegation
   * SUBJECT's key, closing theft-replay for the key-bearing population.
   *
   * - `'off'` (default): no holder-binding check — current behavior, unchanged.
   * - `'warn'`: check and log failures (missing/unbound proof), but still allow.
   * - `'enforce'`: reject calls whose proof is missing or does not bind the
   *   subject. **Breaking for callers that don't yet send `_kyaos_proof`** — opt
   *   in only once your agents mint request proofs.
   *
   * Scope is did:key subjects (the DID encodes the key). did:web and other
   * subjects are deferred to cnf-based binding (phase 2) and logged, never
   * rejected — so enabling `'enforce'` never breaks did:web traffic.
   */
  holderBinding?: "off" | "warn" | "enforce";
  /**
   * Tuning for the delegation verifier's SIGNATURE-verification cache (the
   * expensive DID-resolve + crypto dimension). Revocation status and basic
   * checks (expiry) are always evaluated fresh on every call and are NOT
   * affected by this setting. Set `ttlMs: 0` to disable signature caching
   * entirely (e.g. when issuer key rotation must take effect immediately).
   */
  verificationCache?: {
    /** Signature-result TTL in milliseconds. Default 60_000. `0` disables caching. */
    ttlMs?: number;
    /** Maximum cached signature results (FIFO eviction). Default 1000. */
    maxEntries?: number;
  };
}

export interface KyaOsConfig {
  /** Agent identity (DID + key material) */
  identity: KyaOsIdentityConfig;
  /** Session configuration overrides */
  session?: Omit<SessionConfig, "nonceCache">;
  /**
   * Replay-protection store, shared by the session handshake AND inbound holder
   * binding so both draw on one nonce namespace. Defaults to an in-memory store
   * (single-process only); inject a Redis / Durable Object / KV-backed
   * {@link NonceCacheProvider} for multi-instance deployments. Set here, not on
   * `session`, so there is exactly one cache and the two cannot diverge.
   */
  nonceCache?: NonceCacheProvider;
  /**
   * Durable store for approved authorization grants, enabling the no-paste
   * retry: an agent that already obtained a grant can call again — even on a
   * fresh instance with empty memory, or after a restart — without re-pasting
   * the delegation. Defaults to an in-memory {@link MemoryGrantStore}
   * (single-process only); inject a Redis / Durable Object / DB-backed
   * {@link GrantStore} for multi-instance deployments. Mirrors `nonceCache?`.
   *
   * For the no-paste retry to actually RESOLVE a bound grant, the call must be
   * resolvable: either holder binding is `'enforce'` and the agent presents a
   * per-request `_kyaos_proof` (agent-anchored `getByAgent`), or the client
   * threads its `sessionId` (session-bearer `getBySession`). A grant that would
   * be unresolvable — holder binding `'off'` with no threaded `sessionId` — is
   * NOT bound (it would only orphan a store row); such flows achieve durability
   * by re-presenting the delegation instead.
   */
  grantStore?: GrantStore;
  /**
   * Whether to ALSO emit the detached proof under the legacy bare `_meta.proof`
   * key (in addition to the namespaced `org.kya-os/proof`). The value is
   * identical under both keys and `_meta` is excluded from the response hash
   * (§7.6), so the mirror never affects signatures or verification.
   *
   * Default `true` — a transition aid so pre-1.1 clients that still read bare
   * `proof` keep working. Set `false` once your clients read the namespaced key
   * (the examples do this for a clean single-key Inspector view).
   *
   * Stays ON by default for the whole 1.x line (a pre-1.1 reader of bare
   * `_meta.proof` would otherwise silently get no proof); the legacy mirror is
   * dropped at 2.0.
   */
  emitLegacyProofKey?: boolean;
  /** Delegation verification overrides */
  delegation?: KyaOsDelegationConfig;
  /**
   * When true, automatically creates a session on the first tool call
   * if no session exists. Useful for demos and development where
   * MCP clients don't support the `_kyaos` handshake flow.
   * In production, KYA-OS-aware runtimes should execute handshake before tool calls.
   */
  autoSession?: boolean;
  /**
   * Verifiable audit trail service. Set `false` to explicitly advertise no
   * audit assurance. Cannot be combined with the legacy `auditLog` sink.
   */
  audit?: KyaOsAuditTrail | false;
  /**
   * Sink for retaining audit records of verified tool calls. Defaults to a
   * no-op; supply an {@link AuditLogProvider} (e.g. a durable, append-only
   * implementation) to capture an audit trail.
   */
  auditLog?: AuditLogProvider;
}
