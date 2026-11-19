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
import type { DelegationCredential, ResponseProofProfile } from "../types/protocol.js";

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
   * Optional custom DID resolver, asked first. If it returns null, middleware
   * falls back to `didResolvers`, then built-in did:key resolution and
   * fetch-backed did:web resolution. When none of them finds a document, the
   * refusal shows the failure of the first that reported one through
   * `DIDResolver.lastFailure`, so this resolver's before any the middleware
   * asks after it. One deadline, `dependencyTimeoutMs`, covers the whole
   * resolution, and the document it returns is held to the limits of SPEC
   * §4.4.2 on every call, with an `id` that is a DID: a document they refuse
   * ends the resolution, with no fallback. The gate reads its own copy of the
   * document, made as it is checked; the object returned is neither frozen nor
   * changed.
   */
  didResolver?: DIDResolver;
  /**
   * Optional fetch provider for did:web documents, and for the factories in
   * `didResolvers`. If omitted, middleware uses a `RuntimeFetchProvider` over
   * the runtime's global fetch when there is one. Every did:web read through
   * it is bounded (SPEC §4.4.2) and held to the private-network rule: its
   * `fetch` returns a `Response` whose `body` is a WHATWG `ReadableStream`,
   * read as it streams, or a response with a `text()` or `json()` method, such
   * as SafeFetch's, read through it under the same limits; and it must pass
   * `redirect: "manual"` on, so each redirect is followed and checked by hand.
   * Its `allowPrivateNetworkHosts`, when `true`, admits private IP literals and
   * local names: the production opt-in for intranet hosts. In local
   * development set `KyaOsConfig.development` instead.
   */
  fetchProvider?: FetchProvider;
  /**
   * Optional DID method resolver registry. Entries are keyed by DID method
   * (for example, "cheqd") and are checked before the built-in did:key and
   * did:web fallback, whose failure never replaces one an entry reports
   * through `DIDResolver.lastFailure`. An entry that throws ends the
   * resolution, as `didResolver` does: the DID is refused with the code and
   * words of a `RefusalError` it throws, or as `did_unavailable`, its error
   * logged with the entry's method and never shown. Factory entries receive
   * the active fetch provider.
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
   * It runs before any credential is checked, on the presented leaf (for a
   * VC-JWT, its payload before the envelope's signature is checked), so it
   * must treat the leaf as unauthenticated and bound its own I/O: no limit
   * or deadline of the gate covers it. The chain it returns is verified.
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
   * DIDs allowed to issue root delegations, the chain's Responsible Party
   * (SPEC §6). When set, a delegation whose root credential is issued by any
   * other DID is rejected, both when presented and when a stored grant is
   * reused. The root's `issuer` is compared whole with each entry before any
   * DID is resolved, status list read or signature checked, and the root is
   * then verified with a key of that issuer's DID document. Each entry must
   * be a DID, a string that starts with `did:` and has no white space around
   * it; creating the middleware with any other value throws a `TypeError`.
   * An empty list trusts no issuer.
   *
   * Unset, any issuer would be accepted, including an agent that signs a
   * delegation for itself. So a server that gates a tool on a delegation
   * needs it: outside development, `wrapWithDelegation` throws an `Error`
   * naming each fix while it is unset, unless `allowAnyRootIssuer` is
   * `true`. With `allowAnyRootIssuer: true`, or with `KyaOsConfig.development`
   * `true`, the server starts and warns once, when the first tool is
   * wrapped. A server that gates no tool on a delegation needs none of
   * this, and is not warned. Set it with `allowAnyRootIssuer: true` and
   * creating the middleware throws a `TypeError`.
   */
  trustedRootIssuers?: readonly string[];
  /**
   * Accept a delegation from any issuer, by name: the opt-out from
   * `trustedRootIssuers` for a server that gates a tool on a delegation
   * outside development, such as one whose trust decision is made by its
   * own code after the gate. Any issuer means any: an agent can sign a
   * delegation for itself and pass the gate, so prefer `trustedRootIssuers`.
   * With it `true` the server starts and warns once, when the first tool
   * is wrapped with `wrapWithDelegation`; absent or `false` changes
   * nothing. Creating the middleware throws a `TypeError` for a value that
   * is not a boolean, and for `true` beside a `trustedRootIssuers` list,
   * an empty one included: set one or the other.
   */
  allowAnyRootIssuer?: boolean;
  /**
   * Local cost limit: the most credentials this server will verify in one
   * delegation chain, root to leaf inclusive, checked once the chain is
   * resolved and before any of them is verified. Each costs a signature
   * check and possibly a DID resolution. It bounds the server's own work,
   * not how far authority may be delegated.
   * Unset verifies any length; a value that is not a positive integer is
   * refused at startup. It does not bound `resolveDelegationChain` itself, so
   * a resolver that fetches one parent at a time should apply its own limit.
   */
  maxChainLength?: number;
  /**
   * How long, in milliseconds, the delegation gate waits for each dependency it
   * asks: a DID resolution, a did:web or status-list read through the default
   * `fetchProvider`, `statusListResolver`, `resolveDelegationChain` and
   * `revocationChecker`. A number greater than 0 and at most 2,147,483,647.
   * Default 5,000. Any other value is refused at startup with a `TypeError`.
   * A `fetchProvider`, `didResolver` or `statusListResolver` built by the host
   * takes its own `dependencyTimeoutMs`.
   */
  dependencyTimeoutMs?: number;
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
   * A request proof is EdDSA, so only an Ed25519 did:key can be bound:
   * `'enforce'` refuses a did:key subject of any other key, a P-256 one say, or
   * one that does not decode, since no proof can bind it.
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
    /**
     * Signature-result TTL in milliseconds: a finite number, 0 or more, where `0` disables caching.
     * Default 60_000. Any other value throws a `TypeError` naming the option when the middleware is
     * created.
     */
    ttlMs?: number;
    /**
     * Maximum cached signature results (FIFO eviction): a whole number greater than 0. Default 1000.
     * Any other value throws a `TypeError` naming the option when the middleware is created.
     */
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
   * (single-process only). For multi-instance deployments inject a shared
   * {@link NonceCacheProvider} whose `consume()` is an atomic conditional insert
   * with expiry (Redis `SET NX PX`, a DynamoDB conditional write, a Durable
   * Object transaction). Eventually consistent stores such as Workers KV cannot
   * make that claim atomic on their own. Set here, not on `session`, so there is
   * exactly one cache and the two cannot diverge.
   */
  nonceCache?: NonceCacheProvider;
  /**
   * Refuse a `nonceCache` without an atomic `consume()`: middleware creation
   * throws instead of falling back to `has()` then `add()`, which lets concurrent
   * duplicates of one signed request through. Applies to the handshake and to
   * holder binding. Default false, with a startup warning for such a cache.
   */
  requireAtomicNonce?: boolean;
  /**
   * How long, in milliseconds, a wrapper's result may wait to be sent before
   * its proof is given up (default 300000, five minutes). Proofs are made
   * where the KYA-OS transport sends a result, once: a result delivered later
   * than this, or a second time (an MCP task result fetched again), goes out
   * without a proof and with `proofError`, and the audit trail records
   * `PROOF_EXPIRED`. A result never sent is closed with `PROOF_NOT_SENT` when
   * the window ends. Raise it for task results fetched later; memory stays
   * bounded by the count and size caps on waiting proofs. At most
   * 2147483647 (2^31 - 1, about 24.8 days), the longest timer a JavaScript
   * runtime keeps; a larger value, zero, or a value that is not a finite
   * number is refused.
   */
  pendingProofTtlMs?: number;
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
  /**
   * Response-proof profile every proof this server mints is bound under
   * (SPEC §7.3).
   *
   * - `"org.kya-os/response-proof.body"` (default): `responseHash` covers the
   *   response BODY only (the MCP `content` array). Wire-identical to earlier
   *   releases — any existing verifier keeps working.
   * - `"org.kya-os/response-proof.envelope"`: `responseHash` covers the ENTIRE result
   *   object with the top-level `_meta` member removed, so `structuredContent`,
   *   `isError`, and `resultType` are authenticated. Each proof carries a
   *   signature-covered `prf` claim naming the profile, so verification cannot
   *   silently fall back to body-only semantics.
   *
   * Opting into the envelope profile requires clients whose verifiers
   * understand `prf` (this package's verifier accepts both profiles, keyed off
   * each proof's own claim); an older verifier rejects envelope-profile proofs
   * outright rather than mis-verifying them. The default stays body-only so
   * existing verifiers keep working; opt in once your client population
   * verifies the envelope profile.
   *
   * Proofs under either profile are made by the KYA-OS transport when it
   * sends a result, after the MCP SDK has finished it: the SDK changes a
   * result after the handler returns (`resultType` on the 2026-07-28
   * revision, a filled-in or appended `content`), and the proof covers what
   * the client receives. `withKyaOs` wraps the transport it is connected
   * through; wrap one yourself with `createKyaOsTransport`. Once a KYA-OS
   * transport has been created for the middleware, every wrapper result must
   * go out through one: while none is open, every wrapper and `proveOutcome`
   * throws on entry.
   */
  responseProofProfile?: ResponseProofProfile;
  /** Delegation verification overrides */
  delegation?: KyaOsDelegationConfig;
  /**
   * Local development: every resolver and reader the middleware builds reads
   * did:web documents on private and local hosts, such as a `*.localhost`
   * name, as a fetch provider with `allowPrivateNetworkHosts: true` does,
   * whatever `delegation.fetchProvider` is, and each factory in
   * `delegation.didResolvers` is told so in its context. Nothing else about
   * those reads changes: the scheme rule, checked redirects, byte caps and
   * deadlines all hold. A tool may also be wrapped with `wrapWithDelegation`
   * while `delegation.trustedRootIssuers` is unset, accepting any issuer,
   * with one warning. While `NODE_ENV` is `production`, creating the
   * middleware throws; the first time it is on in a process, it warns once.
   * A runtime with no `process`, such as Workers, has no `NODE_ENV` to read
   * unless its bundler defines `process.env.NODE_ENV`, so there it does not
   * throw: keep it out of production configuration.
   * To read intranet hosts in production, give the fetch provider
   * `allowPrivateNetworkHosts: true`. Any value but a boolean throws a
   * `TypeError`.
   */
  development?: boolean;
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
