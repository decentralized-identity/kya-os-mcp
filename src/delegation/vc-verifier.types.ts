/**
 * Delegation Credential Verifier — shared types.
 *
 * The result/option/resolver shapes for the verifier + its stateless check
 * functions. Re-exported from `./vc-verifier.ts`, so existing imports of
 * `DIDResolver` / `SignatureVerificationFunction` / … are unchanged.
 */

import type { RefusalCode } from "../refusal-codes.js";
import type { CredentialStatus } from "../types/protocol.js";
import type { StatusCheckContext } from "../utils/statuslist-acceptance.js";

/**
 * The code a refusal carries beside its `reason`, and whether it is transient. Both are set on every
 * refusal the library returns and absent from a result that verified. They are optional in the types
 * so that a result built by other code, such as a test double or a verifier the host supplies, still
 * fits.
 */
export interface RefusalCoding {
  /** Why the verifier refused, as a stable value to branch on (see `REFUSAL_CODES`). */
  code?: RefusalCode;
  /** Whether the verifier could not decide because a dependency failed, so the same request may succeed later. */
  transient?: boolean;
}

/**
 * Machine-readable outcome of the credential-status check. Both values still
 * DENY (fail-closed) — the label only tells the consumer *why*, so retry vs
 * re-consent can be decided:
 * - `revoked`: the status bit is set — a settled deny. Re-consent required.
 * - `status_unresolvable`: the status could not be read (resolver missing,
 *   threw, or infra unavailable). Deny now, but the credential may still be
 *   good; safe to retry once status resolution recovers.
 */
export type StatusOutcome = "revoked" | "status_unresolvable";

/**
 * The signature/DID-validity dimension of a verification — the expensive,
 * slow-changing half that the verifier caches. Shared by the Data Integrity
 * path (`verifySignature`) and the VC-JWT path (`verifyVcJwtSignature`,
 * whose `VcJwtSignatureResult` is structurally identical).
 */
export interface SignatureVerificationResult extends RefusalCoding {
  valid: boolean;
  reason?: string;
  durationMs?: number;
}

/** The verdict on a delegation credential, with its code and whether it is transient when it is refused. */
export interface DelegationVCVerificationResult extends RefusalCoding {
  valid: boolean;
  reason?: string;
  /**
   * Present only when a status check produced a deny. Distinguishes a settled
   * `revoked` from a transient `status_unresolvable` without weakening
   * fail-closed — both still deny (see {@link StatusOutcome}).
   */
  statusOutcome?: StatusOutcome;
  /**
   * On failure, the check that failed. `complete` only ever accompanies
   * `valid: true` (both signature and status ran and passed).
   */
  stage: "basic" | "signature" | "status" | "complete";
  /**
   * True when the SIGNATURE verification was served from the per-instance
   * cache. Basic checks (schema/expiry) and revocation status are always
   * evaluated fresh on every call — only the signature/DID-validity result
   * is ever cached. On a hit, `metrics.signatureCheckMs` reports the
   * near-zero cache retrieval, not the original compute.
   */
  cached?: boolean;
  metrics?: {
    basicCheckMs?: number;
    signatureCheckMs?: number;
    statusCheckMs?: number;
    totalMs: number;
  };
  checks?: {
    basicValid?: boolean;
    signatureValid?: boolean;
    /** Absent when the status was not checked: it is read only once the signature has verified. */
    statusValid?: boolean;
  };
}

export interface VerifyDelegationVCOptions {
  skipCache?: boolean;
  skipSignature?: boolean;
  skipStatus?: boolean;
  didResolver?: DIDResolver;
  statusListResolver?: StatusListResolver;
}

export interface DIDResolver {
  resolve(did: string): Promise<DIDDocument | null>;
  /**
   * Why this resolver's last resolution of `did` found no document, or `undefined` when it found
   * one, was never asked, or cannot say. Optional: the verifier reads a resolver without it as
   * before. These resolvers of the library have it: `DidWebResolver` and `createDidWebResolver`,
   * `createDidKeyResolver`, `DidCheqdResolver`, `createDidCheqdResolver` and `cheqdResolver`, and
   * the resolver the delegation middleware builds. `RuntimeFetchProvider.resolveDID` is not a
   * resolver of this kind and reports none. When the verifier refuses a credential as `Could not
   * resolve issuer DID: "<did>"` over a resolver that has it, it codes the refusal by the
   * failure's `cause`, and appends its `detail` in parentheses only where that tells the party that
   * presented the credential nothing the verifier's network answered: where the cause is
   * `deadline_exceeded`, whose timing the presenter observes anyway, or where one of the library's
   * resolvers decided the failure from the DID alone, before any request or DNS lookup (the
   * private-network rule refusing an IP literal or a local name the DID names, a DID of a method no
   * resolver serves, a did:key that does not decode, a did:cheqd DID of no network the resolver
   * asks). Any other detail was learned from the network, or comes from a resolver the library
   * cannot vouch for, and is not shown: the library's resolvers log it for the operator. A resolver
   * that wraps one of them may pass its failure on as it is, as
   * `lastFailure: (did) => inner.lastFailure?.(did)`, and the refusal shows what it would have.
   * The delegation middleware's resolver, which asks the host's resolvers before its own, reports
   * the failure of the first resolver it asked that reported one, so the host's is the one shown.
   * `lastFailure` reports the last failure for the DID, so a resolution of the same DID that ends
   * in between may answer for it: read it as a diagnosis, never as a security decision.
   */
  lastFailure?(did: string): DidResolutionFailure | undefined;
}

/**
 * Why a resolver found no document for a DID:
 *
 * - `host_refused`: the read's own rules refused the host, the private-network rule or the scheme
 *   rule, on the document's URL or on a redirect. A name that resolves to a private address is
 *   `unavailable`, as a name that does not resolve is, since the lookup decided it; the log says
 *   `host_refused`.
 * - `deadline_exceeded`: no document arrived within the resolver's deadline.
 * - `unavailable`: the host could not be reached, or answered with something other than a document:
 *   an HTTP error, no body, or text that is not JSON.
 * - `too_large`: the host answered with more bytes than any DID document may hold.
 * - `invalid_document`: what was read is not a valid document of this DID; or the DID is one the
 *   resolver can never resolve: a did:key whose public key does not decode, a did:web DID that names
 *   no URL, or, for a resolver that composes others, as the delegation middleware's does, a DID of a
 *   method none of them serves. A resolver of some methods records nothing for a DID of another.
 */
export type DidResolutionFailureCause = 'host_refused' | 'deadline_exceeded' | 'unavailable' | 'too_large' | 'invalid_document';

/** The cause of a resolver's failure to find a DID's document, and what to tell a person about it. */
export interface DidResolutionFailure {
  /** The class of the failure, for a caller to branch on. */
  readonly cause: DidResolutionFailureCause;
  /**
   * What failed, and how to fix it where the library knows how, in one sentence or two in the
   * library's own words. It quotes no error of the transport's, which the log records instead. A
   * verifier shows it to the party that presented the credential only for `deadline_exceeded`, and
   * for a failure one of the library's resolvers decided from the DID alone, before any request or
   * DNS lookup ({@link DIDResolver.lastFailure}); anything else is for the operator alone.
   */
  readonly detail: string;
}

/**
 * A DID document as a resolver returns it. Each verification relationship lists methods by
 * reference (an absolute or relative DID URL) or embeds them (W3C Controlled Identifiers v1.0 §2.3).
 */
export interface DIDDocument {
  '@context'?: string | string[];
  id: string;
  alsoKnownAs?: string[];
  verificationMethod?: VerificationMethod[];
  authentication?: (string | VerificationMethod)[];
  assertionMethod?: (string | VerificationMethod)[];
  keyAgreement?: (string | VerificationMethod)[];
  capabilityInvocation?: (string | VerificationMethod)[];
  capabilityDelegation?: (string | VerificationMethod)[];
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk?: unknown;
  publicKeyBase58?: string;
  publicKeyMultibase?: string;
}

/**
 * Resolves a credential's status: `checkStatus` returns `true` when its status bit is set, and
 * throws when the status cannot be proven, which the verifier denies as `status_unresolvable`. The
 * denial's reason goes back to whoever presented the credential: a `RefusalError` the resolver
 * throws gives it its code and its words, written for that party; any other error may be a
 * transport's words about the verifier's network, so its message is logged for the operator and
 * the reason names the list and says only that it could not be read or checked.
 * `context` names the credential's issuer and may name its delegation chain's pinned root and the
 * status-list URL that root's own credential names. A list's proof shows only who signed it, so a
 * resolver that verifies the proof also passes
 * `acceptStatusList(list, statusListExpectationFor(status, context, statusListIssuers))`, which
 * reads a list only from the one keeper of the entry's URL: the issuer its own `statusListIssuers`
 * configuration binds the URL or its origin to, else the pinned root when its credential names the
 * URL, else the credential's issuer.
 * A verdict about a list reaches the presenter only once the list's proof verifies: until then the
 * list is whatever its URL answered, which the presenter chose, and the rule's reason quotes it. So
 * a resolver that asks `acceptStatusList` before the proof verifies, as the library's readers do so
 * that a list from another issuer triggers no DID resolution, keeps its reason out of the
 * presenter's refusal: it throws that reason in an error that is not a `RefusalError`, whose words
 * the verifier gives to the operator's log while the refusal names the list and says only that it
 * could not be read or checked. Only a reason given once the proof has verified may be thrown as a
 * `RefusalError` of code `status_signer_untrusted`.
 * `CheqdStatusListResolver` holds every list to the one DID it is configured to trust.
 * A resolver that reads the one bit at an entry's `statusListIndex` first passes
 * `acceptEntrySize(status.statusSize)`, as the library's readers do, and throws its reason, as a
 * `RefusalError`, for an entry that is not one bit wide: such an entry keeps its status in other
 * bits of the list.
 * A list outside the validity window it states says nothing of now, so a resolver reads one only when
 * `acceptStatusListValidity(list, Date.now())` accepts it, once its proof verifies, and otherwise
 * throws its reason as a `RefusalError` of code `status_unavailable`, as the library's readers do.
 *
 * `DelegationCredentialVerifier`, which the delegation middleware runs for each credential of a
 * chain, names the credential's own issuer alone, never the chain's root, even when
 * `trustedRootIssuers` pins it, and denies a credential that names no issuer DID without asking. So
 * on that path a list the root signed for a re-delegated credential is refused (the verifier fails
 * closed) unless the resolver's own configuration, a `statusListIssuers` map it passes to
 * `statusListExpectationFor`, binds the list's URL or its origin to the root.
 *
 * Whether a list may be read depends on the context, so a caching wrapper must key on it as well as
 * on the entry's URL, index and purpose, as `withStatusCache` does.
 *
 * The verifier also passes `status` as a fresh copy of the credential's entry that carries the
 * context, under the non-enumerable key `Symbol.for('@kya-os/mcp/status-check-context')`, and the
 * library's own checkers and `withStatusCache` read it there when they are given no `context`. So a
 * resolver that wraps a library checker and passes on only the very `status` it was given still
 * holds the list to the credential. The copy has the entry's own enumerable members and no others,
 * so it serializes as the entry does; a copy made of it by spreading or by JSON does not carry it.
 *
 * The answer is read strictly: `true` is revoked, `false` is not, and any other value, which only
 * untyped code can give, denies the credential as `status_unresolvable`. So does a `checkStatus`
 * that has not answered within the verifier's `dependencyTimeoutMs`, 5,000 ms by default.
 */
export interface StatusListResolver {
  checkStatus(status: CredentialStatus, context?: StatusCheckContext): Promise<boolean>;
}

/**
 * Internal result of a credential-status check. `outcome` is set on every
 * deny (see {@link StatusOutcome}); it is surfaced as
 * `DelegationVCVerificationResult.statusOutcome`.
 */
export interface StatusCheckResult extends RefusalCoding {
  valid: boolean;
  reason?: string;
  outcome?: StatusOutcome;
  durationMs?: number;
}

/**
 * Verifies a credential's embedded proof under `publicKeyJwk`. The answer is read strictly: the
 * signature verifies only on an object whose `valid` is the literal `true`, and any other answer,
 * which only untyped code can give, leaves it unverified as `runtime_error`. So does a verifier that
 * has not answered within the verifier's `dependencyTimeoutMs`, 5,000 ms by default, as
 * `deadline_exceeded`. A refusal is `invalid_proof` unless it names another code of the catalog as
 * its `code`, which is typed `string`, so a code read from a variable or from JSON compiles; any
 * other string is read as no code.
 */
export interface SignatureVerificationFunction {
  (
    vc: import("../types/protocol.js").DelegationCredential,
    publicKeyJwk: unknown,
  ): Promise<{
    valid: boolean;
    reason?: string;
    code?: string;
  }>;
}
