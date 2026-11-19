/**
 * Delegation chain enforcement — framework-agnostic core (E3 · #2888).
 *
 * The leaf→root chain walk, scope-attenuation, audience binding, confused-deputy
 * guard (KYA-OS §11.6), and ancestor-revocation rules, lifted out of the
 * `with-kya-os` middleware closure so the SAME logic runs in every host (MCP
 * middleware, an HTTP PEP, the conformance harness) against one implementation
 * rather than a per-transport fork.
 *
 * Dependencies are injected as ports (interface-first): a per-credential
 * verifier, an optional ancestor resolver, and an optional graph-backed
 * `RevocationChecker`. Nothing here imports a transport or framework.
 */
import {
  extractDelegationFromVC,
  type DelegationCredential,
  type DelegationRecord,
} from "../types/protocol.js";
import type { RefusalCode } from "../refusal-codes.js";
import { answerWithinDeadline, dependencyTimeoutRefusal } from "../utils/deadline.js";
import { describeValue } from "../utils/describe-value.js";
import { OUTBOUND_READ_TIMEOUT_MS } from "../utils/outbound-read-limits.js";
import { coded, refusal, refusalCodeOf, type Passed, type Refusal } from "../utils/refusal.js";
import { OPERATOR_REASON_LENGTH } from "../utils/revocation-answer.js";
import { readVerdict } from "../utils/verdict.js";
import { verifyDelegationAudience } from "./audience-validator.js";
import { attenuationWarnings, checkScopeAttenuation, statedExpiry } from "./chain-attenuation.js";
import {
  chainResolutionFailure,
  credentialVerificationFailure,
  presentedReason,
  revocationCheckFailure,
  revocationRefusal,
  unreadableChainAnswer,
} from "./chain-reasons.js";
import { chainLinkageRefusal } from "./chain-linkage.js";
import { checkConstraintAttenuation } from "./constraint-attenuation.js";
import { rootAdmissionRefusal } from "./root-admission.js";
import { hasDelegationShape, resolvedAncestors } from "./resolved-chain.js";
import type { AncestorReading, EvaluatedCredentials } from "./resolved-chain.js";
import type { RefusalCoding } from "./vc-verifier.types.js";

export { attenuationWarnings, getDelegationScopes, validateScopeAttenuation } from "./chain-attenuation.js";

/**
 * Per-credential verifier port (signature / schema / expiry / own status). A credential passes
 * only on an answer whose `valid` is the literal `true`; any other answer refuses the chain. A
 * refusal takes the `code` the answer names when it is one of the catalog's, as the library's
 * `DelegationCredentialVerifier` names one, else `delegation_invalid`; an answer that is not a
 * verdict is `runtime_error`. Each call gets `dependencyTimeoutMs` to answer: one that has not
 * answered by then refuses the chain as `deadline_exceeded`, and one that throws refuses it as
 * `runtime_error`, or with the code of a `RefusalError` it throws.
 */
export interface DelegationCredentialVerifierPort {
  verifyDelegationCredential(
    credential: DelegationCredential,
    options?: { skipSignature?: boolean },
  ): Promise<{ valid: boolean; reason?: string; code?: RefusalCode }>;
}

/**
 * Graph-backed ancestor-revocation port. The reference adapter is
 * `CascadingRevocationManager` (./cascading-revocation), whose `isRevoked()`
 * walks root→target over the delegation graph + StatusList, detecting a
 * cascade-revoked ANCESTOR independently of how the chain was resolved.
 *
 * Wiring this is the E3.1 correctness fix: the prior closure checked only each
 * credential's OWN `credentialStatus` bit via the resolver, so an ancestor
 * cascade-revocation that hadn't flipped the leaf's own bit could be missed.
 *
 * The answer is read strictly: a chain passes only on `revoked: false`, is revoked only on
 * `revoked: true`, and is refused as unreadable on anything else. Each call gets
 * `dependencyTimeoutMs` to answer, and one that has not answered by then fails the check.
 */
export interface RevocationChecker {
  isRevoked(delegationId: string): Promise<{
    revoked: boolean;
    reason?: string;
    revokedAncestor?: string;
    /**
     * The code the chain is refused with when `revoked` is `true`: a code of `REFUSAL_CODES`, else
     * `delegation_revoked`, as it is when the answer states none. Not read when `revoked` is `false`.
     * Typed `string`, so a code read from a variable or from JSON compiles; only the catalog's is read.
     */
    code?: string;
    /**
     * Whether `code` is transient. Optional, so an answer built as any refusal is fits: the verifier
     * takes it from `code`, as every refusal's is, and does not read this.
     */
    transient?: boolean;
  }>;
}

export interface ChainEnforcementDeps extends AncestorReading {
  /** The verifying server's DID — every chain credential's audience must include it. */
  serverDid: string;
  /** Per-credential verifier (signature / schema / expiry / own status). */
  verifier: DelegationCredentialVerifierPort;
  /**
   * Resolve ancestor credentials for a re-delegated leaf. May return ancestors
   * only (root→parent) or the full chain (root→leaf). Required when the leaf has
   * a `parentId`. It gets `dependencyTimeoutMs` to answer: a chain it has not
   * returned by then is refused as one that could not be resolved, and an
   * answer that is not an array is refused as `runtime_error`.
   */
  resolveDelegationChain?: (
    leafCredential: DelegationCredential,
  ) => Promise<DelegationCredential[]>;
  /**
   * Whether a StatusList resolver is configured downstream. A credential bearing
   * `credentialStatus` is rejected when false (fail-closed).
   */
  statusListConfigured: boolean;
  /** Optional graph-backed ancestor-revocation check (see {@link RevocationChecker}). */
  revocationChecker?: RevocationChecker;
  /**
   * DIDs allowed to sign the chain's root credential (its Responsible Party).
   * When set, a root naming any other issuer is rejected before any credential
   * is verified. A list that is not an array of DIDs, each a string that starts
   * with `did:` and has no white space around it, rejects every chain with a
   * reason that says so; this function does not throw for it. Omit to accept
   * any root issuer.
   */
  trustedRootIssuers?: readonly string[];
  /**
   * Local cost limit: the most credentials this verifier will verify in one
   * chain, root to leaf inclusive. Each credential costs a signature check and
   * possibly a DID resolution, and a resolver may return a chain of any length.
   * This bounds the verifier's own work; it is not a protocol rule about how far
   * authority may be delegated, which the base profile leaves unbounded. Omit to
   * verify any length. A value that is not a positive integer rejects every
   * chain.
   *
   * It is checked after `resolveDelegationChain` returns, so it does not bound
   * the resolver itself: a resolver that walks `parentId` one fetch at a time
   * should apply its own limit. More values from the resolver than the limit
   * refuse the chain before any of them is read, as one of at least that many
   * credentials (see `snapshotAncestor`). The Entity Card profile's
   * `validateDelegationChain` (`@kya-os/mcp/card`) takes the same option and
   * counts the same way.
   */
  maxChainLength?: number;
  /**
   * How long, in milliseconds, `resolveDelegationChain`, each `verifier` call and each `revocationChecker` call may take to answer: a number greater than 0 and at most
   * 2,147,483,647. Default 5,000. Any other value rejects every chain.
   */
  dependencyTimeoutMs?: number;
}

/** The verdict on a delegation chain, with its code and whether it is transient when it is refused. */
export interface ChainValidationResult extends EvaluatedCredentials, RefusalCoding {
  valid: boolean;
  reason?: string;
  /** Earliest verified credential/constraint expiry across the chain (ms epoch). */
  expiresAt?: number;
  /**
   * Non-fatal findings worth logging on a chain that validated: each way a
   * re-delegation is wider than its parent ({@link attenuationWarnings}).
   */
  warnings?: string[];
}

/**
 * Validate a delegation credential and (if re-delegated) its full chain:
 * structural shape, per-credential verification, audience binding to the server,
 * the §11.6 re-delegation audience-constraint requirement, parent↔child linkage
 * (parentId + issuerDid==parent.subjectDid), cycle detection, scope attenuation,
 * and — when a {@link RevocationChecker} is supplied — graph-backed ancestor
 * revocation. `skipSignature` applies only to the presented leaf whose JWT
 * envelope the caller has verified; ancestors always require verification.
 * Each child must also be signed by its parent's subject: the claimed
 * `issuerDid` alone is not signed evidence of who issued it. The root must be
 * signed by the `issuerDid` it names, so that DID is the chain's Responsible
 * Party, and by one of `trustedRootIssuers` when that is set.
 * With `trustedRootIssuers` unset it admits a root from any issuer, one an
 * agent signs for itself included, and neither throws nor warns: unlike the
 * `withKyaOs` gate, which refuses to run with no root pinned, it leaves
 * pinning the root to its caller.
 * A re-delegation must also narrow its parent's CRISP budget and replicate
 * every constraint the walk does not interpret (`./constraint-attenuation.ts`).
 * The presented credential is verified before any ancestor, and a refusal of the
 * chain the resolver returned tells the presenter only what the presented
 * credential states, the ancestors it withholds going to the operator's log.
 * Success includes the earliest applicable expiry for downstream grant storage.
 * Never throws on a malformed input, nor when a dependency throws or answers
 * what it may not; returns `{ valid, reason }`, and on a refusal the `code`
 * and `transient` of the rule or dependency that refused.
 */
export async function validateDelegationChain(
  leafCredential: DelegationCredential,
  deps: ChainEnforcementDeps,
  options?: { skipSignature?: boolean },
): Promise<ChainValidationResult> {
  return enforceChain(leafCredential, deps, options);
}

/** What the walk of a chain comes to: a chain that validated, with what it found, or a coded refusal. */
type ChainVerdict = (Passed & { readonly expiresAt?: number; readonly warnings?: string[] }) | Refusal;

/** {@link validateDelegationChain}, with a refusal that cannot be built without its code. */
async function enforceChain(
  leafCredential: DelegationCredential,
  deps: ChainEnforcementDeps,
  options?: { skipSignature?: boolean },
): Promise<ChainVerdict & EvaluatedCredentials> {
  // Shape guard (validate* never-throw contract): a structurally malformed leaf
  // returns a { valid, reason } result rather than letting extractDelegationFromVC
  // or the downstream scope check throw.
  if (!hasDelegationShape(leafCredential)) {
    return refusal(
      "delegation_malformed",
      "Malformed delegation credential: missing credentialSubject.delegation or its constraints",
    );
  }
  const { dependencyTimeoutMs: timeoutMs = OUTBOUND_READ_TIMEOUT_MS } = deps;
  const timeoutRefusal = dependencyTimeoutRefusal(timeoutMs);
  if (timeoutRefusal !== undefined) return refusal("configuration_error", timeoutRefusal);
  const leafDelegation = extractDelegationFromVC(leafCredential);
  let chain: DelegationCredential[] = [leafCredential];

  if (leafDelegation.parentId) {
    if (!deps.resolveDelegationChain) {
      return refusal(
        "configuration_error",
        `Delegation ${leafDelegation.id} references parent ${leafDelegation.parentId} but no resolveDelegationChain handler is configured`,
      );
    }

    let resolvedChain: unknown;
    try {
      const resolve = deps.resolveDelegationChain;
      resolvedChain = await answerWithinDeadline("the chain resolver", () => resolve(leafCredential), timeoutMs);
    } catch (error) {
      return refusal(refusalCodeOf(error, "runtime_error"), chainResolutionFailure(error));
    }
    if (!Array.isArray(resolvedChain)) return refusal("runtime_error", unreadableChainAnswer(resolvedChain));

    if (resolvedChain.length === 0) {
      return refusal(
        "chain_invalid",
        `Delegation ${leafDelegation.id} references parent ${leafDelegation.parentId} but the resolved chain is empty`,
      );
    }

    const resolved = resolvedAncestors(resolvedChain, leafDelegation.id, deps);
    if ("valid" in resolved) {
      return resolved;
    }

    // Always validate the presented leaf. A resolver may return a copy, but it
    // must not replace the credential whose JWT envelope was authenticated.
    chain = [...resolved.ancestors, leafCredential];
  }

  // Checked before any credential is verified, so an over-long chain costs no
  // signature checks or DID resolutions.
  const { maxChainLength } = deps;
  if (maxChainLength !== undefined) {
    if (!Number.isInteger(maxChainLength) || maxChainLength < 1) {
      return refusal("configuration_error", `maxChainLength must be a positive integer (got ${String(maxChainLength)})`);
    }
    if (chain.length > maxChainLength) {
      return refusal("chain_invalid", `Delegation chain of ${chain.length} credentials exceeds the maximum of ${maxChainLength}`);
    }
  }

  // Structure, then trust, then proofs. The linkage of every credential, and then the root by the
  // issuer it names, are checked before any credential is verified, so a broken chain or an
  // untrusted root costs no DID, signature or status resolution; verifying each credential below
  // authenticates the issuer it names. Only the root is admitted: a delegated leaf need not be a
  // trusted root issuer. The application's `resolveDelegationChain` above runs first and bounds its
  // own I/O. What the resolver answered is the operator's to read: a refusal of it tells the
  // presenter only what the presented credential states (`chainLinkageRefusal`).
  const linkage = chainLinkageRefusal(chain);
  if (linkage !== undefined) {
    return refusal("chain_invalid", linkage.logged === undefined ? linkage.reason : presentedReason(linkage.reason, linkage.logged));
  }
  const rootRefusal = admissionRefusal(chain, deps.trustedRootIssuers);
  if (rootRefusal !== undefined) return rootRefusal;

  // Every result of the walk carries the credentials it reached, root first.
  const reached: Reached = { ancestors: 0 };
  const verdict = await walkChain(chain, reached, leafDelegation, deps, timeoutMs, options);
  // The walk examines the presented credential first, so every verdict covers it.
  const evaluated = [...chain.slice(0, reached.ancestors), leafCredential];
  return { ...verdict, evaluated };
}

/**
 * Why the root of `chain` is not admitted under `trustedRootIssuers` ({@link rootAdmissionRefusal}),
 * or `undefined`. A root the chain resolver returned, which its presenter did not write, is named
 * only in the operator's log: the presenter is told, under the same code, that the presented
 * credential descends from a root that is not admitted.
 */
function admissionRefusal(chain: readonly DelegationCredential[], trustedRootIssuers: readonly string[] | undefined): Refusal | undefined {
  const refused = rootAdmissionRefusal(chain[0]!, trustedRootIssuers);
  if (refused === undefined || chain.length === 1 || refused.code === "configuration_error") return refused;
  const leafId = extractDelegationFromVC(chain[chain.length - 1]!).id;
  const said = refused.code === "untrusted_root"
    ? `Delegation ${describeValue(leafId)} descends from a root whose issuer is not a trusted root issuer`
    : `Delegation ${describeValue(leafId)} descends from a root whose credential names no issuer`;
  return refusal(refused.code, presentedReason(said, refused.reason));
}

/** How far the walk of a chain reached: how many of its ancestors, root first, past the presented credential. */
interface Reached {
  ancestors: number;
}

/**
 * The per-credential and per-link checks of a chain, recording in `reached` each credential they
 * reach. The presented credential, the chain's last, is verified first, so a presenter who cannot
 * sign as its parent's subject costs no ancestor's verification and learns nothing of an
 * ancestor's standing; then each ancestor, root first, with the link from the one before it; then
 * the presented credential's link from its parent. Each credential verification and each
 * revocation check gets `timeoutMs` to answer.
 */
async function walkChain(
  chain: readonly DelegationCredential[],
  reached: Reached,
  leafDelegation: DelegationRecord,
  deps: ChainEnforcementDeps,
  timeoutMs: number,
  options?: { skipSignature?: boolean },
): Promise<ChainVerdict> {
  const leafCredential = chain[chain.length - 1]!;
  const expiry: { at?: number } = {};
  const warnings: string[] = [];

  const presentedRefusal = await credentialRefusal(leafCredential, expiry, deps, timeoutMs, options?.skipSignature === true);
  if (presentedRefusal !== undefined) return presentedRefusal;

  let previousCredential: DelegationCredential | undefined;
  for (const credential of chain.slice(0, -1)) {
    reached.ancestors += 1;
    const ancestorRefusal = await credentialRefusal(credential, expiry, deps, timeoutMs, false);
    if (ancestorRefusal !== undefined) return ancestorRefusal;
    if (previousCredential !== undefined) {
      const linkRefusal = attenuationRefusal(previousCredential, credential, warnings);
      if (linkRefusal !== undefined) return linkRefusal;
    }
    previousCredential = credential;
  }
  if (previousCredential !== undefined) {
    const linkRefusal = attenuationRefusal(previousCredential, leafCredential, warnings);
    if (linkRefusal !== undefined) return linkRefusal;
  }
  const expiresAt = expiry.at;

  // Read again after the walk: a leaf that is not stable data may answer another id by now.
  const finalDelegation = extractDelegationFromVC(leafCredential);
  if (finalDelegation.id !== leafDelegation.id) {
    return refusal(
      "chain_invalid",
      `Resolved delegation chain ended at ${finalDelegation.id} instead of leaf ${leafDelegation.id}`,
    );
  }

  // E3.1: graph-backed ancestor revocation. Independent of how the chain above
  // was resolved — catches a cascade-revoked ANCESTOR even when the leaf's own
  // credentialStatus bit was never flipped. Every credential in the verified
  // chain is asked about, root first: a leaf minted after its ancestor was
  // revoked was never registered, so the graph cannot reach the ancestor
  // from the leaf's id alone. Opt-in: only runs when a checker is wired, so
  // existing callers are unaffected.
  if (deps.revocationChecker) {
    for (const credential of chain) {
      const delegationId = credential.credentialSubject.delegation.id;
      let answer: unknown;
      try {
        const checker = deps.revocationChecker;
        answer = await answerWithinDeadline("the revocation checker", () => checker.isRevoked(delegationId), timeoutMs);
      } catch (error) {
        return refusal(refusalCodeOf(error, "status_unavailable"), revocationCheckFailure(delegationId, error));
      }
      // Only an answer whose `revoked` is the literal `false` lets the chain go on.
      const revoked = revocationRefusal(leafDelegation.id, delegationId, answer);
      if (revoked !== undefined) return revoked;
    }
  }

  return {
    valid: true,
    ...(expiresAt !== undefined ? { expiresAt } : {}),
    ...(warnings.length > 0 ? { warnings } : {}),
  };
}

/**
 * Why `credential` is refused on its own: a status entry with no status list resolver configured,
 * the verifier's answer (with `skipSignature` when the caller authenticated its envelope), an
 * audience that does not admit the server, or a re-delegation that states no audience. A
 * credential that passes lowers `expiry.at` to the earliest expiry it states.
 */
async function credentialRefusal(
  credential: DelegationCredential,
  expiry: { at?: number },
  deps: ChainEnforcementDeps,
  timeoutMs: number,
  skipSignature: boolean,
): Promise<Refusal | undefined> {
  const delegation = extractDelegationFromVC(credential);

  if (credential.credentialStatus && !deps.statusListConfigured) {
    return refusal(
      "configuration_error",
      `Delegation ${delegation.id} has credentialStatus but no statusListResolver is configured`,
    );
  }

  // The verifier is a port the host may supply, under the same deadline as every other: a
  // credential passes only on the literal `true`. Its reason is kept as far as the operator reads
  // one, so a status reason it ends with stays whole.
  let verdict: unknown;
  try {
    const { verifier } = deps;
    const skip = skipSignature ? { skipSignature: true } : {};
    verdict = await answerWithinDeadline("the credential verifier", () => verifier.verifyDelegationCredential(credential, skip), timeoutMs);
  } catch (error) {
    return refusal(refusalCodeOf(error, "runtime_error"), credentialVerificationFailure(delegation.id, error));
  }
  const credentialVerification = readVerdict("the credential verifier", verdict, "delegation_invalid", OPERATOR_REASON_LENGTH);
  if (!credentialVerification.valid) {
    return {
      valid: false,
      reason: `Delegation ${delegation.id} invalid: ${credentialVerification.reason}`,
      ...coded(credentialVerification.code),
    };
  }

  // Use the already-verified walk so grant lifetime cannot outlive a shorter
  // ancestor or constraint. Expiry/status are still rechecked on every call.
  const deadline = statedExpiry(credential);
  if (deadline !== undefined) {
    expiry.at = Math.min(expiry.at ?? deadline, deadline);
  }

  if (!verifyDelegationAudience(delegation, deps.serverDid)) {
    return refusal("chain_invalid", `Delegation ${delegation.id} audience does not include server DID ${deps.serverDid}`);
  }

  // Every non-root credential in the chain MUST carry an `audience` constraint
  // binding it to the verifying server. This closes the confused-deputy class
  // where a re-delegated credential is forwarded to an unintended server
  // (KYA-OS §11.6). Unconditional as of 1.4.0.
  if (delegation.parentId && !delegation.constraints.audience) {
    return refusal(
      "chain_invalid",
      `Delegation ${delegation.id} is a re-delegation (parentId: ${delegation.parentId}) but has no audience constraint. Re-delegations MUST include an audience constraint (KYA-OS §11.6)`,
    );
  }
  return undefined;
}

/**
 * Why `child` is wider than `parent`, its parent in a chain whose linkage was checked before any
 * verification (`chainLinkageRefusal`), so each credential's issuerDid is the issuer whose key the
 * verifier checked: by its scopes or by its other constraints. A child that is not refused adds to
 * `warnings` each way it may still be wider ({@link attenuationWarnings}).
 */
function attenuationRefusal(
  parent: DelegationCredential,
  child: DelegationCredential,
  warnings: string[],
): Refusal | undefined {
  const scopeValidation = checkScopeAttenuation(parent, child);
  if (!scopeValidation.valid) return scopeValidation;
  const constraintValidation = checkConstraintAttenuation(parent, child);
  if (!constraintValidation.valid) return constraintValidation;
  warnings.push(...attenuationWarnings(parent, child));
  return undefined;
}
