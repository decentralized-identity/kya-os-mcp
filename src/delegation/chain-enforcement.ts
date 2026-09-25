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
import { verifyDelegationAudience } from "./audience-validator.js";
import { authorityContains, crispScopes, scopeAuthority } from "./scope-matcher.js";
import { credentialIssuerDid } from "./vc-jwt-verify.js";

/** Union of a credential's delegation scopes and its constraint scopes. */
export function getDelegationScopes(credential: DelegationCredential): string[] {
  const scopes = new Set<string>();
  for (const scope of credential.credentialSubject.delegation.scopes ?? []) {
    scopes.add(scope);
  }
  for (const scope of credential.credentialSubject.delegation.constraints?.scopes ?? []) {
    scopes.add(scope);
  }
  return Array.from(scopes);
}

/**
 * A child re-delegation may only narrow (attenuate) its parent's authority
 * (SPEC.md §6.4). Scope authority comes in two representations (SPEC.md §6.3):
 * flat scopes, matched exactly, and CRISP scope matchers. Both credentials are
 * read as one typed authority ({@link scopeAuthority}), and every flat scope and
 * matcher the child grants must be proven inside the parent's authority
 * ({@link authorityContains}), whichever representation either side uses;
 * anything unprovable, including a malformed entry, fails closed. A credential
 * with no scopes of either kind is not scope-restricted: such a parent accepts
 * any child, and such a child never attenuates a restricted parent. Pure.
 */
export function validateScopeAttenuation(
  parentCredential: DelegationCredential,
  childCredential: DelegationCredential,
): { valid: boolean; reason?: string } {
  const parentId = parentCredential.credentialSubject.delegation.id;
  const childId = childCredential.credentialSubject.delegation.id;
  const parentAuthority = scopeAuthority(parentCredential);
  if (parentAuthority.length === 0) {
    return { valid: true };
  }

  const childScopes = getDelegationScopes(childCredential);
  const childMatchers = crispScopes(childCredential);
  if (childScopes.length === 0 && childMatchers.length === 0) {
    return {
      valid: false,
      reason: `Delegation ${childId} omits scopes required to prove attenuation from parent ${parentId}`,
    };
  }

  const withinParent = authorityContains(parentAuthority);
  const widenedMatchers = childMatchers.filter((scope) => !withinParent(scope));
  if (widenedMatchers.length > 0) {
    return {
      valid: false,
      reason: `Delegation ${childId} introduces crisp scope matcher(s) outside parent ${parentId}: ${widenedMatchers
        .map((s) => `${s?.matcher}:${s?.resource}`)
        .join(", ")}`,
    };
  }
  const widenedScopes = childScopes.filter((scope) => !withinParent({ resource: scope, matcher: "exact" }));
  if (widenedScopes.length > 0) {
    return {
      valid: false,
      reason: `Delegation ${childId} widens scopes beyond parent ${parentId}: ${widenedScopes.join(", ")}`,
    };
  }

  return { valid: true };
}

/** Per-credential verifier port (signature / schema / expiry / own status). */
export interface DelegationCredentialVerifierPort {
  verifyDelegationCredential(
    credential: DelegationCredential,
    options?: { skipSignature?: boolean },
  ): Promise<{ valid: boolean; reason?: string }>;
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
 */
export interface RevocationChecker {
  isRevoked(delegationId: string): Promise<{
    revoked: boolean;
    reason?: string;
    revokedAncestor?: string;
  }>;
}

export interface ChainEnforcementDeps {
  /** The verifying server's DID — every chain credential's audience must include it. */
  serverDid: string;
  /** Per-credential verifier (signature / schema / expiry / own status). */
  verifier: DelegationCredentialVerifierPort;
  /**
   * Resolve ancestor credentials for a re-delegated leaf. May return ancestors
   * only (root→parent) or the full chain (root→leaf). Required when the leaf has
   * a `parentId`.
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
   * When set, a root signed by any other DID is rejected. Omit to accept any
   * root issuer.
   */
  trustedRootIssuers?: readonly string[];
}

export interface ChainValidationResult {
  valid: boolean;
  reason?: string;
  /** Earliest verified credential/constraint expiry across the chain (ms epoch). */
  expiresAt?: number;
  /** Non-fatal inconsistencies worth logging, such as a root whose issuerDid is not its signer. */
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
 * `issuerDid` alone is not signed evidence of who issued it. When
 * `trustedRootIssuers` is set, the root must be signed by one of them.
 * Success includes the earliest applicable expiry for downstream grant storage.
 * Never throws on a malformed input; returns `{ valid, reason }`.
 */
export async function validateDelegationChain(
  leafCredential: DelegationCredential,
  deps: ChainEnforcementDeps,
  options?: { skipSignature?: boolean },
): Promise<ChainValidationResult> {
  // Shape guard (validate* never-throw contract): a structurally malformed leaf
  // returns a { valid, reason } result rather than letting extractDelegationFromVC
  // or the downstream scope check throw. Requires both
  // credentialSubject.delegation AND .constraints (the verifier's own invariant).
  const leafDelegationObj = (
    leafCredential?.credentialSubject as
      | { delegation?: { constraints?: unknown } }
      | undefined
  )?.delegation;
  if (
    !leafDelegationObj ||
    typeof leafDelegationObj !== "object" ||
    !leafDelegationObj.constraints ||
    typeof leafDelegationObj.constraints !== "object"
  ) {
    return {
      valid: false,
      reason:
        "Malformed delegation credential: missing credentialSubject.delegation or its constraints",
    };
  }
  const leafDelegation = extractDelegationFromVC(leafCredential);
  let chain: DelegationCredential[] = [leafCredential];

  if (leafDelegation.parentId) {
    if (!deps.resolveDelegationChain) {
      return {
        valid: false,
        reason: `Delegation ${leafDelegation.id} references parent ${leafDelegation.parentId} but no resolveDelegationChain handler is configured`,
      };
    }

    let resolvedChain: DelegationCredential[];
    try {
      resolvedChain = await deps.resolveDelegationChain(leafCredential);
    } catch (error) {
      return {
        valid: false,
        reason: `Failed to resolve delegation chain: ${error instanceof Error ? error.message : "Unknown error"}`,
      };
    }

    if (resolvedChain.length === 0) {
      return {
        valid: false,
        reason: `Delegation ${leafDelegation.id} references parent ${leafDelegation.parentId} but the resolved chain is empty`,
      };
    }

    const leafIndex = resolvedChain.findIndex(
      (credential) =>
        credential.credentialSubject.delegation.id === leafDelegation.id,
    );
    if (leafIndex !== -1 && leafIndex !== resolvedChain.length - 1) {
      return {
        valid: false,
        reason: `Resolved delegation chain for ${leafDelegation.id} must end with the leaf credential`,
      };
    }

    // Always validate the presented leaf. A resolver may return a copy, but it
    // must not replace the credential whose JWT envelope was authenticated.
    chain = [
      ...(leafIndex === -1 ? resolvedChain : resolvedChain.slice(0, -1)),
      leafCredential,
    ];
  }

  let expiresAt: number | undefined;
  const warnings: string[] = [];
  const seenIds = new Set<string>();
  let previousDelegation: DelegationRecord | undefined;
  let previousCredential: DelegationCredential | undefined;

  for (const credential of chain) {
    const delegation = extractDelegationFromVC(credential);

    if (seenIds.has(delegation.id)) {
      return {
        valid: false,
        reason: `Delegation chain contains a circular reference at ${delegation.id}`,
      };
    }
    seenIds.add(delegation.id);

    if (credential.credentialStatus && !deps.statusListConfigured) {
      return {
        valid: false,
        reason: `Delegation ${delegation.id} has credentialStatus but no statusListResolver is configured`,
      };
    }

    const credentialVerification = await deps.verifier.verifyDelegationCredential(
      credential,
      {
        ...(options?.skipSignature && credential === leafCredential
          ? { skipSignature: true }
          : {}),
      },
    );
    if (!credentialVerification.valid) {
      return {
        valid: false,
        reason: `Delegation ${delegation.id} invalid: ${credentialVerification.reason}`,
      };
    }

    // Use the already-verified walk so grant lifetime cannot outlive a shorter
    // ancestor or constraint. Expiry/status are still rechecked on every call.
    const deadlines = [
      credential.expirationDate ? Date.parse(credential.expirationDate) : undefined,
      delegation.constraints.notAfter !== undefined
        ? delegation.constraints.notAfter * 1000
        : undefined,
    ];
    for (const deadline of deadlines) {
      if (deadline !== undefined && Number.isFinite(deadline)) {
        expiresAt = Math.min(expiresAt ?? deadline, deadline);
      }
    }

    if (!verifyDelegationAudience(delegation, deps.serverDid)) {
      return {
        valid: false,
        reason: `Delegation ${delegation.id} audience does not include server DID ${deps.serverDid}`,
      };
    }

    // Every non-root credential in the chain MUST carry an `audience` constraint
    // binding it to the verifying server. This closes the confused-deputy class
    // where a re-delegated credential is forwarded to an unintended server
    // (KYA-OS §11.6). Unconditional as of 1.4.0.
    if (delegation.parentId && !delegation.constraints.audience) {
      return {
        valid: false,
        reason: `Delegation ${delegation.id} is a re-delegation (parentId: ${delegation.parentId}) but has no audience constraint. Re-delegations MUST include an audience constraint (KYA-OS §11.6)`,
      };
    }

    // The DID whose key the verifier checked this credential against. Unlike
    // `delegation.issuerDid`, which is only a claim inside the signed body,
    // this is who actually issued it.
    const signerDid = credentialIssuerDid(credential);

    if (!previousDelegation || !previousCredential) {
      if (delegation.parentId) {
        return {
          valid: false,
          reason: `Resolved delegation chain is incomplete: root delegation ${delegation.id} still references parent ${delegation.parentId}`,
        };
      }

      if (
        deps.trustedRootIssuers &&
        (signerDid === undefined || !deps.trustedRootIssuers.includes(signerDid))
      ) {
        return {
          valid: false,
          reason: `Root delegation ${delegation.id} is issued by ${signerDid ?? "an unidentified issuer"}, which is not a trusted root issuer`,
        };
      }

      if (signerDid !== delegation.issuerDid) {
        warnings.push(
          `Root delegation ${delegation.id} names issuerDid ${delegation.issuerDid} but is signed by ${signerDid ?? "an unidentified issuer"}`,
        );
      }

      previousDelegation = delegation;
      previousCredential = credential;
      continue;
    }

    if (delegation.parentId !== previousDelegation.id) {
      return {
        valid: false,
        reason: `Delegation ${delegation.id} references parent ${delegation.parentId} but expected ${previousDelegation.id}`,
      };
    }

    if (delegation.issuerDid !== previousDelegation.subjectDid) {
      return {
        valid: false,
        reason: `Delegation ${delegation.id} issued by ${delegation.issuerDid} but parent subject is ${previousDelegation.subjectDid}`,
      };
    }

    // Only the parent's delegate may re-delegate. Without this, anyone could
    // sign a child that merely claims the parent's subject as its issuer.
    if (signerDid !== previousDelegation.subjectDid) {
      return {
        valid: false,
        reason: `Delegation ${delegation.id} is signed by ${signerDid ?? "an unidentified issuer"} but parent subject is ${previousDelegation.subjectDid}`,
      };
    }

    const scopeValidation = validateScopeAttenuation(previousCredential, credential);
    if (!scopeValidation.valid) {
      return scopeValidation;
    }

    previousDelegation = delegation;
    previousCredential = credential;
  }

  const finalDelegation = extractDelegationFromVC(chain[chain.length - 1]!);
  if (finalDelegation.id !== leafDelegation.id) {
    return {
      valid: false,
      reason: `Resolved delegation chain ended at ${finalDelegation.id} instead of leaf ${leafDelegation.id}`,
    };
  }

  // E3.1: graph-backed ancestor revocation. Independent of how the chain above
  // was resolved — catches a cascade-revoked ANCESTOR even when the leaf's own
  // credentialStatus bit was never flipped. Opt-in: only runs when a checker is
  // wired, so existing callers are unaffected.
  if (deps.revocationChecker) {
    const revocation = await deps.revocationChecker.isRevoked(leafDelegation.id);
    if (revocation.revoked) {
      return {
        valid: false,
        reason: revocation.revokedAncestor
          ? `Delegation ${leafDelegation.id} is revoked via ancestor ${revocation.revokedAncestor}`
          : `Delegation ${leafDelegation.id} is revoked${revocation.reason ? `: ${revocation.reason}` : ""}`,
      };
    }
  }

  return {
    valid: true,
    ...(expiresAt !== undefined ? { expiresAt } : {}),
    ...(warnings.length > 0 ? { warnings } : {}),
  };
}
