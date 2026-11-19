/**
 * The ancestors a delegation chain resolver's answer gives.
 *
 * `validateDelegationChain` (`./chain-enforcement.ts`) asks the host's
 * `resolveDelegationChain` for the ancestors of a re-delegated leaf, and walks
 * what comes back. What comes back is read here, each value once, and refused
 * before any credential of it is verified when it holds more values than the
 * walk may evaluate, a value that cannot be copied, the leaf anywhere but
 * last, or a value that is not a delegation credential. How a host has the
 * values read ({@link AncestorReading}) and what the walk reports of the
 * credentials it read ({@link EvaluatedCredentials}) are declared here.
 *
 * Pure: no transport, no framework, no key material.
 */
import type { DelegationCredential } from "../types/protocol.js";
import { refusal, type Refusal } from "../utils/refusal.js";
import type { ChainEnforcementDeps } from "./chain-enforcement.js";
import { delegationIdMember } from "./delegation-id.js";

/** How the walk reads the values a resolver returns: a member of `ChainEnforcementDeps`. */
export interface AncestorReading {
  /**
   * Take the copy of a value the resolver returned that every check reads,
   * in place of the value. It is called once for each value, root first, as
   * soon as the resolver returns and before anything else reads the value,
   * the resolver's own copy of the leaf included. Every check, and
   * `evaluated` in the result, uses the copy, so that a value which answers
   * differently each time it is read cannot verify as one credential and be
   * recorded as another. A host passes `structuredClone`, or a function that
   * also throws for a value it will not read at all: the middleware's
   * refuses one that is not plain data, and one nested deeper than a
   * credential may be (SPEC §7.8), before it copies. A value that cannot be
   * copied (the call throws) refuses the chain before any credential of it
   * is verified, and the values after it are not passed here. Nor are any
   * when the resolver returned more values than `maxChainLength`: the chain
   * is refused as one of at least that many credentials, since the last may
   * be the resolver's own copy of the leaf. The presented leaf is the
   * caller's to copy, and is never passed here. Omit to walk the resolver's
   * values as they are.
   */
  snapshotAncestor?: (ancestor: DelegationCredential) => DelegationCredential;
}

/** What the walk reports of the credentials it read: a member of `ChainValidationResult`. */
export interface EvaluatedCredentials {
  /**
   * The credentials the walk reached, root first, each as the walk read it
   * (see `snapshotAncestor`). On a chain that validated that is the whole
   * chain, the presented credential last. On a refusal it is the ancestors
   * the walk reached, up to the one it stopped at, then the presented
   * credential, which the walk examines before any ancestor, so a caller can
   * record what was examined and nothing that was not: a presented
   * credential refused on its own is the only one. Absent when the walk never started: the leaf
   * was malformed, its chain could not be assembled (a value the resolver
   * returned could not be copied, or what it returned is not a chain of
   * delegation credentials), it was longer than `maxChainLength`, or its
   * links or its root's issuer were refused, which are checked before any
   * credential is verified.
   */
  evaluated?: readonly DelegationCredential[];
}

/**
 * The ancestors of the leaf whose delegation is `leafId`, root first, from
 * the values the resolver returned: ancestors only, or the whole chain with
 * the resolver's own copy of the leaf last. Each is the copy every check
 * reads (see `snapshotAncestor`). A refusal instead when the answer is refused:
 * `chain_invalid` for more values than `maxChainLength` or a leaf that is not
 * last, and `delegation_malformed` for a value that could not be copied or is not
 * a delegation credential.
 */
export function resolvedAncestors(
  resolvedChain: readonly DelegationCredential[],
  leafId: string,
  deps: Pick<ChainEnforcementDeps, "maxChainLength" | "snapshotAncestor">,
): { ancestors: DelegationCredential[] } | Refusal {
  // More values than the limit make a chain longer than it, whether or not
  // the last is the resolver's copy of the leaf, so they are refused before
  // any of them is read.
  const limit = deps.maxChainLength;
  if (limit !== undefined && Number.isInteger(limit) && limit >= 1 && resolvedChain.length > limit) {
    return refusal(
      "chain_invalid",
      `Delegation chain of at least ${resolvedChain.length} credentials exceeds the maximum of ${limit}`,
    );
  }

  // Each value is read once, root first, before anything looks at it: what
  // every check reads is its copy.
  const read: DelegationCredential[] = [];
  for (const resolved of resolvedChain) {
    const reading = readingOf(resolved, deps.snapshotAncestor);
    if (reading === undefined) {
      return refusal("delegation_malformed", `Resolved delegation chain for ${leafId} holds a value that could not be copied`);
    }
    read.push(reading.copy);
  }

  const leafIndex = read.findIndex((credential) => delegationIdMember(credential) === leafId);
  if (leafIndex !== -1 && leafIndex !== read.length - 1) {
    return refusal("chain_invalid", `Resolved delegation chain for ${leafId} must end with the leaf credential`);
  }

  // The presented leaf is the one validated: the resolver's copy of it is set
  // aside unchecked, whatever else it holds.
  const ancestors = leafIndex === -1 ? read : read.slice(0, -1);

  // The same guard as the leaf's on every ancestor: a value that is not a
  // delegation credential is refused before any credential of the chain is
  // verified.
  if (!ancestors.every(hasDelegationShape)) {
    return refusal(
      "delegation_malformed",
      `Resolved delegation chain for ${leafId} holds a value that is not a delegation credential`,
    );
  }
  return { ancestors };
}

/**
 * Whether a value has what the walk reads of every credential:
 * `credentialSubject.delegation` and its `constraints` (the verifier's own
 * invariant). Each is held to be an object of any kind, an array included,
 * which is looser than `isRecord`: the walk reads members of them and never
 * needs them to be records, and a credential whose `constraints` is an array
 * constrains nothing and goes on to the checks after this one.
 */
export function hasDelegationShape(credential: unknown): boolean {
  const delegation = (
    credential as { credentialSubject?: { delegation?: { constraints?: unknown } } } | null | undefined
  )?.credentialSubject?.delegation;
  return (
    !!delegation &&
    typeof delegation === "object" &&
    !!delegation.constraints &&
    typeof delegation.constraints === "object"
  );
}

/**
 * A value the resolver returned, as every check reads it: the host's copy of
 * it when the host takes one. Undefined when it could not be copied.
 */
function readingOf(
  resolved: DelegationCredential,
  snapshot: ChainEnforcementDeps["snapshotAncestor"],
): { copy: DelegationCredential } | undefined {
  if (snapshot === undefined) return { copy: resolved };
  try {
    return { copy: snapshot(resolved) };
  } catch {
    return undefined;
  }
}
