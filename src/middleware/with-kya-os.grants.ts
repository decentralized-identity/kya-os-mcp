/**
 * KYA-OS Middleware — durable-grant resolution (the no-paste retry).
 *
 * Resolves and mints agent-anchored / session-bound authorization grants so a
 * verified delegation need not be re-pasted on the next call — even on a fresh
 * instance with empty memory. Extracted from `./with-kya-os.ts`; depends only on
 * the immutable {@link MiddlewareDeps} (no shared session state).
 */

import type { Grant } from "../providers/grant-store.js";
import type {
  DelegationCredential,
  DetachedProof,
} from "../types/protocol.js";
import { scopeSatisfies } from "../delegation/scope-matcher.js";
import type {
  DelegationRecords,
  DelegationVerification,
} from "./with-kya-os.delegation-verify.js";
import { getDelegationScopes } from "../delegation/chain-enforcement.js";
import { isHolderBindingApplicable, toHolderBindingRequest } from "../delegation/holder-binding.js";
import {
  admitsRetainedDelegation,
  verifyDelegatedCallProof,
  type ProofDelegationClaims,
} from "../delegation/delegated-call-proof.js";
import { delegationCredentialDigest, type ReceivedCredential } from "../delegation/chain-digest.js";
import { warnOfNoneAmongGrants, warnOfUnnamedProof } from "../delegation/unnamed-proof-warning.js";
import { logger } from "../logging/index.js";
import type { MiddlewareDeps } from "./with-kya-os.deps.js";

/**
 * A durable grant whose retained delegation re-verified for this call, with
 * how the audit trail refers to that delegation.
 */
export interface ResolvedGrant extends DelegationRecords {
  grant: Grant;
  /** The scopes the re-verified credential grants (not the store's copy). */
  delegatedScopes: string[];
  /** The root issuer the grant's delegation verified to just now: the call's Responsible Party. */
  rootIssuer: string;
}

export interface GrantResolution {
  /**
   * Resolve an existing durable grant for a no-delegation (retry) call, so a
   * fresh instance with empty memory authorizes the retry from the shared store.
   * Fail-closed, holder-of-key first (agent-anchored, portable), then session
   * reuse only where the configured binding policy permits it. Every path
   * revalidates the retained delegation. Returns undefined to fall through to the
   * needs_authorization challenge.
   */
  resolveExistingGrant(
    toolName: string,
    args: Record<string, unknown>,
    sessionId: string | undefined,
    scopeId: string,
  ): Promise<ResolvedGrant | undefined>;
  /**
   * Mint a durable grant from a freshly-verified delegation so the NEXT call —
   * on any instance — resolves via {@link resolveExistingGrant} without
   * re-pasting the VC. Best-effort: a store failure must not break the
   * already-authorized response.
   */
  bindGrantOnSuccess(
    vc: DelegationCredential,
    delegationArg: unknown,
    isVCJWT: boolean,
    sessionId: string | undefined,
    scopeId: string,
    responsibleParty: string,
    expiresAt?: number,
  ): Promise<void>;
}

/**
 * Whether a stored grant still stands for the delegation it holds, re-verified just now to
 * `rootIssuer`. A grant names the Responsible Party it was minted for, and stands only while its
 * chain verifies to that root. A grant stored before grants named one recorded its leaf's
 * `controller` as `userDid`, and is held to that record as it was then.
 */
function namesItsResponsibleParty(grant: Grant, rootIssuer: string, controller: string | undefined): boolean {
  return grant.responsibleParty !== undefined ? grant.responsibleParty === rootIssuer : controller === grant.userDid;
}

export function createGrantResolution(
  deps: MiddlewareDeps,
  // A grant hands on its credential's values as the gate does, so it refuses those the gate cannot encode.
  verifyEncodableDelegation: DelegationVerification["verifyEncodableDelegation"],
): GrantResolution {
  const {
    identity,
    cryptoProvider,
    grantStore,
    holderBindingMode,
    holderBindingVerifier,
    requestBindingMode,
  } = deps;
  const hash = (bytes: Uint8Array): Promise<string> => cryptoProvider.hash(bytes);

  /**
   * Deterministic grant id from (agentDid, sessionId, sorted scopes). Stable for
   * the same tuple so a repeated VC-paste UPSERTS one grant rather than piling
   * duplicate rows in a durable store.
   */
  async function grantId(
    agentDid: string,
    sessionId: string | undefined,
    scopes: string[],
  ): Promise<string> {
    const key = `${agentDid}|${sessionId ?? ""}|${[...scopes].sort().join(",")}`;
    const digest = await cryptoProvider.hash(new TextEncoder().encode(key));
    return `grant_${digest.replace(/^sha256:/, "")}`;
  }

  /**
   * A grant caches evidence, never a permanent authorization decision. Returns
   * the grant with the scopes of its re-verified credential, or undefined when
   * the grant does not authorize `scopeId` now, or its delegation is not one
   * `claims`, the call's holder proof's, admit (SPEC §7.8).
   */
  async function authorizeGrant(
    grant: Grant,
    scopeId: string,
    claims?: ProofDelegationClaims,
  ): Promise<ResolvedGrant | undefined> {
    if (grant.status !== "active" || !grant.scopes.includes(scopeId)) return undefined;
    if (
      grant.expiresAt !== undefined &&
      (!Number.isFinite(grant.expiresAt) || grant.expiresAt <= Date.now())
    ) return undefined;

    // Prefer the original JWT wire form when present: its envelope is the proof.
    // Legacy rows without signed evidence intentionally require authorization again.
    const evidence = grant.credentialJwt ?? grant.delegationCredential;
    if (evidence === undefined) return undefined;
    try {
      const check = await verifyEncodableDelegation(evidence);
      if (!check.valid) return undefined;
      const subject = check.vc.credentialSubject;
      if (
        subject.id !== grant.agentDid ||
        !namesItsResponsibleParty(grant, check.rootIssuer, subject.delegation.controller) ||
        !scopeSatisfies(scopeId, check.vc).satisfied
      ) return undefined;
      const credentialDigest = check.evidence.delegationCredentialDigest;
      if (
        claims !== undefined &&
        (credentialDigest === undefined ||
          !(await admitsRetainedDelegation(claims, {
            credentialDigest,
            delegationRef: check.evidence.delegationRef,
            chainDigest: check.chainDigest,
          })))
      ) return undefined;
      return {
        grant,
        delegatedScopes: getDelegationScopes(check.vc),
        rootIssuer: check.rootIssuer,
        evidence: check.evidence,
        chainEvidence: check.chainEvidence,
      };
    } catch {
      // Resolver/provider failures must not turn cached authority into a bypass.
      return undefined;
    }
  }

  /** The holder of a call that presents no delegation, and what its proof says of the delegation it means. */
  interface Holder {
    agentDid: string;
    claims: ProofDelegationClaims;
  }

  /**
   * The holder a no-delegation call proves itself to be, or undefined. The
   * agent DID is taken from the `_kyaos_proof` and re-proven per request
   * (possession of the subject key over THIS request), never trusted from a
   * bearer hint. This is the single most security-sensitive gate of the
   * durable-consent change: without it, any caller who knows agent A's DID
   * could replay A's grant (confused-deputy escalation, spec §A.4).
   */
  async function provenHolder(toolName: string, args: Record<string, unknown>): Promise<Holder | undefined> {
    if (!holderBindingVerifier) return undefined; // inert unless holder binding is on
    const proofArg = args["_kyaos_proof"];
    if (proofArg === undefined) return undefined;
    let parsedProof: unknown = proofArg;
    if (typeof proofArg === "string") {
      try {
        parsedProof = JSON.parse(proofArg);
      } catch {
        return undefined;
      }
    }
    const proof = parsedProof as DetachedProof;
    const agentDid = proof?.meta?.did;
    if (typeof agentDid !== "string" || !isHolderBindingApplicable(agentDid)) {
      return undefined;
    }
    const binding = await verifyDelegatedCallProof({
      proof,
      subjectDid: agentDid,
      request: toHolderBindingRequest(toolName, args),
      expectedAudience: identity.did,
      proofVerifier: holderBindingVerifier,
      presented: null,
      mode: requestBindingMode,
      hash,
    });
    if (binding.status !== "bound" || binding.claims === undefined) return undefined;
    warnOfUnnamedProof(binding);
    return { agentDid, claims: binding.claims };
  }

  /** The digest of the credential `grant` retains, or undefined when it retains none with a signed form. */
  async function retainedDigest(grant: Grant): Promise<string | undefined> {
    const evidence = grant.credentialJwt ?? grant.delegationCredential;
    try {
      return evidence === undefined ? undefined : await delegationCredentialDigest(evidence as ReceivedCredential, hash);
    } catch {
      return undefined;
    }
  }

  /**
   * The first of `grants` that authorizes `scopeId` under a delegation
   * `holder`'s proof admits. A proof that names a credential resolves only a
   * grant of that one, so the call is not run under another Responsible
   * Party's grant for the agent. One that states `none` names no credential:
   * where the grants hold more than one, `require` resolves none of them, since
   * nothing says which the holder means, and `prefer` takes the first with a
   * warning.
   */
  async function firstAdmitted(grants: readonly Grant[], scopeId: string, holder: Holder): Promise<ResolvedGrant | undefined> {
    const unnamed = holder.claims.statement.kind === "none";
    let first: ResolvedGrant | undefined;
    for (const grant of grants) {
      if (first === undefined) {
        first = await authorizeGrant(grant, scopeId, holder.claims);
        if (first !== undefined && !unnamed) return first;
        continue;
      }
      const own = first.evidence.delegationCredentialDigest;
      if (requestBindingMode === "require") {
        const another = await authorizeGrant(grant, scopeId, holder.claims);
        if (another !== undefined && another.evidence.delegationCredentialDigest !== own) {
          logger.warn(
            `[kya-os] No grant resolved for scope "${scopeId}": the request proof names no delegation, and the grants retained for its subject hold more than one`,
          );
          return undefined;
        }
      } else {
        const other = await retainedDigest(grant);
        if (other === undefined || other === own) continue;
        warnOfNoneAmongGrants();
        return first;
      }
    }
    return first;
  }

  async function resolveExistingGrant(
    toolName: string,
    args: Record<string, unknown>,
    sessionId: string | undefined,
    scopeId: string,
  ): Promise<ResolvedGrant | undefined> {
    const holder = await provenHolder(toolName, args);
    if (holder !== undefined) {
      // A session-bound grant is usable only from its own session; an
      // agent-anchored (session-less) grant is portable across transports.
      const grants = (await grantStore.getByAgent(holder.agentDid, [scopeId])).filter(
        (grant) => grant.agentDid === holder.agentDid && (grant.sessionId === undefined || grant.sessionId === sessionId),
      );
      const agentGrant = await firstAdmitted(grants, scopeId, holder);
      if (agentGrant) return agentGrant;
    }

    if (sessionId) {
      const grants = await grantStore.getBySession(sessionId, [scopeId]);
      for (const grant of grants) {
        if (grant.sessionId !== sessionId) continue;
        // Enforce applies to every did:key retry, even with a session bearer.
        // A verified proof would already have resolved it through the agent path.
        if (
          holderBindingMode === "enforce" &&
          isHolderBindingApplicable(grant.agentDid)
        ) continue;
        // A proof the grant's own agent made is held to here as well: what it
        // names is not answered by a session grant of another delegation.
        const resolved = await authorizeGrant(
          grant,
          scopeId,
          holder !== undefined && holder.agentDid === grant.agentDid ? holder.claims : undefined,
        );
        if (resolved) return resolved;
      }
    }
    return undefined;
  }

  async function bindGrantOnSuccess(
    vc: DelegationCredential,
    delegationArg: unknown,
    isVCJWT: boolean,
    sessionId: string | undefined,
    scopeId: string,
    responsibleParty: string,
    expiresAt?: number,
  ): Promise<void> {
    try {
      const agentDid = vc.credentialSubject?.id;
      if (!agentDid) return;

      // A session-less grant minted with holder binding OFF is unresolvable on
      // retry (getByAgent needs a holder-of-key proof; getBySession needs a
      // sessionId), so DON'T bind it — that would only orphan a row in a durable
      // store. Durability for such flows comes from re-presenting the delegation,
      // not from a grant. Enable holderBinding 'enforce' or thread a sessionId to
      // use the grant-backed no-paste retry.
      if (holderBindingMode === "off" && sessionId === undefined) {
        logger.debug(
          `[kya-os] Skipping an unresolvable session-less grant for scope "${scopeId}" (holderBinding 'off', no sessionId).`,
        );
        return;
      }

      let delegatedScopes: string[];
      try {
        delegatedScopes = getDelegationScopes(vc);
      } catch {
        delegatedScopes = [];
      }
      // Store the EXACT required scope alongside the delegated scopes. The retry
      // queries by the tool's exact scopeId, but the delegation may have granted
      // a prefix/regex scope (e.g. "cart:*"); the store's exact `coversScopes`
      // would never match the wildcard, so the no-paste retry would silently
      // re-challenge. Including scopeId makes the grant resolvable.
      const scopes = Array.from(new Set([scopeId, ...delegatedScopes]));
      const grant: Grant = {
        id: await grantId(agentDid, sessionId, scopes),
        agentDid,
        responsibleParty,
        scopes,
        ...(sessionId !== undefined ? { sessionId } : {}),
        authorization: { type: "delegation" },
        ...(isVCJWT && typeof delegationArg === "string"
          ? { credentialJwt: delegationArg }
          : { delegationCredential: structuredClone(vc) }),
        issuedAt: Date.now(),
        ...(expiresAt !== undefined ? { expiresAt } : {}),
        status: "active",
      };
      await grantStore.bind(grant);
    } catch (error) {
      logger.error("[kya-os] Grant bind failed", {
        scope: scopeId,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return { resolveExistingGrant, bindGrantOnSuccess };
}
