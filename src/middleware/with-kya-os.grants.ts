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
import { getDelegationScopes } from "../delegation/chain-enforcement.js";
import {
  assertHolderBinding,
  isHolderBindingApplicable,
  toHolderBindingRequest,
} from "../delegation/holder-binding.js";
import { logger } from "../logging/index.js";
import type { MiddlewareDeps } from "./with-kya-os.deps.js";

export interface GrantResolution {
  /**
   * Resolve an existing durable grant for a no-delegation (retry) call, so a
   * fresh instance with empty memory authorizes the retry from the shared store.
   * Fail-closed, holder-of-key first (agent-anchored, portable), then the
   * session bearer capability. Returns undefined to fall through to the
   * needs_authorization challenge.
   */
  resolveExistingGrant(
    toolName: string,
    args: Record<string, unknown>,
    sessionId: string | undefined,
    scopeId: string,
  ): Promise<Grant | undefined>;
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
  ): Promise<void>;
}

export function createGrantResolution(deps: MiddlewareDeps): GrantResolution {
  const {
    identity,
    cryptoProvider,
    grantStore,
    holderBindingMode,
    holderBindingVerifier,
  } = deps;

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

  /** Grant expiry (ms epoch) derived from the VC, or undefined for no expiry. */
  function delegationExpiryMs(vc: DelegationCredential): number | undefined {
    if (vc.expirationDate) {
      const parsed = Date.parse(vc.expirationDate);
      if (!Number.isNaN(parsed)) return parsed;
    }
    const notAfter = vc.credentialSubject?.delegation?.constraints?.notAfter;
    if (typeof notAfter === "number") return notAfter * 1000;
    return undefined;
  }

  /**
   * Resolve a durable, agent-anchored grant for a no-delegation call — BUT ONLY
   * behind a verified holder-of-key proof. The agent DID is taken from the
   * `_kyaos_proof` and re-proven per request (possession of the subject key over
   * THIS request), never trusted from a bearer hint. This is the single most
   * security-sensitive gate of the durable-consent change: without it, any
   * caller who knows agent A's DID could replay A's grant (confused-deputy
   * escalation, spec §A.4). Returns undefined unless possession is proven.
   */
  async function resolveAgentGrant(
    toolName: string,
    args: Record<string, unknown>,
    sessionId: string | undefined,
    scopeId: string,
  ): Promise<Grant | undefined> {
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
    const binding = await assertHolderBinding({
      proof,
      subjectDid: agentDid,
      request: toHolderBindingRequest(toolName, args),
      expectedAudience: identity.did,
      proofVerifier: holderBindingVerifier,
    });
    if (binding.status !== "bound") return undefined;
    const grants = await grantStore.getByAgent(agentDid, [scopeId]);
    // A session-bound grant is usable only from its own session; an
    // agent-anchored (session-less) grant is portable across transports.
    return grants.find(
      (g) => g.sessionId === undefined || g.sessionId === sessionId,
    );
  }

  async function resolveExistingGrant(
    toolName: string,
    args: Record<string, unknown>,
    sessionId: string | undefined,
    scopeId: string,
  ): Promise<Grant | undefined> {
    const agentGrant = await resolveAgentGrant(toolName, args, sessionId, scopeId);
    if (agentGrant) return agentGrant;

    if (sessionId) {
      const [sessionGrant] = await grantStore.getBySession(sessionId, [scopeId]);
      if (sessionGrant) return sessionGrant;
    }
    return undefined;
  }

  async function bindGrantOnSuccess(
    vc: DelegationCredential,
    delegationArg: unknown,
    isVCJWT: boolean,
    sessionId: string | undefined,
    scopeId: string,
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
      const userDid = vc.credentialSubject?.delegation?.controller;
      const expiresAt = delegationExpiryMs(vc);

      const grant: Grant = {
        id: await grantId(agentDid, sessionId, scopes),
        agentDid,
        ...(userDid !== undefined ? { userDid } : {}),
        scopes,
        ...(sessionId !== undefined ? { sessionId } : {}),
        authorization: { type: "delegation" },
        ...(isVCJWT && typeof delegationArg === "string"
          ? { credentialJwt: delegationArg }
          : {}),
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
