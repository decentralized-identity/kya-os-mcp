/**
 * KYA-OS Middleware — the delegation gate (`wrapWithDelegation`).
 *
 * Requires a valid W3C Delegation Credential (or a durable grant / no-paste
 * retry), enforces holder-of-key binding (spec §11.8) and scope, then strips the
 * `_kyaos*` control namespace and runs the handler. Extracted from
 * `./with-kya-os.ts`; verification plumbing lives in `./with-kya-os.delegation-verify.ts`.
 */

import {
  isHolderBindingApplicable,
  isKyaOsControlArg,
  assertHolderBinding,
  toHolderBindingRequest,
} from "../delegation/holder-binding.js";
import { scopeSatisfies } from "../delegation/scope-matcher.js";
import { parseVCJWT } from "../delegation/utils.js";
import {
  type DelegationCredential,
  type DetachedProof,
} from "../types/protocol.js";
import { logger } from "../logging/index.js";
import { KYA_OS_ERROR_CODES } from "../errors.js";
import type {
  KyaOsToolHandler,
  KyaOsDelegationGate,
} from "./with-kya-os.types.js";
import type { MiddlewareDeps, AttachOutcomeProof } from "./with-kya-os.deps.js";
import type { GrantResolution } from "./with-kya-os.grants.js";
import { sanitizeForMessage } from "./with-kya-os.helpers.js";
import { canonicalizeJsonBytes } from "../utils/canonical-json.js";
import type { Digest } from "../audit/types.js";
import {
  createDelegationVerification,
  type DelegationGateConfig,
} from "./with-kya-os.delegation-verify.js";

const MAX_AUDIT_REFERENCE_LENGTH = 256;

/** Extract only a bounded string from an untrusted credential-shaped value. */
function rejectedDelegationRef(value: unknown): string {
  try {
    if (typeof value !== 'object' || value === null) return 'unknown';
    const credential = value as Record<string, unknown>;
    const direct = credential.id;
    if (typeof direct === 'string' && direct.length > 0) {
      return direct.slice(0, MAX_AUDIT_REFERENCE_LENGTH);
    }
    const subject = credential.credentialSubject;
    if (typeof subject !== 'object' || subject === null) return 'unknown';
    const delegation = (subject as Record<string, unknown>).delegation;
    if (typeof delegation !== 'object' || delegation === null) return 'unknown';
    const nested = (delegation as Record<string, unknown>).id;
    return typeof nested === 'string' && nested.length > 0
      ? nested.slice(0, MAX_AUDIT_REFERENCE_LENGTH)
      : 'unknown';
  } catch {
    // A hostile Proxy/getter must not turn a deny decision into an exception.
    return 'unknown';
  }
}

/** Collaborators the delegation gate borrows from its sibling sub-factories. */
export interface DelegationGateWiring {
  attachOutcomeProof: AttachOutcomeProof;
  resolveExistingGrant: GrantResolution["resolveExistingGrant"];
  bindGrantOnSuccess: GrantResolution["bindGrantOnSuccess"];
}

export function createDelegationGate(
  deps: MiddlewareDeps,
  wiring: DelegationGateWiring,
): Pick<KyaOsDelegationGate, "wrapWithDelegation"> {
  const { identity, holderBindingMode, holderBindingVerifier, audit, cryptoProvider } = deps;
  const { attachOutcomeProof, resolveExistingGrant, bindGrantOnSuccess } =
    wiring;
  const {
    validateDelegationChain,
    buildDelegationErrorResponse,
    buildNeedsAuthorizationChallenge,
  } = createDelegationVerification(deps);

  function wrapWithDelegation(
    toolName: string,
    config: DelegationGateConfig,
    handler: KyaOsToolHandler,
  ): KyaOsToolHandler {
    return async (args: Record<string, unknown>, sessionId?: string) => {
      const delegationArg = args["_kyaos_delegation"];

      if (delegationArg === undefined || delegationArg === null) {
        // No delegation pasted — a durable grant may already authorize this call
        // (the no-paste retry), even on a fresh instance with empty memory.
        // Holder-of-key first (agent-anchored, proof-gated), then the session
        // bearer capability. On a hit, skip the challenge and run the handler
        // with exactly the call shape a verified delegation would have produced.
        const existingGrant = await resolveExistingGrant(
          toolName,
          args,
          sessionId,
          config.scopeId,
        );
        if (existingGrant) {
          const grantArgs: Record<string, unknown> = {};
          for (const [k, v] of Object.entries(args)) {
            if (!isKyaOsControlArg(k)) grantArgs[k] = v;
          }
          logger.debug(
            `[kya-os] Grant resolved for "${toolName}" (scope "${config.scopeId}") — no re-paste required`,
          );
          const grantContext = {
            scopeId: config.scopeId,
            actor: { kind: 'pairwise_did' as const, did: existingGrant.agentDid },
            ...(existingGrant.userDid?.startsWith('did:')
              ? { responsibleParty: { kind: 'pairwise_did' as const, did: existingGrant.userDid } }
              : {}),
            authorization: {
              source: 'grant' as const,
              decision: 'allowed' as const,
              scopeId: config.scopeId,
              grantRef: existingGrant.id,
              verificationCode: 'DURABLE_GRANT_RESOLVED',
            },
          };
          await audit?.authorization('grant_used', {
            outcome: 'succeeded',
            grantRef: existingGrant.id,
            context: grantContext,
          });
          return handler(grantArgs, sessionId, grantContext);
        }

        // No delegation provided — sign & return the needs_authorization
        // challenge. The proof binds a responseHash over the EMITTED challenge
        // content (incl. the authorizationUrl), so a verifier that recomputes it
        // over the content it received detects a tampered/MITM-swapped consent
        // URL. Best-effort: attachOutcomeProof no-ops if no session resolves.
        const { challengeContent, message } =
          await buildNeedsAuthorizationChallenge(toolName, config);
        return attachOutcomeProof(
          { content: challengeContent },
          toolName,
          args,
          sessionId,
          message,
          "needs_authorization",
          undefined,
          challengeContent,
        );
      }

      // Accept delegation as either a JSON object (embedded proof) or a
      // VC-JWT string (compact JWT). The Cloudflare consent service issues
      // VC-JWTs; examples use embedded proofs. Support both transparently.
      let vc: DelegationCredential;
      let isVCJWT = false;
      if (typeof delegationArg === "string") {
        const parsed = parseVCJWT(delegationArg);
        if (!parsed || !parsed.payload.vc) {
          return attachOutcomeProof(
            buildDelegationErrorResponse(
              KYA_OS_ERROR_CODES.delegation_invalid,
              "Invalid VC-JWT format",
            ),
            toolName,
            args,
            sessionId,
            "Invalid VC-JWT format",
          );
        }
        vc = parsed.payload.vc as DelegationCredential;
        // VC-JWTs don't have an embedded proof — the JWT signature is the
        // proof. Add a marker so basic validation (which checks for proof
        // presence) passes. The actual signature is in the JWT envelope.
        if (!vc.proof) {
          vc = { ...vc, proof: { type: 'JwtProof2020', jwt: delegationArg } };
        }
        isVCJWT = true;
      } else {
        vc = delegationArg as DelegationCredential;
      }

      // For VC-JWTs the embedded-signature check is skipped (the JWT envelope
      // signature is the proof); schema/expiry/status/scope checks still apply.
      // validateDelegationChain performs the shape check and returns
      // { valid, reason } for malformed input, never throwing on normal or
      // structurally-malformed credentials. This try/catch is therefore a PURE
      // BACKSTOP — it fires only on a truly unexpected throw (e.g. a hostile
      // getter/Proxy accessor or a provider fault): it logs the detail
      // server-side and returns a GENERIC reason, so no internal/implementation
      // detail (stack, raw error text) leaks to the client or the signed proof.
      const verificationResult = await (async (): Promise<{
        valid: boolean;
        reason?: string;
      }> => {
        try {
          return await validateDelegationChain(vc, { skipSignature: isVCJWT });
        } catch (error) {
          logger.error("[kya-os] Unexpected error verifying delegation", {
            tool: toolName,
            error: error instanceof Error ? error.message : String(error),
            stack: error instanceof Error ? error.stack : undefined,
          });
          return { valid: false, reason: "Delegation credential could not be verified" };
        }
      })();

      if (!verificationResult.valid) {
        const reason = verificationResult.reason ?? "Unknown delegation validation error";
        try {
          await audit?.delegation('rejected', {
            delegationRef: rejectedDelegationRef(vc),
            outcome: 'failed',
            reasonCode: 'DELEGATION_VERIFICATION_FAILED',
          });
        } catch (error) {
          logger.error('[kya-os] Failed to record rejected delegation audit event', {
            tool: toolName,
            error: error instanceof Error ? error.message : String(error),
          });
        }
        logger.warn(
          `[kya-os] Delegation verification failed for "${toolName}": ${sanitizeForMessage(reason)}`,
        );
        return attachOutcomeProof(
          buildDelegationErrorResponse(KYA_OS_ERROR_CODES.delegation_invalid, reason),
          toolName,
          args,
          sessionId,
          reason,
        );
      }

      // Holder binding (spec §11.8): the delegation is valid, but a valid
      // *credential* is a bearer token until we also prove the caller holds the
      // delegation SUBJECT's key. Opt-in via `delegation.holderBinding`. did:key
      // subjects are bound here; did:web is deferred to cnf binding (phase 2) and
      // logged, never rejected. Runs after identity is established, before scope.
      if (holderBindingMode !== "off" && holderBindingVerifier) {
        const subjectDid = vc.credentialSubject?.id;
        if (subjectDid && isHolderBindingApplicable(subjectDid)) {
          const proofArg = args["_kyaos_proof"];
          if (proofArg === undefined) {
            const reason =
              "Holder-of-key proof (_kyaos_proof) is required for this delegation subject";
            logger.warn(
              `[kya-os] Holder binding: "${toolName}" called without _kyaos_proof`,
            );
            if (holderBindingMode === "enforce") {
              return attachOutcomeProof(
                buildDelegationErrorResponse(
                  KYA_OS_ERROR_CODES.holder_binding_failed,
                  reason,
                ),
                toolName,
                args,
                sessionId,
                reason,
              );
            }
          } else {
            let parsedProof: unknown = proofArg;
            if (typeof proofArg === "string") {
              try {
                parsedProof = JSON.parse(proofArg);
              } catch {
                parsedProof = {};
              }
            }
            const binding = await assertHolderBinding({
              proof: parsedProof as DetachedProof,
              subjectDid,
              request: toHolderBindingRequest(toolName, args),
              expectedAudience: identity.did,
              proofVerifier: holderBindingVerifier,
            });
            if (binding.status !== "bound") {
              const reason =
                binding.reason ??
                "Holder-of-key proof did not bind the delegation subject";
              logger.warn(
                `[kya-os] Holder binding ${binding.status} for "${toolName}": ${sanitizeForMessage(reason)}`,
              );
              if (holderBindingMode === "enforce") {
                return attachOutcomeProof(
                  buildDelegationErrorResponse(
                    KYA_OS_ERROR_CODES.holder_binding_failed,
                    reason,
                  ),
                  toolName,
                  args,
                  sessionId,
                  reason,
                );
              }
            }
          }
        } else if (subjectDid) {
          // Non-did:key subject — phase 1 cannot pin its key; defer to cnf
          // binding (phase 2) rather than reject legitimate traffic.
          logger.warn(
            `[kya-os] Holder binding: subject "${subjectDid}" is not did:key; deferring to cnf binding (phase 2)`,
          );
        }
      }

      // Safe to call directly: the structural guard + validateDelegationChain
      // above guarantee a well-formed credential here, and scopeSatisfies is
      // bounded (ReDoS-guarded) and returns rather than throws.
      const scopeResult = scopeSatisfies(config.scopeId, vc);
      if (scopeResult.usedNonExactMatcher) {
        logger.warn(
          `[kya-os] Scope "${config.scopeId}" for "${toolName}" granted via a non-exact ` +
            `(prefix/regex) matcher. Verify this is intended — non-exact matchers widen authority.`,
        );
      }
      if (!scopeResult.satisfied) {
        const reason = `Required scope "${config.scopeId}" not in delegation scopes`;
        logger.warn(
          `[kya-os] Delegation missing required scope "${config.scopeId}" for "${toolName}"`,
        );
        return attachOutcomeProof(
          buildDelegationErrorResponse(KYA_OS_ERROR_CODES.insufficient_scope, reason),
          toolName,
          args,
          sessionId,
          reason,
        );
      }

      const serializedCredential = isVCJWT
        ? new TextEncoder().encode(delegationArg as string)
        : canonicalizeJsonBytes(vc);
      const credentialDigest = await cryptoProvider.hash(serializedCredential) as Digest;
      const delegationRef = vc.id ?? vc.credentialSubject.delegation.id;
      const actor = { kind: 'pairwise_did' as const, did: vc.credentialSubject.id };
      const controller = vc.credentialSubject.delegation.controller;
      const authorization = {
        source: 'delegation' as const,
        decision: 'allowed' as const,
        scopeId: config.scopeId,
        delegationRef,
        delegationCredentialDigest: credentialDigest,
        verificationCode: 'DELEGATION_CHAIN_VALID',
      };
      const callContext = {
        scopeId: config.scopeId,
        actor,
        ...(controller?.startsWith('did:')
          ? { responsibleParty: { kind: 'pairwise_did' as const, did: controller } }
          : {}),
        authorization,
      };

      await audit?.delegation('verified', {
        delegationRef,
        outcome: 'succeeded',
        parentRef: vc.credentialSubject.delegation.parentId,
        context: callContext,
      });
      await audit?.authorization('approved', {
        outcome: 'succeeded',
        context: callContext,
      });

      // Strip the reserved _kyaos* control namespace before passing to the
      // handler — same predicate the bound request hash uses, so the handler
      // receives exactly the call the subject signed (no smuggled control arg).
      const cleanArgs: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(args)) {
        if (!isKyaOsControlArg(k)) cleanArgs[k] = v;
      }

      // Mint a durable grant from this verified delegation so the next call —
      // on any instance — resolves via resolveExistingGrant with no re-paste.
      await bindGrantOnSuccess(vc, delegationArg, isVCJWT, sessionId, config.scopeId);

      logger.debug(
        `[kya-os] Delegation verified for "${toolName}", scope "${config.scopeId}"`,
      );
      return handler(cleanArgs, sessionId, callContext);
    };
  }

  return { wrapWithDelegation };
}
