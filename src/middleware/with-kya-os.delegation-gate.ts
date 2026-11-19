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
  assertHolderBinding,
  toHolderBindingRequest,
} from "../delegation/holder-binding.js";
import { scopeSatisfies } from "../delegation/scope-matcher.js";
import { getDelegationScopes } from "../delegation/chain-enforcement.js";
import { NO_DELEGATION_ID } from "../delegation/delegation-id.js";
import { type DetachedProof } from "../types/protocol.js";
import { logger } from "../logging/index.js";
import { KYA_OS_ERROR_CODES } from "../errors.js";
import { CHECKER_REASON_LENGTH, OPERATOR_REASON_LENGTH } from "../utils/revocation-answer.js";
import { coded } from "../utils/refusal.js";
import { describeValue } from "../utils/describe-value.js";
import type {
  KyaOsCallContext,
  KyaOsToolHandler,
  KyaOsDelegationGate,
} from "./with-kya-os.types.js";
import type { MiddlewareDeps, AttachOutcomeProof, RequireProofLayer } from "./with-kya-os.deps.js";
import type { GrantResolution } from "./with-kya-os.grants.js";
import { DEFAULT_APPROVALS_KEY, sanitizeForMessage, withoutControlArgs } from "./with-kya-os.helpers.js";
import {
  type DelegationRecords,
  type DelegationVerification,
  type DelegationGateConfig,
} from "./with-kya-os.delegation-verify.js";
import type { AuthorizationEvidence } from "../audit/types.js";

/**
 * Approval grants for a composed policy gate. They ride the reserved
 * `_kyaos_approvals` argument, which is withheld from the handler like every
 * control argument, so they travel on in the call context instead.
 */
function forwardedApprovals(args: Record<string, unknown>): Pick<KyaOsCallContext, "approvals"> {
  const approvals = args[DEFAULT_APPROVALS_KEY];
  return approvals === undefined ? {} : { approvals };
}

/**
 * `context` for an audit event that records the gate's verdict on a
 * delegation: its authorization evidence, with the digest of each credential
 * evaluated. The list is recorded with the verdict and not carried with the
 * call, whose later events refer to the credential by reference and digest.
 */
function withChainEvidence<C extends { authorization: AuthorizationEvidence }>(
  context: C,
  records: Pick<DelegationRecords, "chainEvidence">,
): C {
  return { ...context, authorization: { ...context.authorization, ...records.chainEvidence } };
}

/** Collaborators the delegation gate borrows from its sibling sub-factories. */
export interface DelegationGateWiring {
  delegationVerification: DelegationVerification;
  attachOutcomeProof: AttachOutcomeProof;
  requireProofLayer: RequireProofLayer;
  resolveExistingGrant: GrantResolution["resolveExistingGrant"];
  bindGrantOnSuccess: GrantResolution["bindGrantOnSuccess"];
}

export function createDelegationGate(
  deps: MiddlewareDeps,
  wiring: DelegationGateWiring,
): Pick<KyaOsDelegationGate, "wrapWithDelegation"> {
  const { identity, holderBindingMode, holderBindingVerifier, audit } = deps;
  const { attachOutcomeProof, requireProofLayer, resolveExistingGrant, bindGrantOnSuccess } =
    wiring;

  /**
   * Log a call whose holder-of-key proof is missing or does not bind, as `what` says, with the
   * proof's `reason` when there is one. Under `enforce` the call is refused, so the line carries
   * the refusal's code; under `warn` it is let through, so the line says so and carries none.
   */
  const logUnboundHolder = (what: string, reason?: string): void => {
    const why = reason === undefined ? "" : `: ${sanitizeForMessage(reason, CHECKER_REASON_LENGTH)}`;
    if (holderBindingMode === "enforce") {
      logger.warn(`[kya-os] Holder binding${what}${why}`, coded("holder_binding_failed"));
    } else {
      logger.warn(`[kya-os] Holder binding${what}; the call was allowed, as holderBinding is "warn"${why}`);
    }
  };
  const {
    verifyEncodableDelegation,
    buildDelegationErrorResponse,
    buildNeedsAuthorizationChallenge,
  } = wiring.delegationVerification;

  function wrapWithDelegation(
    toolName: string,
    config: DelegationGateConfig,
    handler: KyaOsToolHandler,
  ): KyaOsToolHandler {
    return async (args: Record<string, unknown>, sessionId?: string) => {
      requireProofLayer();
      const delegationArg = args["_kyaos_delegation"];

      if (delegationArg === undefined || delegationArg === null) {
        // No delegation pasted — a durable grant may already authorize this call
        // (the no-paste retry), even on a fresh instance with empty memory.
        // Holder-of-key first, then policy-permitted session reuse. The resolver
        // revalidates signed evidence on both paths. On a hit, run the handler
        // with exactly the call shape a verified delegation would have produced.
        const resolvedGrant = await resolveExistingGrant(
          toolName,
          args,
          sessionId,
          config.scopeId,
        );
        if (resolvedGrant) {
          const existingGrant = resolvedGrant.grant;
          const grantArgs = withoutControlArgs(args);
          logger.debug(
            `[kya-os] Grant resolved for "${toolName}" (scope "${config.scopeId}") — no re-paste required`,
          );
          const grantContext = {
            scopeId: config.scopeId,
            actor: { kind: 'pairwise_did' as const, did: existingGrant.agentDid },
            responsibleParty: { kind: 'pairwise_did' as const, did: resolvedGrant.rootIssuer },
            // A grant stands for the delegation it was minted from, verified
            // again just now, so its events refer to that delegation too.
            authorization: {
              source: 'grant' as const,
              decision: 'allowed' as const,
              scopeId: config.scopeId,
              grantRef: existingGrant.id,
              ...resolvedGrant.evidence,
              verificationCode: 'DURABLE_GRANT_RESOLVED',
            },
          };
          await audit?.authorization('grant_used', {
            outcome: 'succeeded',
            grantRef: existingGrant.id,
            context: withChainEvidence(grantContext, resolvedGrant),
          });
          return handler(grantArgs, sessionId, {
            ...grantContext,
            principal: {
              agentDid: existingGrant.agentDid,
              responsibleParty: resolvedGrant.rootIssuer,
              delegatedScopes: resolvedGrant.delegatedScopes,
            },
            ...forwardedApprovals(args),
          });
        }

        // No delegation provided — sign & return the needs_authorization
        // challenge. The proof binds a responseHash over the EMITTED challenge
        // (incl. the authorizationUrl; the envelope under the envelope profile),
        // so a verifier that recomputes it over what it received detects a
        // tampered/MITM-swapped consent URL. Best-effort: attachOutcomeProof
        // no-ops if no session resolves.
        const { challenge, message } =
          await buildNeedsAuthorizationChallenge(toolName, config);
        return attachOutcomeProof(
          challenge,
          toolName,
          args,
          sessionId,
          message,
          "needs_authorization",
        );
      }

      // Authenticate the presented delegation (object embedded-proof OR VC-JWT
      // string) and normalize it to a verified credential. verifyDelegation owns
      // the wire-form-specific signature checks — the gate never sets
      // skipSignature itself, so a JWT envelope can't be silently skipped. The
      // gate hands the credential's values on, so it refuses those it cannot encode.
      const check = await verifyEncodableDelegation(delegationArg);
      if (!check.valid) {
        try {
          await audit?.delegation('rejected', {
            delegationRef: check.evidence.delegationRef ?? NO_DELEGATION_ID,
            outcome: 'failed',
            reasonCode: 'DELEGATION_VERIFICATION_FAILED',
            // What was refused, by reference and digest, and what its verification came to, as
            // DELEGATION_CHAIN_VALID records it for one that passed: the refusal code. The event
            // carries no reason text.
            context: withChainEvidence(
              {
                authorization: {
                  source: 'delegation',
                  decision: 'denied',
                  ...check.evidence,
                  verificationCode: check.code,
                },
              },
              check,
            ),
          });
        } catch (error) {
          logger.error('[kya-os] Failed to record rejected delegation audit event', {
            tool: toolName,
            error: error instanceof Error ? error.message : String(error),
          });
        }
        // The operator's log line carries the code and the full reason, up to the length an operator
        // reads, so a statusListIssuers remedy it ends with is whole; the client's reason stays cut at 256.
        logger.warn(
          `[kya-os] Delegation verification failed for "${toolName}": ${sanitizeForMessage(check.reason, OPERATOR_REASON_LENGTH)}`,
          { code: check.code, transient: check.transient },
        );
        return attachOutcomeProof(
          buildDelegationErrorResponse(KYA_OS_ERROR_CODES.delegation_invalid, check.reason),
          toolName,
          args,
          sessionId,
          check.reason,
        );
      }
      const { vc, isJwt } = check;

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
            logUnboundHolder(`: "${toolName}" called without _kyaos_proof`);
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
              logUnboundHolder(` ${binding.status} for "${toolName}"`, reason);
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
          // binding (phase 2) rather than reject legitimate traffic. The
          // subject is text its credential's issuer wrote, so it is quoted.
          logger.warn(
            `[kya-os] Holder binding: subject ${describeValue(subjectDid)} is not did:key; deferring to cnf binding (phase 2)`,
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
          coded("insufficient_scope"),
        );
        return attachOutcomeProof(
          buildDelegationErrorResponse(KYA_OS_ERROR_CODES.insufficient_scope, reason),
          toolName,
          args,
          sessionId,
          reason,
        );
      }

      const actor = { kind: 'pairwise_did' as const, did: vc.credentialSubject.id };
      // The Responsible Party is the chain's root issuer, which the check verified (SPEC.md §2),
      // never the `controller` a credential's own issuer writes.
      const responsibleParty = check.rootIssuer;
      const authorization = {
        source: 'delegation' as const,
        decision: 'allowed' as const,
        scopeId: config.scopeId,
        ...check.evidence,
        verificationCode: 'DELEGATION_CHAIN_VALID',
      };
      const callContext = {
        scopeId: config.scopeId,
        actor,
        responsibleParty: { kind: 'pairwise_did' as const, did: responsibleParty },
        authorization,
      };

      await audit?.delegation('verified', {
        delegationRef: check.evidence.delegationRef ?? NO_DELEGATION_ID,
        outcome: 'succeeded',
        parentRef: vc.credentialSubject.delegation.parentId,
        context: withChainEvidence(callContext, check),
      });
      await audit?.authorization('approved', {
        outcome: 'succeeded',
        context: callContext,
      });

      // Strip the reserved _kyaos* control namespace before passing to the
      // handler — same predicate the bound request hash uses, so the handler
      // receives exactly the call the subject signed (no smuggled control arg).
      const cleanArgs = withoutControlArgs(args);

      // Mint a durable grant from this verified delegation so the next call —
      // on any instance — resolves via resolveExistingGrant with no re-paste.
      await bindGrantOnSuccess(
        vc, delegationArg, isJwt, sessionId, config.scopeId, responsibleParty, check.expiresAt,
      );

      logger.debug(
        `[kya-os] Delegation verified for "${toolName}", scope "${config.scopeId}"`,
      );
      return handler(cleanArgs, sessionId, {
        ...callContext,
        principal: {
          agentDid: vc.credentialSubject.id,
          responsibleParty,
          delegatedScopes: getDelegationScopes(vc),
        },
        ...forwardedApprovals(args),
      });
    };
  }

  return { wrapWithDelegation };
}
