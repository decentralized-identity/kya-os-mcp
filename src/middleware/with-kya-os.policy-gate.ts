/**
 * KYA-OS Middleware — the per-action policy / step-up gate.
 *
 * Composed AFTER `wrapWithDelegation` (which enforces identity + scope), this
 * adds the PROPORTIONALITY layer: classify the action's risk, ask a pluggable
 * PolicyEngine, and either allow, deny (signed denial proof), or require N-of-M
 * human approval before the handler runs. Extracted from `./with-kya-os.ts`.
 */

import { RiskClassifier } from "../policy/classifier.js";
import { DefaultPolicyEngine } from "../policy/default-engine.js";
import { verifyApprovalQuorum, type ApprovalGrant } from "../policy/approval.js";
import type { PolicyEngine } from "../policy/engine.js";
import { buildPolicyRequest } from "../policy/projection.js";
import { createNeedsApprovalError } from "../types/protocol.js";
import { acceptedRequestHashes, type ToolRequest } from "../proof/generator.js";
import { KYA_OS_ERROR_CODES } from "../errors.js";
import { logger } from "../logging/index.js";
import type {
  KyaOsCallContext,
  KyaOsToolHandler,
  KyaOsPolicyGate,
  PolicyGateOptions,
} from "./with-kya-os.types.js";
import type { MiddlewareDeps, AttachOutcomeProof, RequireProofLayer } from "./with-kya-os.deps.js";
import {
  DEFAULT_APPROVALS_KEY,
  extractPolicyPrincipal,
  sanitizeForMessage,
  withoutControlArgs,
} from "./with-kya-os.helpers.js";

/** Collaborators the policy gate borrows from the session/proof sub-factory. */
export interface PolicyGateWiring {
  attachOutcomeProof: AttachOutcomeProof;
  requireProofLayer: RequireProofLayer;
}

export function createPolicyGate(
  deps: MiddlewareDeps,
  wiring: PolicyGateWiring,
): Pick<KyaOsPolicyGate, "withPolicyGate"> {
  const { proofGenerator, cryptoProvider, audit } = deps;
  const { attachOutcomeProof, requireProofLayer } = wiring;

  const defaultRiskClassifier = new RiskClassifier();
  const defaultPolicyEngine: PolicyEngine = new DefaultPolicyEngine();

  function withPolicyGate(
    toolName: string,
    handler: KyaOsToolHandler,
    opts: PolicyGateOptions = {},
  ): KyaOsToolHandler {
    const engine = opts.engine ?? defaultPolicyEngine;
    const classifier = opts.classifier ?? defaultRiskClassifier;
    const approvalsKey = opts.approvalsArgKey ?? DEFAULT_APPROVALS_KEY;
    if (approvalsKey !== DEFAULT_APPROVALS_KEY) {
      logger.warn(
        `[kya-os] withPolicyGate("${toolName}") reads approval grants from "${approvalsKey}". ` +
          `A key outside the _kyaos prefix reaches the handler as an ordinary tool argument, ` +
          `and a _kyaos-prefixed key does not survive wrapWithDelegation, which forwards only ` +
          `${DEFAULT_APPROVALS_KEY}.`,
      );
    }
    const isValidApprovalSignature =
      opts.isValidApprovalSignature ?? (async () => false);

    return async (
      callArgs: Record<string, unknown>,
      sessionId?: string,
      context?: KyaOsCallContext,
    ) => {
      requireProofLayer();
      // Composed after wrapWithDelegation, the approvals argument has already
      // been stripped and arrives in the call context; restore it so a step-up
      // resume verifies the same grants either way. The restored copy is only
      // read, never hashed or handed on: the client did not send it there.
      const args =
        callArgs[approvalsKey] === undefined && context?.approvals !== undefined
          ? { ...callArgs, [approvalsKey]: context.approvals }
          : callArgs;

      // The call as received, without its _kyaos* control arguments (SPEC
      // §7.3's covered request): what the handler runs with, what an inner
      // wrapWithProof binds, and what every outcome proof binds. A custom
      // approvals key outside the _kyaos prefix is an ordinary argument and
      // stays in.
      const handlerArgs = withoutControlArgs(callArgs);

      const namespace = opts.resolveNamespace?.(args) ?? toolName;
      const risk = classifier.classify({ toolName, namespace });
      // Prefer the principal wrapWithDelegation authenticated; the raw
      // `_kyaos_delegation` projection is the unverified standalone fallback.
      const principal =
        context?.principal ?? extractPolicyPrincipal(args["_kyaos_delegation"]);

      const policyRequest = buildPolicyRequest({
        principal: {
          agentDid: principal.agentDid,
          ...(principal.responsibleParty
            ? { responsibleParty: principal.responsibleParty }
            : {}),
        },
        action: { toolName },
        resource: { namespace },
        delegatedScopes: [...principal.delegatedScopes],
        scopeMatched: opts.scopeMatched ?? false,
        risk,
      });

      const decision = await engine.evaluate(policyRequest);

      const auditContext = context === undefined ? undefined : {
        ...(context.actor === undefined ? {} : { actor: context.actor }),
        ...(context.responsibleParty === undefined
          ? {}
          : { responsibleParty: context.responsibleParty }),
        ...(context.authorization === undefined
          ? {}
          : { authorization: context.authorization }),
      };
      await audit?.authorization('evaluated', {
        outcome: decision.decision === 'allow' ? 'succeeded'
          : decision.decision === 'deny' ? 'denied' : 'challenged',
        reasonCode: decision.decision === 'allow'
          ? undefined
          : decision.decision === 'deny' ? 'POLICY_DENIED' : 'POLICY_STEP_UP',
        context: auditContext,
      });

      if (decision.decision === "allow") {
        await audit?.authorization('approved', {
          outcome: 'succeeded',
          context: auditContext,
        });
        return handler(handlerArgs, sessionId, context);
      }

      if (decision.decision === "deny") {
        const denied: Awaited<ReturnType<KyaOsToolHandler>> = {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: KYA_OS_ERROR_CODES.policy_denied,
                reason: sanitizeForMessage(decision.reason),
              }),
            },
          ],
          isError: true,
        };
        return attachOutcomeProof(
          denied,
          toolName,
          callArgs,
          sessionId,
          decision.reason,
          "denied",
        );
      }

      // step_up: verify any supplied approval grants, bound to this exact action.
      // The challenge advertises the legacy-shape hash; a grant over the SPEC
      // §7.3 `tools/call` shape of the same action is accepted as well. The
      // action leaves the approvals key out: grants cannot bind a hash that
      // includes themselves.
      const approvedAction: ToolRequest = {
        method: toolName,
        params: Object.fromEntries(Object.entries(handlerArgs).filter(([key]) => key !== approvalsKey)),
      };
      const requestHash = await proofGenerator.hashRequest(approvedAction);
      const grants = Array.isArray(args[approvalsKey])
        ? (args[approvalsKey] as ApprovalGrant[])
        : [];
      const quorumResult = await verifyApprovalQuorum(
        grants,
        await acceptedRequestHashes(approvedAction, (bytes) => cryptoProvider.hash(bytes)),
        decision.quorum,
        isValidApprovalSignature,
      );
      if (quorumResult.satisfied) {
        await audit?.authorization('approved', {
          outcome: 'succeeded',
          context: auditContext,
        });
        return handler(handlerArgs, sessionId, context);
      }

      const needsApproval = createNeedsApprovalError({
        message: `Tool "${toolName}" requires ${decision.quorum.n}-of-N approval before it may proceed (${sanitizeForMessage(decision.reason)}).`,
        resumeToken: `step_up:${requestHash}`,
        expiresAt: Math.floor(Date.now() / 1000) + 300,
        requestHash,
        quorum: decision.quorum,
      });
      const stepUp: Awaited<ReturnType<KyaOsToolHandler>> = {
        content: [{ type: "text", text: JSON.stringify(needsApproval) }],
        isError: true,
      };
      return attachOutcomeProof(
        stepUp,
        toolName,
        callArgs,
        sessionId,
        decision.reason,
        "step_up_required",
      );
    };
  }

  return { withPolicyGate };
}
