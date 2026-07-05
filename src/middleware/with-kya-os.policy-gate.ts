/**
 * KYA-OS Middleware — the per-action policy / step-up gate.
 *
 * Composed AFTER `wrapWithDelegation` (which enforces identity + scope), this
 * adds the PROPORTIONALITY layer: classify the action's risk, ask a pluggable
 * PolicyEngine, and either allow, deny (signed denial proof), or require N-of-M
 * human approval before the handler runs. Extracted from `./with-kya-os.ts`.
 */

import { logger } from "../logging/index.js";
import { RiskClassifier } from "../policy/classifier.js";
import { DefaultPolicyEngine } from "../policy/default-engine.js";
import { verifyApprovalQuorum, type ApprovalGrant } from "../policy/approval.js";
import type { PolicyEngine } from "../policy/engine.js";
import { buildPolicyRequest } from "../policy/projection.js";
import { createNeedsApprovalError } from "../types/protocol.js";
import { isKyaOsControlArg } from "../delegation/holder-binding.js";
import { KYA_OS_ERROR_CODES } from "../errors.js";
import type {
  KyaOsToolHandler,
  KyaOsPolicyGate,
  PolicyGateOptions,
} from "./with-kya-os.types.js";
import type { MiddlewareDeps, AttachOutcomeProof } from "./with-kya-os.deps.js";
import { sanitizeForMessage, extractPolicyPrincipal } from "./with-kya-os.helpers.js";

/** Collaborators the policy gate borrows from the session/proof sub-factory. */
export interface PolicyGateWiring {
  attachOutcomeProof: AttachOutcomeProof;
}

export function createPolicyGate(
  deps: MiddlewareDeps,
  wiring: PolicyGateWiring,
): Pick<KyaOsPolicyGate, "withPolicyGate"> {
  const { proofGenerator } = deps;
  const { attachOutcomeProof } = wiring;

  const defaultRiskClassifier = new RiskClassifier();
  const defaultPolicyEngine: PolicyEngine = new DefaultPolicyEngine();

  function withPolicyGate(
    toolName: string,
    handler: KyaOsToolHandler,
    opts: PolicyGateOptions = {},
  ): KyaOsToolHandler {
    const engine = opts.engine ?? defaultPolicyEngine;
    const classifier = opts.classifier ?? defaultRiskClassifier;
    const approvalsKey = opts.approvalsArgKey ?? "_kyaos_approvals";
    const isValidApprovalSignature =
      opts.isValidApprovalSignature ?? (async () => false);

    return async (args: Record<string, unknown>, sessionId?: string) => {
      // Drop the reserved _kyaos* namespace plus the (possibly custom) approvals
      // key, so no control arg reaches the handler.
      const cleanArgs: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(args)) {
        if (!isKyaOsControlArg(k) && k !== approvalsKey) cleanArgs[k] = v;
      }

      const namespace = opts.resolveNamespace?.(args) ?? toolName;
      const risk = classifier.classify({ toolName, namespace });
      const principal = extractPolicyPrincipal(args["_kyaos_delegation"]);

      const policyRequest = buildPolicyRequest({
        principal: {
          agentDid: principal.agentDid,
          ...(principal.responsibleParty
            ? { responsibleParty: principal.responsibleParty }
            : {}),
        },
        action: { toolName },
        resource: { namespace },
        delegatedScopes: principal.delegatedScopes,
        scopeMatched: opts.scopeMatched ?? false,
        risk,
      });

      const decision = await engine.evaluate(policyRequest);

      if (decision.decision === "allow") {
        return handler(cleanArgs, sessionId);
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
          args,
          sessionId,
          decision.reason,
          "denied",
          cleanArgs,
        );
      }

      // step_up: verify any supplied approval grants, bound to this exact action.
      const requestHash = await proofGenerator.hashRequest({
        method: toolName,
        params: cleanArgs,
      });
      const grants = Array.isArray(args[approvalsKey])
        ? (args[approvalsKey] as ApprovalGrant[])
        : [];
      const quorumResult = await verifyApprovalQuorum(
        grants,
        requestHash,
        decision.quorum,
        isValidApprovalSignature,
      );
      if (quorumResult.satisfied) {
        return handler(cleanArgs, sessionId);
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
        args,
        sessionId,
        decision.reason,
        "step_up_required",
        cleanArgs,
      );
    };
  }

  return { withPolicyGate };
}
