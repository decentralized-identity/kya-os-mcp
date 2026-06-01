import { describe, it, expect } from "vitest";
import { buildPolicyRequest } from "../projection.js";
import type { RiskAssessment } from "../types.js";

const risk: RiskAssessment = {
  reversibility: "reversible",
  blastRadius: "record",
  severity: "low",
};

describe("buildPolicyRequest", () => {
  it("projects resolved facts into the canonical PolicyRequest shape", () => {
    const request = buildPolicyRequest({
      principal: { agentDid: "did:example:agent" },
      action: { toolName: "send_email" },
      resource: { namespace: "mail" },
      delegatedScopes: ["send:mail"],
      scopeMatched: true,
      risk,
    });

    expect(request).toEqual({
      principal: { agentDid: "did:example:agent" },
      action: { toolName: "send_email" },
      resource: { namespace: "mail" },
      context: {
        delegatedScopes: ["send:mail"],
        scopeMatched: true,
        humanApprovals: [],
        reversibility: "reversible",
        blastRadius: "record",
        severity: "low",
      },
    });
  });

  it("includes responsibleParty only when supplied", () => {
    const without = buildPolicyRequest({
      principal: { agentDid: "did:a" },
      action: { toolName: "t" },
      resource: { namespace: "n" },
      delegatedScopes: [],
      scopeMatched: false,
      risk,
    });
    expect("responsibleParty" in without.principal).toBe(false);

    const withParty = buildPolicyRequest({
      principal: { agentDid: "did:a", responsibleParty: "did:org" },
      action: { toolName: "t" },
      resource: { namespace: "n" },
      delegatedScopes: [],
      scopeMatched: false,
      risk,
    });
    expect(withParty.principal.responsibleParty).toBe("did:org");
  });

  it("defaults humanApprovals to empty and preserves supplied approvals", () => {
    const defaulted = buildPolicyRequest({
      principal: { agentDid: "did:a" },
      action: { toolName: "t" },
      resource: { namespace: "n" },
      delegatedScopes: [],
      scopeMatched: true,
      risk,
    });
    expect(defaulted.context.humanApprovals).toEqual([]);

    const supplied = buildPolicyRequest({
      principal: { agentDid: "did:a" },
      action: { toolName: "t" },
      resource: { namespace: "n" },
      delegatedScopes: [],
      scopeMatched: true,
      risk,
      humanApprovals: ["did:approver"],
    });
    expect(supplied.context.humanApprovals).toEqual(["did:approver"]);
  });

  it("includes budgetRemaining only when supplied", () => {
    const without = buildPolicyRequest({
      principal: { agentDid: "did:a" },
      action: { toolName: "t" },
      resource: { namespace: "n" },
      delegatedScopes: [],
      scopeMatched: true,
      risk,
    });
    expect("budgetRemaining" in without.context).toBe(false);

    const withBudget = buildPolicyRequest({
      principal: { agentDid: "did:a" },
      action: { toolName: "t" },
      resource: { namespace: "n" },
      delegatedScopes: [],
      scopeMatched: true,
      risk,
      budgetRemaining: 42,
    });
    expect(withBudget.context.budgetRemaining).toBe(42);
  });

  it("carries the risk assessment through into context", () => {
    const request = buildPolicyRequest({
      principal: { agentDid: "did:a" },
      action: { toolName: "t" },
      resource: { namespace: "n" },
      delegatedScopes: [],
      scopeMatched: true,
      risk: {
        reversibility: "irreversible",
        blastRadius: "tenant",
        severity: "catastrophic",
      },
    });
    expect(request.context.reversibility).toBe("irreversible");
    expect(request.context.blastRadius).toBe("tenant");
    expect(request.context.severity).toBe("catastrophic");
  });
});
