/**
 * Step-up approval grants and quorum verification.
 *
 * A step-up suspends a high-risk action until N-of-M approvers each sign a
 * grant bound to the EXACT requestHash of the suspended action. Binding to the
 * requestHash defeats the TOCTOU swap where a human approves one action and a
 * different one is forwarded.
 */
export interface ApprovalGrant {
  approvalRequestId: string;
  approverDid: string;
  /** MUST equal the suspended action's requestHash. */
  requestHash: string;
  decision: 'approve' | 'deny';
  ts: number;
  /** Verified by the caller-supplied `isValidSignature` (identity-layer concern). */
  signature: string;
}

export interface QuorumResult {
  satisfied: boolean;
  reason?: string;
  /**
   * The distinct approver DIDs whose grants verified (allowlisted, bound to the
   * request, signature accepted), whether or not they reached the quorum. The
   * only set a policy engine's `humanApprovals` should be built from.
   * `verifyApprovalQuorum` always sets it; it is optional so that code
   * building its own `QuorumResult` keeps compiling.
   */
  approvers?: string[];
}

export interface Quorum {
  n: number;
  /** Allowed approver DIDs; empty = any identity may approve. */
  approvers: string[];
}

/**
 * Quorum is satisfied iff at least `quorum.n` DISTINCT approvers each signed an
 * `approve` grant over EXACTLY `requestHash`, drawn from `quorum.approvers`
 * (empty = any), with a signature accepted by `isValidSignature`.
 *
 * `requestHash` may list several hashes when they all identify the one
 * suspended action, as the hashes of its legacy and SPEC §7.3 request shapes
 * do; a grant over any of them counts.
 */
export async function verifyApprovalQuorum(
  grants: ApprovalGrant[],
  requestHash: string | readonly string[],
  quorum: Quorum,
  isValidSignature: (g: ApprovalGrant) => Promise<boolean>,
): Promise<QuorumResult> {
  const actionHashes: readonly string[] = typeof requestHash === 'string'
    ? [requestHash]
    : requestHash;
  // A non-positive quorum is a misconfiguration (e.g. a third-party engine
  // returning {n:0}); treat it as never-satisfiable rather than auto-passing.
  if (quorum.n <= 0) {
    return { satisfied: false, reason: 'invalid_quorum:n<=0', approvers: [] };
  }

  const approvers = new Set<string>();

  for (const g of grants) {
    if (g.decision !== 'approve') continue;
    if (!actionHashes.includes(g.requestHash)) continue; // TOCTOU guard
    if (quorum.approvers.length > 0 && !quorum.approvers.includes(g.approverDid)) continue;
    if (!(await isValidSignature(g))) continue;
    approvers.add(g.approverDid);
  }

  if (approvers.size >= quorum.n) {
    return { satisfied: true, approvers: [...approvers] };
  }
  return {
    satisfied: false,
    reason: `quorum_not_met:${approvers.size}/${quorum.n}`,
    approvers: [...approvers],
  };
}
