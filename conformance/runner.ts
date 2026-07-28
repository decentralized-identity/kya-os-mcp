/**
 * KYA-OS Conformance Runner.
 *
 * Feeds each loaded vector to the supplied {@link ConformanceAdapter}, compares
 * the adapter's accept/reject outcome to the vector's `expected`, and aggregates
 * a {@link ConformanceReport}. A vector PASSES the suite when the adapter's
 * outcome equals `expected` — so a `fail` vector (a tampered proof, broken chain,
 * revoked credential, malformed DID) passes the suite only when the
 * implementation correctly REJECTS it.
 *
 * The runner is implementation-agnostic: it never imports `@kya-os/mcp`. To run
 * the reference implementation, pass {@link ./reference-adapter}; a third party
 * passes their own adapter (see CONFORMANCE.md).
 */

import type {
  AdapterResult,
  AuditIntegrityInput,
  CardProofInput,
  ConformanceAdapter,
  ConformanceVector,
  DelegationChainInput,
  DidResolutionInput,
  EntityCardInput,
  ExpectedOutcome,
  NegotiationInput,
  SignedProofInput,
  StatusListInput,
} from './types.js';

export interface VectorRunResult {
  id: string;
  category: ConformanceVector['category'];
  description: string;
  expected: ExpectedOutcome;
  actual: ExpectedOutcome | 'error';
  ok: boolean;
  detail?: string;
}

export interface ConformanceReport {
  adapter: string;
  total: number;
  passed: number;
  failed: number;
  results: VectorRunResult[];
  /** True iff every vector's actual outcome matched its expected outcome. */
  allMatched: boolean;
}

/** Dispatch a single vector to the adapter method for its category. */
async function dispatch(
  adapter: ConformanceAdapter,
  vector: ConformanceVector,
): Promise<AdapterResult> {
  switch (vector.category) {
    case 'signed-proof':
      return adapter.verifySignedProof(vector.input as SignedProofInput);
    case 'delegation-chain':
      return adapter.verifyDelegationChain(vector.input as DelegationChainInput);
    case 'status-list':
      return adapter.verifyStatusList(vector.input as StatusListInput);
    case 'did-key-resolution':
      return adapter.resolveDidKey(vector.input as DidResolutionInput);
    case 'did-web-resolution':
      return adapter.resolveDidWeb(vector.input as DidResolutionInput);
    case 'card-proof':
      return adapter.verifyCardProof(vector.input as CardProofInput);
    case 'entity-card':
      return adapter.verifyEntityCard(vector.input as EntityCardInput);
    case 'audit-integrity':
      return adapter.verifyAuditIntegrity(vector.input as AuditIntegrityInput);
    case 'negotiation':
      return adapter.evaluateNegotiation(vector.input as NegotiationInput);
    default: {
      const exhaustive: never = vector.category;
      throw new Error(`Unknown vector category: ${String(exhaustive)}`);
    }
  }
}

/**
 * Run every vector through the adapter and aggregate the report.
 *
 * A thrown error from an adapter method is recorded as `actual: 'error'` and
 * counts as a mismatch — adapters are required to be fail-closed and return
 * `{ outcome: 'fail' }` rather than throw.
 */
export async function runConformance(
  adapter: ConformanceAdapter,
  vectors: ConformanceVector[],
): Promise<ConformanceReport> {
  const results: VectorRunResult[] = [];

  for (const vector of vectors) {
    let actual: ExpectedOutcome | 'error';
    let detail: string | undefined;
    try {
      const result = await dispatch(adapter, vector);
      actual = result.outcome;
      detail = result.detail;
    } catch (error) {
      actual = 'error';
      detail = `adapter threw: ${error instanceof Error ? error.message : String(error)}`;
    }
    const ok = actual === vector.expected;
    results.push({
      id: vector.id,
      category: vector.category,
      description: vector.description,
      expected: vector.expected,
      actual,
      ok,
      detail,
    });
  }

  const passed = results.filter((r) => r.ok).length;
  const failed = results.length - passed;

  return {
    adapter: adapter.name,
    total: results.length,
    passed,
    failed,
    results,
    allMatched: failed === 0,
  };
}

/** Render a human-readable report suitable for CI logs. */
export function formatReport(report: ConformanceReport): string {
  const lines: string[] = [];
  lines.push(`KYA-OS Conformance — adapter: ${report.adapter}`);
  lines.push('');
  for (const r of report.results) {
    const mark = r.ok ? 'PASS' : 'FAIL';
    lines.push(`  [${mark}] ${r.id} (${r.category}) — expected ${r.expected}, got ${r.actual}`);
    if (!r.ok && r.detail) {
      lines.push(`         ${r.detail}`);
    }
  }
  lines.push('');
  lines.push(
    `Total: ${report.total}  Passed: ${report.passed}  Failed: ${report.failed}`,
  );
  lines.push(report.allMatched ? 'RESULT: PASS (all vectors matched)' : 'RESULT: FAIL');
  return lines.join('\n');
}
