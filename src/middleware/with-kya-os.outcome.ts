/**
 * KYA-OS Middleware — `proveOutcome`, the public entry to outcome proofs.
 *
 * Application code that decides an authorization outcome itself (a provider
 * enforcing OAuth scopes in-server, say) proves it here with the proof the
 * gates attach to theirs. There is one implementation, `attachOutcomeProof`
 * in `./with-kya-os.session.ts`; this module only adapts a request object to
 * it, so the claims, `_meta` keys, profile handling, audit events and
 * lifecycle stamp cannot drift between the gates and application code.
 */

import type {
  KyaOsAuthorizationOutcome,
  KyaOsOutcomeProofRequest,
  KyaOsOutcomeProver,
  KyaOsToolResult,
} from "./with-kya-os.types.js";
import type { AttachOutcomeProof } from "./with-kya-os.deps.js";
import { withoutOutcomeMeta } from "./with-kya-os.session.js";
import { withoutControlArgs } from "./with-kya-os.helpers.js";

const OUTCOMES: ReadonlySet<string> = new Set<KyaOsAuthorizationOutcome>([
  "needs_authorization",
  "step_up_required",
  "denied",
]);

/** Collaborators the outcome prover borrows from the session/proof sub-factory. */
export interface OutcomeProverWiring {
  attachOutcomeProof: AttachOutcomeProof;
}

export function createOutcomeProver(wiring: OutcomeProverWiring): KyaOsOutcomeProver {
  const { attachOutcomeProof } = wiring;

  return {
    async proveOutcome<R extends KyaOsToolResult>(request: KyaOsOutcomeProofRequest<R>): Promise<R> {
      if (!OUTCOMES.has(request.outcome)) {
        throw new TypeError(
          `proveOutcome: unknown outcome ${JSON.stringify(request.outcome)}; ` +
            `expected one of ${[...OUTCOMES].join(", ")}`,
        );
      }
      const params = withoutControlArgs(request.args);
      // A copy, so the caller's result is never changed, without the `_meta`
      // members only the middleware may set.
      const result = { ...withoutOutcomeMeta(request.result) };
      // The same members, plus `_meta`: still an R.
      return attachOutcomeProof(
        result,
        request.toolName,
        params,
        request.sessionId,
        request.reason,
        request.outcome,
        params,
      ) as Promise<R>;
    },
  };
}
