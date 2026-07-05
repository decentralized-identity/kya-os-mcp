/**
 * KYA-OS Middleware — the internal dependency bag.
 *
 * `createKyaOsMiddleware` constructs these collaborators once and threads this
 * bag into each sub-factory (session/proof, grant-resolution, delegation-gate,
 * policy-gate). Internal to the middleware package — not part of the public API.
 */

import type { CryptoProvider } from "../providers/base.js";
import type { AuditLogProvider } from "../providers/audit-log.js";
import type { GrantStore } from "../providers/grant-store.js";
import type { SessionManager } from "../session/manager.js";
import type { ProofGenerator, ProofAgentIdentity } from "../proof/generator.js";
import type { ProofVerifier } from "../proof/verifier.js";
import type {
  KyaOsConfig,
  KyaOsDelegationConfig,
  KyaOsToolHandler,
} from "./with-kya-os.types.js";

/**
 * Attach a signed proof recording an authorization OUTCOME (denied / step-up /
 * needs-authorization) to a response. Provided by the session/proof sub-factory
 * and consumed by the delegation- and policy-gate sub-factories, so it is typed
 * here as the shared internal contract between them.
 */
export type AttachOutcomeProof = (
  response: Awaited<ReturnType<KyaOsToolHandler>>,
  toolName: string,
  args: Record<string, unknown>,
  sessionId: string | undefined,
  reason: string,
  outcome?: "denied" | "step_up_required" | "needs_authorization",
  paramsOverride?: Record<string, unknown>,
  responseData?: unknown,
) => Promise<Awaited<ReturnType<KyaOsToolHandler>>>;

/** The constructed dependencies shared across the middleware sub-factories. */
export interface MiddlewareDeps {
  /** Proof-generation identity (DID + key material). */
  identity: ProofAgentIdentity;
  /** The full user config (for `identity.agentName`, `autoSession`, …). */
  config: KyaOsConfig;
  cryptoProvider: CryptoProvider;
  sessionManager: SessionManager;
  proofGenerator: ProofGenerator;
  auditLog: AuditLogProvider;
  grantStore: GrantStore;
  delegationConfig: KyaOsDelegationConfig | undefined;
  holderBindingMode: "off" | "warn" | "enforce";
  /** Present iff holder binding is enabled; the inbound per-request proof verifier. */
  holderBindingVerifier: ProofVerifier | undefined;
  /** Mirror the proof under the legacy bare `_meta.proof` key (pre-1.1 back-compat). */
  emitLegacyProofKey: boolean;
}
