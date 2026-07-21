/**
 * KYA-OS Middleware — Core Implementation
 *
 * Adds identity, session management, and proof generation to MCP servers.
 *
 * For most use cases, prefer the high-level `withKyaOs()` adapter from
 * `./with-kya-os-server.ts` which (by default) auto-registers the handshake
 * tool and auto-attaches proofs to all tool responses:
 *
 *   import { withKyaOs } from '@kya-os/mcp';
 *   await withKyaOs(server, { crypto: new NodeCryptoProvider() });
 *
 * `createKyaOsMiddleware()` in this file is the lower-level API used
 * internally by `withKyaOs()` and for advanced use cases like the
 * low-level `Server` API or custom request handler patterns.
 */

import { type CryptoProvider } from "../providers/base.js";
import { RuntimeFetchProvider, NoopFetchProvider } from "../providers/runtime-fetch.js";
import { NoopAuditLogProvider } from "../providers/audit-log.js";
import { McpAuditEventAdapter } from "../audit/adapters/mcp.js";
import { MemoryGrantStore } from "../providers/grant-store.js";
import { SessionManager } from "../session/manager.js";
import {
  ProofGenerator,
  type ProofAgentIdentity,
} from "../proof/generator.js";
import { ProofVerifier } from "../proof/verifier.js";
import { SystemClockProvider } from "../providers/system-clock.js";
import { MemoryNonceCacheProvider } from "../providers/memory.js";
import { logger } from "../logging/index.js";
import {
  type KyaOsConfig,
  type KyaOsMiddleware,
} from "./with-kya-os.types.js";
import type { MiddlewareDeps } from "./with-kya-os.deps.js";
import { createGrantResolution } from "./with-kya-os.grants.js";
import { createPolicyGate } from "./with-kya-os.policy-gate.js";
import { createDelegationGate } from "./with-kya-os.delegation-gate.js";
import { createSessionProof } from "./with-kya-os.session.js";
import { createProtocol } from "./with-kya-os.protocol.js";

// The public type surface lives in `./with-kya-os.types.ts`; re-export it here so
// `import { KyaOsConfig, ... } from './with-kya-os'` continues to resolve unchanged.
export * from "./with-kya-os.types.js";

/**
 * Create KYA-OS middleware for a standard MCP SDK Server.
 *
 * For most use cases, prefer {@link withKyaOs} from `./with-kya-os-server.ts`
 * which wraps this function and (by default) auto-registers handshake +
 * auto-attaches proofs.
 *
 * Use `createKyaOsMiddleware` directly when:
 * - You use the low-level `Server` API (not `McpServer`)
 * - You need custom request handler patterns
 * - You want per-tool control over proof/delegation wrapping
 *
 * @param config - Agent identity and session configuration
 * @param cryptoProvider - Platform-specific crypto implementation
 * @returns Middleware components for session management and proof generation
 *
 * @remarks
 * **Session resolution**: proof generation resolves the session from the explicit
 * `sessionId` threaded into each wrapper. A single-process `activeSessionId`
 * fallback (the established handshake/auto session) is consulted ONLY when no
 * sessionId was threaded — e.g. non-KYA-OS clients (MCP Inspector) and the
 * transport auto-proof path; a KYA-OS-aware call never depends on it. By default
 * sessions live in an in-memory Map; for multi-instance deployments inject a
 * durable `SessionStore` via `config.session.sessionStore`.
 */

export function createKyaOsMiddleware(
  config: KyaOsConfig,
  cryptoProvider: CryptoProvider,
): KyaOsMiddleware {
  if (config.audit && config.auditLog) {
    throw new TypeError('Configure either audit or legacy auditLog, not both');
  }
  const identity: ProofAgentIdentity = {
    did: config.identity.did,
    kid: config.identity.kid,
    privateKey: config.identity.privateKey,
    publicKey: config.identity.publicKey,
  };

  // One replay-protection store, shared by the handshake and holder binding.
  // Defaults to in-memory; SessionManager.cleanup() drives its expiry sweep.
  const nonceCache = config.nonceCache ?? new MemoryNonceCacheProvider();

  const sessionManager = new SessionManager(cryptoProvider, {
    ...config.session,
    serverDid: identity.did,
    nonceCache,
  });

  const proofGenerator = new ProofGenerator(identity, cryptoProvider);
  const delegationConfig = config.delegation;
  const auditLog = config.auditLog ?? new NoopAuditLogProvider();
  const audit = config.audit !== undefined && config.audit !== false
    ? new McpAuditEventAdapter(config.audit)
    : undefined;

  // Emit the proof under the legacy bare key as well, by default, for pre-1.1
  // back-compat. The value is identical under both keys and `_meta` is never
  // hashed (§7.6), so the mirror is purely additive.
  const emitLegacyProofKey = config.emitLegacyProofKey ?? true;

  // Durable grant store for the no-paste retry. Defaults to in-memory; inject a
  // shared, durable store for multi-instance / restart survival (mirrors the
  // nonceCache precedent and its production warning).
  const grantStore = config.grantStore ?? new MemoryGrantStore();
  if (!config.grantStore) {
    logger.warn(
      "[kya-os] Using MemoryGrantStore — grants are lost on restart and not " +
        "shared across instances. Inject a Redis / Durable Object / DB-backed " +
        "GrantStore via config.grantStore for production / multi-instance use.",
    );
  }

  // Holder binding (spec §11.8). Built once so all tools share one replay cache.
  // The verifier derives the subject key from the did:key DID directly, so its
  // fetchProvider is unused on the phase-1 path — a never-called stub keeps
  // enforcement active even where a runtime fetch is absent.
  const holderBindingMode = delegationConfig?.holderBinding ?? "off";
  const holderBindingVerifier =
    holderBindingMode === "off"
      ? undefined
      : new ProofVerifier({
          cryptoProvider,
          clockProvider: new SystemClockProvider(),
          nonceCacheProvider: nonceCache,
          fetchProvider:
            delegationConfig?.fetchProvider ??
            (typeof globalThis.fetch === "function"
              ? new RuntimeFetchProvider()
              : new NoopFetchProvider()),
        });

  // The constructed collaborators, threaded into each sub-factory.
  const deps: MiddlewareDeps = {
    identity,
    config,
    cryptoProvider,
    sessionManager,
    proofGenerator,
    auditLog,
    audit,
    grantStore,
    delegationConfig,
    holderBindingMode,
    holderBindingVerifier,
    emitLegacyProofKey,
  };

  // Session establishment + proof attachment (owns the activeSessionId fallback);
  // the `_kyaos` protocol surface routes to its handshake handler.
  const session = createSessionProof(deps);
  const protocol = createProtocol(deps, {
    handleHandshake: session.handleHandshake,
  });

  // Durable-grant resolution (the no-paste retry). Depends only on the immutable
  // deps above, so it lifts out cleanly with no shared session state.
  const { resolveExistingGrant, bindGrantOnSuccess } =
    createGrantResolution(deps);

  const { wrapWithDelegation } = createDelegationGate(deps, {
    attachOutcomeProof: session.attachOutcomeProof,
    resolveExistingGrant,
    bindGrantOnSuccess,
  });

  const { withPolicyGate } = createPolicyGate(deps, {
    attachOutcomeProof: session.attachOutcomeProof,
  });

  return {
    identity: config.identity,
    sessionManager,
    proofGenerator,
    kyaOsTool: protocol.kyaOsTool,
    handshakeTool: protocol.handshakeTool,
    handleKyaOs: protocol.handleKyaOs,
    handleHandshake: session.handleHandshake,
    wrapWithProof: session.wrapWithProof,
    wrapWithDelegation,
    withPolicyGate,
  };
}
