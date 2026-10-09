/**
 * KYA-OS Middleware — session establishment + proof attachment.
 *
 * Owns the single-process `activeSessionId` fallback (all its readers/writers
 * live here, so the borrowing semantics are preserved exactly) and the two proof
 * paths: `wrapWithProof` (success responses) and `attachOutcomeProof` (denied /
 * step-up / needs-authorization outcomes). Extracted from `./with-kya-os.ts`.
 */

import {
  KYA_OS_PROOF_META_KEY,
  LEGACY_NAMESPACED_PROOF_META_KEY,
  LEGACY_PROOF_META_KEY,
  RESPONSE_PROOF_PROFILE_ENVELOPE,
  type ToolRequest,
  type ToolResponse,
} from "../proof/generator.js";
import {
  validateHandshakeFormat,
  type HandshakeResult,
} from "../session/manager.js";
import { base64urlEncodeFromBytes } from "../utils/base64.js";
import { logger } from "../logging/index.js";
import { KYA_OS_ERROR_CODES } from "../errors.js";
import type { DetachedProof } from "../types/protocol.js";
import type {
  KyaOsToolHandler,
  KyaOsToolResult,
  KyaOsCallContext,
} from "./with-kya-os.types.js";
import type { MiddlewareDeps, AttachOutcomeProof } from "./with-kya-os.deps.js";
import { sanitizeForMessage } from "./with-kya-os.helpers.js";
import type { McpAuditContext } from "../audit/adapters/mcp.js";

/** The `_meta` member carrying this middleware's audit-lifecycle marker. */
const auditMetaKey = 'org.kya-os/audit';

/**
 * The private `_meta` member a middleware's wrappers stamp their results with
 * while an outer layer (the withKyaOs transport) reads them. It holds a random
 * per-middleware token, and the transport strips it before a message leaves,
 * so it never reaches the wire. It lives in `_meta` because the MCP SDK
 * re-creates the result object when it validates it, and `_meta` survives
 * that.
 */
export const LIFECYCLE_STAMP_META_KEY = 'org.kya-os/lifecycle-stamp';

/**
 * `_meta` members only the middleware itself may set: proofs, a proof error,
 * the audit marker and the lifecycle stamp. A tool result carrying them that
 * the middleware did not produce (content relayed from an upstream server, or
 * set by the handler) cannot be told apart from a forgery.
 */
const outcomeMetaKeys: readonly string[] = [
  KYA_OS_PROOF_META_KEY,
  LEGACY_NAMESPACED_PROOF_META_KEY,
  LEGACY_PROOF_META_KEY,
  'proofError',
  auditMetaKey,
  LIFECYCLE_STAMP_META_KEY,
];

type ToolResult = KyaOsToolResult;

/** `result` without the `_meta` members in `keys`, dropping `_meta` if nothing else is left. */
function withoutMetaKeys<T extends ToolResult>(result: T, keys: readonly string[]): T {
  const metadata = result._meta as Record<string, unknown> | undefined;
  if (metadata === undefined || !keys.some((key) => Object.hasOwn(metadata, key))) {
    return result;
  }
  const kept = Object.fromEntries(
    Object.entries(metadata).filter(([key]) => !keys.includes(key)),
  );
  const copy: Record<string, unknown> = { ...result };
  if (Object.keys(kept).length > 0) copy._meta = kept;
  else delete copy._meta;
  return copy as T;
}

/**
 * Remove the `_meta` members only the middleware may set (proofs, proof error,
 * audit marker, lifecycle stamp) from a result it did not produce, keeping
 * every other member (traceparent and the like). Returns a copy when anything
 * is removed.
 */
export function withoutOutcomeMeta<T extends ToolResult>(result: T): T {
  return withoutMetaKeys(result, outcomeMetaKeys);
}

/** Remove the lifecycle stamp, which must never leave the process. */
export function withoutLifecycleStamp<T extends ToolResult>(result: T): T {
  return withoutMetaKeys(result, [LIFECYCLE_STAMP_META_KEY]);
}

/**
 * Each middleware's hook for an outer auto-proof layer, keyed by its
 * `wrapWithProof` so the transport can reach it from whatever
 * `KyaOsMiddleware` it is handed without widening the public interface; a
 * custom implementation simply has no entry.
 */
const outerProofLayerHooks = new WeakMap<object, () => (result: ToolResult) => boolean>();

/**
 * Tell the middleware behind `wrapWithProof` that an outer layer (the withKyaOs
 * transport) reads its results. From then on its wrappers stamp what they
 * return with the middleware's token. Returns the check for that stamp, or
 * undefined for a middleware this module did not create, whose results are
 * then never treated as its own.
 */
export function attachOuterProofLayer(
  wrapWithProof: object,
): ((result: ToolResult) => boolean) | undefined {
  return outerProofLayerHooks.get(wrapWithProof)?.();
}

export interface SessionProof {
  /** Establish a session from a handshake and cache it as the fallback. */
  handleHandshake(args: Record<string, unknown>): Promise<{
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  }>;
  /**
   * Resolve the single-process fallback session for a call that threaded none —
   * or auto-create one when `config.autoSession` is set. Returns undefined (skip
   * the proof) when attribution would be ambiguous (multiple live sessions).
   */
  ensureSession(): Promise<string | undefined>;
  /** Wrap a tool handler to attach a holder-of-key proof to success responses. */
  wrapWithProof<T extends Record<string, unknown> = Record<string, unknown>>(
    toolName: string,
    handler: KyaOsToolHandler<T>,
  ): KyaOsToolHandler;
  /** Attach a signed proof recording an authorization outcome to a response. */
  attachOutcomeProof: AttachOutcomeProof;
}

export function createSessionProof(deps: MiddlewareDeps): SessionProof {
  const {
    identity,
    config,
    cryptoProvider,
    sessionManager,
    proofGenerator,
    auditLog,
    audit,
    emitLegacyProofKey,
    responseProofProfile,
  } = deps;
  const bindsEnvelope = responseProofProfile === RESPONSE_PROOF_PROFILE_ENVELOPE;
  const auditedTerminalResponses = new WeakSet<object>();
  // This middleware's lifecycle token, minted once an outer layer reads its
  // results. Only wrappers holding it can stamp a result as their own.
  let lifecycleStamp: string | undefined;

  const hasOwnStamp = (response: ToolResult): boolean =>
    lifecycleStamp !== undefined &&
    (response._meta as Record<string, unknown> | undefined)?.[LIFECYCLE_STAMP_META_KEY] === lifecycleStamp;

  type MutableToolResponse = ToolResult;

  const emitAudit = async (
    label: string,
    operation: () => Promise<void> | undefined,
    toolName?: string,
  ): Promise<boolean> => {
    try {
      await operation();
      return true;
    } catch (error) {
      logger.error(`[kya-os] ${label}`, {
        ...(toolName === undefined ? {} : { tool: toolName }),
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  };

  const markAuditDegraded = (
    response: MutableToolResponse,
    reason: string,
    stripSuccessProof: boolean,
  ): MutableToolResponse => {
    const metadata = {
      ...((response._meta as Record<string, unknown> | undefined) ?? {}),
    };
    if (stripSuccessProof) {
      delete metadata[KYA_OS_PROOF_META_KEY];
      delete metadata[LEGACY_PROOF_META_KEY];
    }
    metadata[auditMetaKey] = {
      ...(typeof metadata[auditMetaKey] === 'object' && metadata[auditMetaKey] !== null
        ? metadata[auditMetaKey] as Record<string, unknown>
        : {}),
      status: 'degraded',
      reason,
    };
    response._meta = metadata;
    response.isError = true;
    return response;
  };

  const auditUnavailableResponse = (reason: string): MutableToolResponse => ({
    content: [{
      type: 'text',
      text: JSON.stringify({
        success: false,
        error: { code: 'audit_delivery_failed', message: reason },
      }),
    }],
    isError: true,
    _meta: { [auditMetaKey]: { status: 'degraded', reason } },
  });

  // In-process trust boundary: handlers run inside the same process as this
  // middleware, so a handler can set the terminal marker on its own error
  // responses to take over terminal-outcome auditing. The marker is not a
  // defense against untrusted handler code; it only prevents double-auditing
  // by cooperating code paths.
  const hasTerminalAuditMarker = (response: MutableToolResponse): boolean => {
    if (auditedTerminalResponses.has(response)) return true;
    const metadata = response._meta as Record<string, unknown> | undefined;
    const auditMetadata = metadata?.[auditMetaKey];
    return typeof auditMetadata === 'object' && auditMetadata !== null &&
      (auditMetadata as Record<string, unknown>).terminal === true;
  };

  /**
   * The handler's `_meta` members a proof or proof error is merged into: every
   * member except the proofs, proof error, audit marker and stamp, which only
   * the middleware sets. A handler relaying an upstream result could
   * otherwise ship them next to this middleware's proof.
   */
  const handlerMeta = (response: MutableToolResponse): Record<string, unknown> =>
    (withoutOutcomeMeta(response)._meta as Record<string, unknown> | undefined) ?? {};

  /**
   * Stamp a result whose lifecycle a wrapper has run, so the outer layer
   * neither re-proves nor re-audits it. Without an outer layer there is no
   * token, nothing would strip the stamp, and the result is returned as it was.
   */
  const stampLifecycle = (response: MutableToolResponse): MutableToolResponse => {
    if (lifecycleStamp === undefined) return response;
    response._meta = {
      ...((response._meta as Record<string, unknown> | undefined) ?? {}),
      [LIFECYCLE_STAMP_META_KEY]: lifecycleStamp,
    };
    return response;
  };

  const auditContext = (
    context: KyaOsCallContext | undefined,
  ): McpAuditContext | undefined => context === undefined
    ? undefined
    : {
        ...(context.actor === undefined ? {} : { actor: context.actor }),
        ...(context.responsibleParty === undefined
          ? {}
          : { responsibleParty: context.responsibleParty }),
        ...(context.authorization === undefined
          ? {}
          : { authorization: context.authorization }),
        ...(context.correlationId === undefined
          ? {}
          : { correlationId: context.correlationId }),
        ...(context.causationId === undefined ? {} : { causationId: context.causationId }),
      };

  /**
   * Place a detached proof into a `_meta` object: always under the namespaced
   * key, and (when {@link emitLegacyProofKey}) mirrored under the legacy bare
   * key. The single place both emit paths build `_meta`, so they cannot drift.
   */
  const withProofMeta = (
    base: Record<string, unknown>,
    proof: DetachedProof,
  ): Record<string, unknown> => ({
    ...base,
    [KYA_OS_PROOF_META_KEY]: proof,
    ...(emitLegacyProofKey ? { [LEGACY_PROOF_META_KEY]: proof } : {}),
  });

  // Single-process fallback for the established (handshake or auto) session, used
  // ONLY when no sessionId was threaded into the wrapper — e.g. non-KYA-OS clients
  // (MCP Inspector) and the transport auto-proof path, which never thread one. The
  // PRIMARY resolver is the explicit `sessionId` parameter, so a KYA-OS-aware call
  // never depends on this fallback.
  let activeSessionId: string | undefined;

  async function handleHandshake(args: Record<string, unknown>): Promise<{
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  }> {
    if (!validateHandshakeFormat(args)) {
      await emitAudit(
        'Failed to record rejected session audit event',
        () => audit?.session('rejected', {
          succeeded: false,
          reasonCode: KYA_OS_ERROR_CODES.handshake_failed,
        }),
      );
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              success: false,
              error: {
                code: KYA_OS_ERROR_CODES.handshake_failed,
                message:
                  "Invalid handshake format: requires nonce (string), audience (string), and timestamp (positive integer)",
              },
            }),
          },
        ],
        isError: true,
      };
    }

    const result: HandshakeResult =
      await sessionManager.validateHandshake(args);

    const auditPhase = result.success
      ? 'established'
      : result.error?.code === KYA_OS_ERROR_CODES.nonce_replay
        ? 'replay_rejected'
        : 'rejected';
    const sessionAuditDelivered = await emitAudit(
      `Failed to record ${auditPhase} session audit event`,
      () => audit?.session(auditPhase, {
        succeeded: result.success,
        ...(result.error === undefined ? {} : { reasonCode: result.error.code }),
      }),
    );

    if (result.success && !sessionAuditDelivered) {
      const failed = auditUnavailableResponse(
        'Required session audit delivery failed after handshake validation',
      );
      return { content: failed.content, isError: true };
    }

    // Cache the established session as the single-process fallback for callers
    // that do not thread a sessionId (e.g. the transport auto-proof path).
    if (result.success && result.session) {
      activeSessionId = result.session.sessionId;
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: result.success,
            ...(result.session && {
              sessionId: result.session.sessionId,
              serverDid: identity.did,
              serverKid: identity.kid,
            }),
            ...(result.error && { error: result.error }),
          }),
        },
      ],
      ...(result.error && { isError: true }),
    };
  }

  // The store keeps an expired session until something deletes it, so its raw
  // size overcounts live sessions: one stale session would leave the fallback
  // ambiguous for good. A count above one triggers a sweep first, at most once
  // per interval so a genuinely multi-client deployment does not scan the
  // whole store on every unthreaded call.
  const sessionSweepIntervalMs = 60_000;
  let lastSessionSweepAt: number | undefined;

  async function liveSessionCount(): Promise<number> {
    const count = sessionManager.getStats().activeSessions;
    const now = Date.now();
    if (
      count <= 1 ||
      (lastSessionSweepAt !== undefined && now - lastSessionSweepAt < sessionSweepIntervalMs)
    ) {
      return count;
    }
    lastSessionSweepAt = now;
    try {
      await sessionManager.cleanup();
    } catch (error) {
      logger.error("[kya-os] Session sweep failed", {
        error: error instanceof Error ? error.message : String(error),
      });
      return count;
    }
    return sessionManager.getStats().activeSessions;
  }

  // Concurrent first calls share one in-flight auto session: one per caller
  // would leave several live sessions, and every later call ambiguous.
  let autoSessionInFlight: Promise<string | undefined> | undefined;

  async function ensureSession(): Promise<string | undefined> {
    if (activeSessionId) {
      const existing = await sessionManager.getSession(activeSessionId);
      if (existing) {
        if ((await liveSessionCount()) <= 1) {
          return activeSessionId;
        }
        // Ambiguous: more than one session and none threaded — do NOT borrow.
        logger.warn(
          "[kya-os] Multiple sessions active and no sessionId threaded; skipping " +
            "proof attribution to avoid signing with another client's session. " +
            "Thread the sessionId (the auto-proof path is single-session only).",
        );
        return undefined;
      }
    }

    if (!config.autoSession) return undefined;

    autoSessionInFlight ??= createAutoSession().finally(() => {
      autoSessionInFlight = undefined;
    });
    return autoSessionInFlight;
  }

  async function createAutoSession(): Promise<string | undefined> {
    // Generate a server-side session with cryptographically random nonce (SPEC.md §4)
    const nonceBytes = await cryptoProvider.randomBytes(16);
    const nonce = base64urlEncodeFromBytes(nonceBytes);
    const timestamp = Math.floor(Date.now() / 1000);

    const result = await sessionManager.validateHandshake({
      nonce,
      audience: identity.did,
      timestamp,
    });

    if (result.success && result.session) {
      activeSessionId = result.session.sessionId;
      return activeSessionId;
    }

    return undefined;
  }

  function wrapWithProof<T extends Record<string, unknown> = Record<string, unknown>>(
    toolName: string,
    handler: KyaOsToolHandler<T>,
  ): KyaOsToolHandler {
    const run = async (
      args: Record<string, unknown>,
      sessionId?: string,
      context?: KyaOsCallContext,
    ): Promise<MutableToolResponse> => {
      const intentDelivered = await emitAudit(
        'Required tool intent audit delivery failed',
        () => audit?.tool('started', {
          toolName,
          outcome: 'unknown',
          context: auditContext(context),
        }),
        toolName,
      );
      if (!intentDelivered) {
        return auditUnavailableResponse(
          'Required intent audit delivery failed before tool execution',
        );
      }
      let result: ToolResult;
      try {
        result = await handler(args as T, sessionId, context);
      } catch (error) {
        await emitAudit(
          'Failed to record thrown tool outcome; preserving original handler error',
          () => audit?.tool('failed', {
            toolName,
            outcome: 'failed',
            reasonCode: 'HANDLER_THROWN',
            context: auditContext(context),
          }),
          toolName,
        );
        throw error;
      }

      // An outcome the gates or proveOutcome already proved and audited (a
      // challenge need not be an error result): signing it again would replace
      // its outcome proof with one that records the call as allowed. Matched by
      // identity, so a relayed result's own markers never qualify.
      if (auditedTerminalResponses.has(result)) return result;

      if (result.isError) {
        if (!hasTerminalAuditMarker(result)) {
          const delivered = await emitAudit(
            'Failed to record error tool outcome',
            () => audit?.tool('failed', {
              toolName,
              outcome: 'failed',
              reasonCode: 'HANDLER_ERROR_RESULT',
              context: auditContext(context),
            }),
            toolName,
          );
          if (!delivered) {
            markAuditDegraded(
              result,
              'Required terminal audit delivery failed for an error response',
              false,
            );
          }
        }
        return result;
      }

      // Resolve session: explicit param → active session → auto-create
      const resolvedSessionId = sessionId ?? await ensureSession();
      if (!resolvedSessionId) {
        const proofAuditDelivered = await emitAudit(
          'Failed to record unavailable proof session',
          () => audit?.proof('rejected', {
            outcome: 'failed',
            verificationCode: 'PROOF_SESSION_UNAVAILABLE',
            context: auditContext(context),
          }),
          toolName,
        );
        const terminalAuditDelivered = proofAuditDelivered && await emitAudit(
          'Failed to record completed tool outcome',
          () => audit?.tool('completed', {
            toolName,
            outcome: 'succeeded',
            context: auditContext(context),
          }),
          toolName,
        );
        if (!terminalAuditDelivered) {
          return markAuditDegraded(
            result,
            'Required terminal audit delivery failed after tool completion',
            true,
          );
        }
        return result;
      }

      const session = await sessionManager.getSession(resolvedSessionId);
      if (!session) {
        const proofAuditDelivered = await emitAudit(
          'Failed to record missing proof session',
          () => audit?.proof('rejected', {
            outcome: 'failed',
            verificationCode: 'PROOF_SESSION_NOT_FOUND',
            context: auditContext(context),
          }),
          toolName,
        );
        const terminalAuditDelivered = proofAuditDelivered && await emitAudit(
          'Failed to record completed tool outcome',
          () => audit?.tool('completed', {
            toolName,
            outcome: 'succeeded',
            context: auditContext(context),
          }),
          toolName,
        );
        if (!terminalAuditDelivered) {
          return markAuditDegraded(
            result,
            'Required terminal audit delivery failed after tool completion',
            true,
          );
        }
        return result;
      }

      try {
        const request: ToolRequest = { method: toolName, params: args };
        // The envelope profile binds the FULL result envelope (hashing strips the top-level
        // `_meta`, where the proof itself is attached below); the body profile binds the
        // content array only — the original wire contract.
        const response: ToolResponse = {
          data: bindsEnvelope ? result : result.content,
        };

        const proof = await proofGenerator.generateProof(
          request,
          response,
          session,
          { scopeId: context?.scopeId, profile: responseProofProfile },
        );

        // Attach proof under the namespaced _meta key (rendered by MCP
        // Inspector, invisible to LLMs), plus the legacy bare key when enabled.
        // Keys the handler set (traceparent, related-task, ...) are kept: the
        // middleware does not own `_meta` (SPEC §7.6).
        result._meta = withProofMeta(handlerMeta(result), proof);

        const proofAuditDelivered = await emitAudit(
          'Required generated-proof audit delivery failed',
          () => audit?.proof('generated', {
            outcome: 'succeeded',
            context: auditContext(context),
          }),
          toolName,
        );
        const terminalAuditDelivered = proofAuditDelivered && await emitAudit(
          'Required completed-tool audit delivery failed',
          () => audit?.tool('completed', {
            toolName,
            outcome: 'succeeded',
            context: auditContext(context),
          }),
          toolName,
        );
        if (!terminalAuditDelivered) {
          return markAuditDegraded(
            result,
            'Required terminal audit delivery failed after tool completion',
            true,
          );
        }

        // Hand the verified call to the audit sink. A sink failure MUST NOT
        // break the tool response, so it is logged and swallowed.
        try {
          await auditLog.logAuditRecord({
            identity: { did: identity.did, kid: identity.kid },
            session: { sessionId: session.sessionId, audience: session.audience },
            requestHash: proof.meta.requestHash,
            responseHash: proof.meta.responseHash,
            verified: "yes",
            scopeId: proof.meta.scopeId,
          });
        } catch (auditError) {
          logger.error("[kya-os] Audit log failed", {
            tool: toolName,
            error:
              auditError instanceof Error
                ? auditError.message
                : String(auditError),
          });
        }
      } catch (error) {
        logger.error("[kya-os] Proof generation failed", {
          tool: toolName,
          error: error instanceof Error ? error.message : String(error),
        });
        result._meta = {
          ...handlerMeta(result),
          proofError: "Proof generation failed — response is unproven",
        };
        const rejectionAuditDelivered = await emitAudit(
          'Failed to record proof-generation rejection',
          () => audit?.proof('rejected', {
            outcome: 'failed',
            verificationCode: 'PROOF_GENERATION_FAILED',
            context: auditContext(context),
          }),
          toolName,
        );
        if (!rejectionAuditDelivered) {
          markAuditDegraded(
            result,
            'Required proof-failure audit delivery failed after tool completion',
            true,
          );
        }
      }

      return result;
    };
    return async (
      args: Record<string, unknown>,
      sessionId?: string,
      context?: KyaOsCallContext,
    ) => stampLifecycle(await run(args, sessionId, context));
  }
  outerProofLayerHooks.set(wrapWithProof, () => {
    lifecycleStamp ??= base64urlEncodeFromBytes(
      globalThis.crypto.getRandomValues(new Uint8Array(16)),
    );
    return hasOwnStamp;
  });

  const outcomeProof: AttachOutcomeProof = async (
    response,
    toolName,
    args,
    sessionId,
    reason,
    outcome = "denied",
    paramsOverride,
  ) => {
    const phase = outcome === 'denied' ? 'denied' : 'step_up_required';
    const reasonCode = outcome === 'needs_authorization'
      ? 'NEEDS_AUTHORIZATION'
      : outcome === 'step_up_required' ? 'STEP_UP_REQUIRED' : 'AUTHORIZATION_DENIED';
    const authorizationAuditDelivered = await emitAudit(
      'Failed to record authorization outcome',
      () => audit?.authorization(phase, {
        outcome: outcome === 'denied' ? 'denied' : 'challenged',
        reasonCode,
      }),
      toolName,
    );
    const terminalAuditDelivered = authorizationAuditDelivered && await emitAudit(
      'Failed to record terminal authorization tool outcome',
      () => audit?.tool(outcome === 'denied' ? 'denied' : 'challenged', {
        toolName,
        outcome: outcome === 'denied' ? 'denied' : 'challenged',
        reasonCode,
      }),
      toolName,
    );
    auditedTerminalResponses.add(response);
    response._meta = {
      ...((response._meta as Record<string, unknown> | undefined) ?? {}),
      [auditMetaKey]: {
        terminal: true,
        outcome,
        ...(!terminalAuditDelivered
          ? {
              status: 'degraded',
              reason: 'Required terminal audit delivery failed for authorization outcome',
            }
          : {}),
      },
    };
    try {
      const resolvedSessionId = sessionId ?? (await ensureSession());
      if (!resolvedSessionId) return response;
      const session = await sessionManager.getSession(resolvedSessionId);
      if (!session) return response;

      // Prefer the caller's already-stripped args so the signed requestHash
      // matches the needs_approval / resumeToken requestHash exactly.
      let cleanArgs: Record<string, unknown>;
      if (paramsOverride !== undefined) {
        cleanArgs = paramsOverride;
      } else {
        cleanArgs = {};
        for (const [k, v] of Object.entries(args)) {
          if (k !== "_kyaos_delegation") cleanArgs[k] = v;
        }
      }

      const request: ToolRequest = { method: toolName, params: cleanArgs };
      // A needs_authorization challenge has a body to bind; denial / step-up
      // proofs stay body-free under every profile (SPEC §7.4). WHAT gets bound
      // is profile-selected: the envelope profile binds the full response
      // envelope the client receives (hashing strips `_meta`, where the proof
      // lands below), the body profile the bare challenge content — the
      // original wire contract.
      const proofResponse: ToolResponse | undefined =
        outcome === "needs_authorization"
          ? { data: bindsEnvelope ? response : response.content }
          : undefined;
      const proof = await proofGenerator.generateProof(request, proofResponse, session, {
        outcome,
        reason: sanitizeForMessage(reason),
        profile: responseProofProfile,
      });
      response._meta = withProofMeta(
        (response._meta as Record<string, unknown> | undefined) ?? {},
        proof,
      );
      if (terminalAuditDelivered) {
        const proofAuditDelivered = await emitAudit(
          'Failed to record generated outcome proof',
          () => audit?.proof('generated', { outcome: 'succeeded' }),
          toolName,
        );
        if (!proofAuditDelivered) {
          // markAuditDegraded flips isError on the response. Under the body profile that
          // mutation is outside proof coverage, so the already-attached
          // challenge proof stays verifiable and is kept. Under the envelope profile the
          // envelope binding COVERS isError — keeping the proof would ship a
          // binding the client must reject as tampering — so the degraded
          // path strips it (mirroring wrapWithProof's degraded semantics):
          // a degraded envelope-profile challenge ships unproven, never falsely "MITM'd".
          markAuditDegraded(
            response,
            'Required proof audit delivery failed for authorization outcome',
            bindsEnvelope,
          );
        }
      }
    } catch (error) {
      logger.error("[kya-os] Outcome proof generation failed", {
        tool: toolName,
        error: error instanceof Error ? error.message : String(error),
      });
      if (terminalAuditDelivered) {
        await emitAudit(
          'Failed to record outcome-proof rejection',
          () => audit?.proof('rejected', {
            outcome: 'failed',
            verificationCode: 'OUTCOME_PROOF_GENERATION_FAILED',
          }),
          toolName,
        );
      }
    }
    return response;
  };

  // Outcome results are stamped like wrapper results, so the outer layer
  // passes a signed denial or challenge through instead of re-proving it.
  const attachOutcomeProof: AttachOutcomeProof = async (...outcome) =>
    stampLifecycle(await outcomeProof(...outcome));

  return { handleHandshake, ensureSession, wrapWithProof, attachOutcomeProof };
}
