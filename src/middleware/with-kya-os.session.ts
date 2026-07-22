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
  LEGACY_PROOF_META_KEY,
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
  KyaOsCallContext,
} from "./with-kya-os.types.js";
import type { MiddlewareDeps, AttachOutcomeProof } from "./with-kya-os.deps.js";
import { sanitizeForMessage } from "./with-kya-os.helpers.js";
import type { McpAuditContext } from "../audit/adapters/mcp.js";

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
  } = deps;
  const auditedTerminalResponses = new WeakSet<object>();
  const auditMetaKey = 'org.kya-os/audit';

  type MutableToolResponse = Awaited<ReturnType<KyaOsToolHandler>>;

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

  const hasTerminalAuditMarker = (response: MutableToolResponse): boolean => {
    if (auditedTerminalResponses.has(response)) return true;
    const metadata = response._meta as Record<string, unknown> | undefined;
    const auditMetadata = metadata?.[auditMetaKey];
    return typeof auditMetadata === 'object' && auditMetadata !== null &&
      (auditMetadata as Record<string, unknown>).terminal === true;
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

  async function ensureSession(): Promise<string | undefined> {
    if (activeSessionId) {
      const existing = await sessionManager.getSession(activeSessionId);
      if (existing) {
        if (sessionManager.getStats().activeSessions <= 1) {
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
    return async (
      args: Record<string, unknown>,
      sessionId?: string,
      context?: KyaOsCallContext,
    ) => {
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
      let result: Awaited<ReturnType<KyaOsToolHandler>>;
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
        const response: ToolResponse = { data: result.content };

        const proof = await proofGenerator.generateProof(
          request,
          response,
          session,
          { scopeId: context?.scopeId },
        );

        // Attach proof under the namespaced _meta key (rendered by MCP
        // Inspector, invisible to LLMs), plus the legacy bare key when enabled.
        // Other _meta keys may coexist (SEP-414).
        result._meta = withProofMeta({}, proof);

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
  }

  const attachOutcomeProof: AttachOutcomeProof = async (
    response,
    toolName,
    args,
    sessionId,
    reason,
    outcome = "denied",
    paramsOverride,
    responseData,
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
      const proofResponse: ToolResponse | undefined =
        responseData !== undefined ? { data: responseData } : undefined;
      const proof = await proofGenerator.generateProof(request, proofResponse, session, {
        outcome,
        reason: sanitizeForMessage(reason),
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
          markAuditDegraded(
            response,
            'Required proof audit delivery failed for authorization outcome',
            false,
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

  return { handleHandshake, ensureSession, wrapWithProof, attachOutcomeProof };
}
