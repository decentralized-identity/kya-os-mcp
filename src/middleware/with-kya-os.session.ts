/**
 * KYA-OS Middleware — session establishment + proof attachment.
 *
 * Owns the single-process `activeSessionId` fallback (all its readers/writers
 * live here, so the borrowing semantics are preserved exactly) and the two proof
 * paths: `wrapWithProof` (success responses) and `attachOutcomeProof` (denied /
 * step-up / needs-authorization outcomes). Extracted from `./with-kya-os.ts`.
 *
 * Neither path signs in the handler. The MCP SDK changes a result after the
 * handler returns: SDK 2 adds `resultType` on the 2026-07-28 revision, which
 * the envelope profile covers; both SDKs fill in a missing `content`, and SDK
 * 2 appends a text item to `content` when `structuredContent` is not an
 * object, which the body profile covers. Both paths therefore leave the proof
 * to the outer layer, the withKyaOs transport, which makes it over the result
 * it sends, under either profile.
 */

import {
  KYA_OS_PROOF_META_KEY,
  LEGACY_NAMESPACED_PROOF_META_KEY,
  LEGACY_PROOF_META_KEY,
  PRECOMPUTED_REQUEST_HASH,
  RESPONSE_PROOF_PROFILE_ENVELOPE,
  type InternalProofOptions,
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
import type { DetachedProof, SessionContext } from "../types/protocol.js";
import type {
  KyaOsAuthorizationOutcome,
  KyaOsToolHandler,
  KyaOsToolResult,
  KyaOsCallContext,
} from "./with-kya-os.types.js";
import type { MiddlewareDeps, AttachOutcomeProof, RequireProofLayer } from "./with-kya-os.deps.js";
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
 * The private `_meta` member that names the proof a wrapper left for the
 * transport to make: a one-time id. What the proof
 * claims stays in the middleware, keyed by that id, so code that can write a
 * result cannot choose the claims. The transport redeems the id only on a
 * result that also carries the middleware's stamp, and strips it as it strips
 * the stamp. A string, so a copy of the result carries it too.
 */
export const PENDING_PROOF_META_KEY = 'org.kya-os/pending-proof';

/**
 * How long a proof left for the transport waits to be sent. A result that the
 * SDK never sends (a cancelled call, or one the SDK replaced) is closed in the
 * audit trail after this, with `PROOF_NOT_SENT`.
 */
const PENDING_PROOF_TTL_MS = 5 * 60_000;

/** How many proofs may wait at once; past this, the oldest is closed as not sent. */
const PENDING_PROOF_LIMIT = 10_000;

/**
 * Roughly how much the waiting proofs may hold, in UTF-16 code units of their
 * JSON. An entry holds a request hash, never the arguments, but its audit
 * context can carry strings a client influenced; past this, the oldest are
 * closed as not sent.
 */
const PENDING_PROOF_BYTE_BUDGET = 16 * 1024 * 1024;

/** The members only the middleware sets on a result for itself, never sent. */
const privateMetaKeys: readonly string[] = [LIFECYCLE_STAMP_META_KEY, PENDING_PROOF_META_KEY];

/** The `_meta` members a response proof is placed under. */
const proofMetaKeys: readonly string[] = [
  KYA_OS_PROOF_META_KEY,
  LEGACY_NAMESPACED_PROOF_META_KEY,
  LEGACY_PROOF_META_KEY,
];

/**
 * `_meta` members only the middleware itself may set: proofs, a proof error,
 * the audit marker and its private members. A tool result carrying them that
 * the middleware did not produce (content relayed from an upstream server, or
 * set by the handler) cannot be told apart from a forgery.
 */
const outcomeMetaKeys: readonly string[] = [
  ...proofMetaKeys,
  'proofError',
  auditMetaKey,
  ...privateMetaKeys,
];

type ToolResult = KyaOsToolResult;

/**
 * A response proof for a call the middleware let run. It holds the hash of
 * the request, computed when the call was recorded, never the arguments
 * themselves: later changes to them cannot reach what is signed, and a
 * waiting proof costs little however large they were.
 */
interface PendingAllowedProof {
  kind: 'allowed';
  toolName: string;
  requestHash: string;
  /** Re-read when the proof is made; the proof's audience comes from it. */
  sessionId: string;
  scopeId?: string;
  context?: McpAuditContext;
}

/** A response proof recording an authorization outcome (SPEC §7.2); as above, by request hash. */
interface PendingOutcomeProof {
  kind: 'outcome';
  toolName: string;
  requestHash: string;
  /** Re-read when the proof is made; the proof's audience comes from it. */
  sessionId: string;
  outcome: KyaOsAuthorizationOutcome;
  /** Already sanitized, so bounded. */
  reason: string;
  /** Whether the outcome's terminal audit events were delivered. */
  terminalAuditDelivered: boolean;
}

/** What a wrapper's proof claims, wherever it is made. */
type PendingProof = PendingAllowedProof | PendingOutcomeProof;

/** `proofError` on a result whose proof was left to the transport and could not be made. */
const UNPROVEN_PROOF_ERROR = "Proof generation failed — response is unproven";

/** Options that sign over `requestHash` instead of a request the caller still holds. */
function signedOver(requestHash: string, options: InternalProofOptions): InternalProofOptions {
  return { ...options, [PRECOMPUTED_REQUEST_HASH]: requestHash };
}

/** The request a proof names when its hash was computed earlier: the hash is what is signed. */
const hashedRequest = (toolName: string): ToolRequest => ({ method: toolName });

/**
 * Thrown by a wrapper, on entry, while no KYA-OS transport is open for this
 * middleware.
 */
const PROOF_NEEDS_TRANSPORT =
  '[kya-os] A response proof is made where the KYA-OS transport sends the result, ' +
  'after the MCP SDK has finished it, and no KYA-OS transport is open. Connect the ' +
  'server with withKyaOs() (with proofAllTools left on; excludeTools leaves an ' +
  'unwrapped tool unproven), or wrap the transport you connect with ' +
  'createKyaOsTransport().';

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

/** Remove the middleware's private members, which must never leave the process. */
export function withoutPrivateMeta<T extends ToolResult>(result: T): T {
  return withoutMetaKeys(result, privateMetaKeys);
}

/** What the outer layer (the withKyaOs transport) does with a middleware's results. */
export interface OuterProofLayer {
  /**
   * Count one more open transport, until the returned function is called.
   * The wrappers refuse to run while none is open.
   * Calling the returned function again does nothing.
   */
  open(): () => void;
  /** Whether the middleware's wrappers returned `result`: it carries their stamp. */
  owns(result: ToolResult): boolean;
  /**
   * `result` as it may leave the process: without the private members, and,
   * when a wrapper left its proof to the transport, carrying that proof, made
   * over `result` as it is now. Never throws: a proof that cannot be made is
   * reported on the result, as one that fails in a wrapper is. A pending
   * proof is redeemed once.
   */
  send(result: ToolResult): Promise<ToolResult>;
}

/**
 * Each middleware's hook for an outer auto-proof layer, keyed by its
 * `wrapWithProof` so the transport can reach it from whatever
 * `KyaOsMiddleware` it is handed without widening the public interface; a
 * custom implementation simply has no entry.
 */
const outerProofLayerHooks = new WeakMap<object, () => OuterProofLayer>();

/**
 * Tell the middleware behind `wrapWithProof` that an outer layer (the withKyaOs
 * transport) reads its results. From then on its wrappers stamp what they
 * return with the middleware's token and leave their proofs to the layer.
 * Returns the layer's view of those results, or
 * undefined for a middleware this module did not create, whose results are
 * then never treated as its own.
 */
export function attachOuterProofLayer(wrapWithProof: object): OuterProofLayer | undefined {
  return outerProofLayerHooks.get(wrapWithProof)?.();
}

/**
 * The fallback session for a call that threaded none, or why there is none:
 * `ambiguous` when several sessions are live and the middleware refuses to
 * pick one, which might be another client's.
 */
export type FallbackSession =
  | { sessionId: string }
  | { sessionId: undefined; ambiguous: boolean };

/** `proofError` on an allow result the fallback could not attribute. */
const AMBIGUOUS_SESSION_PROOF_ERROR =
  "Proof session is ambiguous (several live sessions, none threaded) — response is unproven";

export interface SessionProof {
  /** Establish a session from a handshake and cache it as the fallback. */
  handleHandshake(args: Record<string, unknown>): Promise<{
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  }>;
  /**
   * Resolve the single-process fallback session for a call that threaded none —
   * or auto-create one when `config.autoSession` is set. Returns no session
   * (skip the proof) when there is none, or, marked `ambiguous`, when
   * attribution would be ambiguous (multiple live sessions).
   */
  ensureSession(): Promise<FallbackSession>;
  /** Wrap a tool handler to attach a holder-of-key proof to success responses. */
  wrapWithProof<T extends Record<string, unknown> = Record<string, unknown>>(
    toolName: string,
    handler: KyaOsToolHandler<T>,
  ): KyaOsToolHandler;
  /** Attach a signed proof recording an authorization outcome to a response. */
  attachOutcomeProof: AttachOutcomeProof;
  /** Refuse a wrapped call whose proof could not be made where it is sent. */
  requireProofLayer: RequireProofLayer;
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
  // KYA-OS transports open for this middleware. The wrappers refuse to run
  // while there are none.
  let openTransports = 0;
  // Proofs left for the transport, by one-time id, each with the timer that
  // closes it as not sent. The claims never leave the middleware.
  const pendingProofs = new Map<string, {
    pending: PendingProof;
    timer: ReturnType<typeof setTimeout>;
    size: number;
  }>();
  let pendingProofBytes = 0;

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

  /**
   * A proof can only be made where the result is sent, so a wrapper with no
   * open KYA-OS transport to send it refuses before it does anything, rather
   * than send a result it cannot prove.
   */
  const requireProofLayer: RequireProofLayer = (): void => {
    if (openTransports === 0) {
      throw new Error(PROOF_NEEDS_TRANSPORT);
    }
  };

  /** Remove and return the proof waiting under `id`, if one is. */
  const takePendingProof = (id: string): PendingProof | undefined => {
    const entry = pendingProofs.get(id);
    if (entry === undefined) return undefined;
    pendingProofs.delete(id);
    pendingProofBytes -= entry.size;
    clearTimeout(entry.timer);
    return entry.pending;
  };

  /**
   * Close, in the audit trail, a proof that was never sent: the SDK dropped
   * its result (a cancelled call, or one the SDK replaced), or no transport
   * is left to send it. Both record the proof rejected with `PROOF_NOT_SENT`.
   * An allowed call, whose result the client never saw, then records the
   * call failed with `RESULT_NOT_SENT`, never completed. An outcome's terminal
   * events were recorded in the handler.
   */
  const closeUnsentProof = async (id: string): Promise<void> => {
    const pending = takePendingProof(id);
    if (pending !== undefined) await closeTaken(pending);
  };

  async function closeTaken(pending: PendingProof): Promise<void> {
    if (pending.kind === 'outcome') {
      if (pending.terminalAuditDelivered) {
        await emitAudit(
          'Failed to record unsent outcome proof',
          () => audit?.proof('rejected', { outcome: 'failed', verificationCode: 'PROOF_NOT_SENT' }),
          pending.toolName,
        );
      }
      return;
    }
    const { toolName, context } = pending;
    const proofAuditDelivered = await emitAudit(
      'Failed to record unsent proof',
      () => audit?.proof('rejected', { outcome: 'failed', verificationCode: 'PROOF_NOT_SENT', context }),
      toolName,
    );
    if (proofAuditDelivered) {
      await emitAudit(
        'Failed to record unsent tool outcome',
        () => audit?.tool('failed', { toolName, outcome: 'failed', reasonCode: 'RESULT_NOT_SENT', context }),
        toolName,
      );
    }
  }

  /** Close every waiting proof as not sent: no KYA-OS transport is left to send it. */
  const closeAllUnsentProofs = (): void => {
    for (const id of [...pendingProofs.keys()]) void closeUnsentProof(id);
  };

  /**
   * Leave `pending` for the outer layer to prove over the result it sends:
   * the MCP SDK changes members after the handler returns, so a proof made
   * here would not cover what the client receives.
   * The result carries only a one-time id; the claims stay here, by request
   * hash. Past the count or the size budget, the oldest waiting proofs are
   * closed as not sent.
   */
  const leaveToOuterLayer = (
    response: MutableToolResponse,
    pending: PendingProof,
  ): MutableToolResponse => {
    const size = JSON.stringify(pending).length;
    while (
      pendingProofs.size > 0 &&
      (pendingProofs.size >= PENDING_PROOF_LIMIT || pendingProofBytes + size > PENDING_PROOF_BYTE_BUDGET)
    ) {
      const oldest = pendingProofs.keys().next().value as string;
      // Taken now, so the loop sees it gone; recorded in the background.
      const evicted = takePendingProof(oldest);
      if (evicted !== undefined) void closeTaken(evicted);
    }
    const id = base64urlEncodeFromBytes(globalThis.crypto.getRandomValues(new Uint8Array(16)));
    const timer = setTimeout(() => void closeUnsentProof(id), PENDING_PROOF_TTL_MS);
    // Do not hold a process open for an audit close-out.
    (timer as { unref?: () => void }).unref?.();
    pendingProofs.set(id, { pending, timer, size });
    pendingProofBytes += size;
    response._meta = {
      ...((response._meta as Record<string, unknown> | undefined) ?? {}),
      [PENDING_PROOF_META_KEY]: id,
    };
    return response;
  };

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

  async function ensureSession(): Promise<FallbackSession> {
    if (activeSessionId) {
      const existing = await sessionManager.getSession(activeSessionId);
      if (existing) {
        if ((await liveSessionCount()) <= 1) {
          return { sessionId: activeSessionId };
        }
        // Ambiguous: more than one session and none threaded — do NOT borrow.
        logger.warn(
          "[kya-os] Multiple sessions active and no sessionId threaded; skipping " +
            "proof attribution to avoid signing with another client's session. " +
            "Thread the sessionId (the auto-proof path is single-session only).",
        );
        return { sessionId: undefined, ambiguous: true };
      }
    }

    if (!config.autoSession) return { sessionId: undefined, ambiguous: false };

    autoSessionInFlight ??= createAutoSession().finally(() => {
      autoSessionInFlight = undefined;
    });
    const sessionId = await autoSessionInFlight;
    return sessionId === undefined
      ? { sessionId: undefined, ambiguous: false }
      : { sessionId };
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
      // `== null`, as `??` below: a plain-JS caller may thread null.
      const fallback = sessionId == null ? await ensureSession() : undefined;
      const resolvedSessionId = sessionId ?? fallback?.sessionId;
      if (!resolvedSessionId) {
        // Refusing to borrow another client's session must not look like a
        // server that never proves: the result says it is unproven, as it
        // does when proof generation fails.
        if (fallback !== undefined && fallback.sessionId === undefined && fallback.ambiguous) {
          result._meta = { ...handlerMeta(result), proofError: AMBIGUOUS_SESSION_PROOF_ERROR };
        }
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

      const callAudit = auditContext(context);
      // The request is hashed now, as the wrapper saw it; the arguments are
      // not kept. Arguments that cannot be hashed fail the proof here.
      let requestHash: string;
      try {
        requestHash = await proofGenerator.hashRequest({ method: toolName, params: args });
      } catch (error) {
        return allowedProofFailed(result, toolName, callAudit, error);
      }
      const pending: PendingAllowedProof = {
        kind: 'allowed',
        toolName,
        requestHash,
        sessionId: session.sessionId,
        ...(context?.scopeId === undefined ? {} : { scopeId: context.scopeId }),
        ...(callAudit === undefined ? {} : { context: callAudit }),
      };
      return leaveToOuterLayer(result, pending);
    };
    return async (
      args: Record<string, unknown>,
      sessionId?: string,
      context?: KyaOsCallContext,
    ) => {
      requireProofLayer();
      return stampLifecycle(await run(args, sessionId, context));
    };
  }

  /**
   * Sign an allowed call's result, record the proof and the call's
   * completion, and hand the call to the audit sink. Run by the outer layer,
   * over the result it sends.
   */
  async function proveAllowedCall(
    result: MutableToolResponse,
    pending: PendingAllowedProof,
    session: SessionContext,
  ): Promise<MutableToolResponse> {
    const { toolName, requestHash, scopeId, context } = pending;
    try {
      // The envelope profile binds the FULL result envelope (hashing strips the top-level
      // `_meta`, where the proof itself is attached below); the body profile binds the
      // content array only — the original wire contract.
      const response: ToolResponse = {
        data: bindsEnvelope ? result : result.content,
      };

      const proof = await proofGenerator.generateProof(
        hashedRequest(toolName),
        response,
        session,
        signedOver(requestHash, { scopeId, profile: responseProofProfile }),
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
          context,
        }),
        toolName,
      );
      const terminalAuditDelivered = proofAuditDelivered && await emitAudit(
        'Required completed-tool audit delivery failed',
        () => audit?.tool('completed', {
          toolName,
          outcome: 'succeeded',
          context,
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
      return allowedProofFailed(result, toolName, context, error);
    }

    return result;
  }

  /**
   * An allowed call whose proof could not be made: the result goes out with
   * `proofError`, and the audit trail records the rejection.
   */
  async function allowedProofFailed(
    result: MutableToolResponse,
    toolName: string,
    context: McpAuditContext | undefined,
    error: unknown,
  ): Promise<MutableToolResponse> {
    logger.error("[kya-os] Proof generation failed", {
      tool: toolName,
      error: error instanceof Error ? error.message : String(error),
    });
    result._meta = {
      ...handlerMeta(result),
      proofError: UNPROVEN_PROOF_ERROR,
    };
    const rejectionAuditDelivered = await emitAudit(
      'Failed to record proof-generation rejection',
      () => audit?.proof('rejected', {
        outcome: 'failed',
        verificationCode: 'PROOF_GENERATION_FAILED',
        context,
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
    return result;
  }

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
    let session: SessionContext | null | undefined;
    try {
      const resolvedSessionId = sessionId ?? (await ensureSession()).sessionId;
      session = resolvedSessionId ? await sessionManager.getSession(resolvedSessionId) : undefined;
    } catch (error) {
      await outcomeProofFailed(toolName, error, terminalAuditDelivered);
      return response;
    }
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

    // Hashed now, as with an allowed call; the arguments are not kept.
    let requestHash: string;
    try {
      requestHash = await proofGenerator.hashRequest({ method: toolName, params: cleanArgs });
    } catch (error) {
      await outcomeProofFailed(toolName, error, terminalAuditDelivered);
      return markUnproven(response);
    }
    const pending: PendingOutcomeProof = {
      kind: 'outcome',
      toolName,
      requestHash,
      sessionId: session.sessionId,
      outcome,
      reason: sanitizeForMessage(reason),
      terminalAuditDelivered,
    };
    return leaveToOuterLayer(response, pending);
  };

  /**
   * Sign an authorization outcome and record the proof. Run by the outer
   * layer, over the result it sends; a proof that fails is reported on the
   * result, as an allowed call's is.
   */
  async function proveAuthorizationOutcome(
    response: MutableToolResponse,
    pending: PendingOutcomeProof,
    session: SessionContext,
  ): Promise<MutableToolResponse> {
    const { toolName, requestHash, outcome, reason, terminalAuditDelivered } = pending;
    try {
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
      const proof = await proofGenerator.generateProof(hashedRequest(toolName), proofResponse, session, signedOver(requestHash, {
        outcome,
        reason: sanitizeForMessage(reason),
        profile: responseProofProfile,
      }));
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
      await outcomeProofFailed(toolName, error, terminalAuditDelivered);
      markUnproven(response);
    }
    return response;
  }

  async function outcomeProofFailed(
    toolName: string,
    error: unknown,
    terminalAuditDelivered: boolean,
  ): Promise<void> {
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

  // Outcome results are stamped like wrapper results, so the outer layer
  // passes a signed denial or challenge through instead of re-proving it.
  const attachOutcomeProof: AttachOutcomeProof = async (...outcome) =>
    stampLifecycle(await outcomeProof(...outcome));

  /** Say on `response` that it goes out without the proof it was meant to carry. */
  const markUnproven = (response: MutableToolResponse): MutableToolResponse => {
    response._meta = {
      ...((withoutMetaKeys(response, proofMetaKeys)._meta as Record<string, unknown> | undefined) ?? {}),
      proofError: UNPROVEN_PROOF_ERROR,
    };
    return response;
  };

  /**
   * A proof left for the transport whose session is gone by the time it is
   * sent: the result goes out unproven and says so, and the audit trail
   * records why, closing an allowed call as a wrapper does when its session
   * is missing.
   */
  async function sessionGoneAtSend(
    response: MutableToolResponse,
    pending: PendingProof,
  ): Promise<MutableToolResponse> {
    markUnproven(response);
    const { toolName } = pending;
    const context = pending.kind === 'allowed' ? pending.context : undefined;
    if (pending.kind === 'outcome' && !pending.terminalAuditDelivered) return response;
    const proofAuditDelivered = await emitAudit(
      'Failed to record missing proof session',
      () => audit?.proof('rejected', { outcome: 'failed', verificationCode: 'PROOF_SESSION_NOT_FOUND', context }),
      toolName,
    );
    if (pending.kind === 'allowed' && proofAuditDelivered) {
      await emitAudit(
        'Failed to record completed tool outcome',
        () => audit?.tool('completed', { toolName, outcome: 'succeeded', context }),
        toolName,
      );
    }
    return response;
  }

  /**
   * The outer layer's last step before a result leaves the process: a result
   * whose wrapper left its proof here gets it now, over the members the MCP
   * SDK has set since the handler returned, and every result loses the
   * private members. Only a result with this middleware's stamp redeems a
   * pending id, each id once; the claims and the session are the
   * middleware's own, never the result's. A stamped result naming no waiting
   * proof goes out unproven and says so.
   */
  async function sendResult(result: ToolResult): Promise<ToolResult> {
    const id = hasOwnStamp(result)
      ? (result._meta as Record<string, unknown>)[PENDING_PROOF_META_KEY]
      : undefined;
    const sent = withoutPrivateMeta(result);
    if (id === undefined) return sent;
    const pending = typeof id === 'string' ? takePendingProof(id) : undefined;
    if (pending === undefined) return markUnproven(sent);
    let session: SessionContext | null;
    try {
      session = await sessionManager.getSession(pending.sessionId);
    } catch (error) {
      logger.error("[kya-os] Proof session lookup failed", {
        tool: pending.toolName,
        error: error instanceof Error ? error.message : String(error),
      });
      session = null;
    }
    if (!session) return sessionGoneAtSend(sent, pending);
    return pending.kind === 'allowed'
      ? proveAllowedCall(sent, pending, session)
      : proveAuthorizationOutcome(sent, pending, session);
  }

  outerProofLayerHooks.set(wrapWithProof, () => {
    lifecycleStamp ??= base64urlEncodeFromBytes(
      globalThis.crypto.getRandomValues(new Uint8Array(16)),
    );
    const open = (): (() => void) => {
      openTransports += 1;
      let released = false;
      return () => {
        if (released) return;
        released = true;
        openTransports -= 1;
        // No transport is left to send what is waiting.
        if (openTransports === 0) closeAllUnsentProofs();
      };
    };
    return { open, owns: hasOwnStamp, send: sendResult };
  });

  return { handleHandshake, ensureSession, wrapWithProof, attachOutcomeProof, requireProofLayer };
}
