/**
 * Audit Log Provider
 *
 * Platform-agnostic seam for retaining KYA-OS audit records and events.
 *
 * The protocol attaches a detached proof to each tool response; an
 * `AuditLogProvider` is the pluggable sink an operator supplies to *persist*
 * those records as an audit trail. The package ships in-memory and no-op
 * defaults — durable backends (Postgres, object storage, append-only log)
 * are operator-provided, keeping the package storage-agnostic exactly like
 * `CryptoProvider` / `NonceCacheProvider`. Audit records are intended for a
 * durable, append-only store; see `SPEC.md` §12.4 (Proof Retention) for guidance.
 */

import type {
  AuditContext,
  AuditEventContext,
  AuditRecord,
} from "../types/protocol.js";

/**
 * Build a frozen `audit.v1` record from audit context metadata.
 *
 * Privacy: only the DID/key id, session id, audience, scope, request/response
 * hashes, and verification result are captured — never private keys, nonces,
 * or raw request/response payloads.
 */
export function buildAuditRecord(context: AuditContext): AuditRecord {
  return {
    version: "audit.v1",
    ts: Date.now(),
    session: context.session.sessionId,
    audience: context.session.audience,
    did: context.identity.did,
    kid: context.identity.kid,
    reqHash: context.requestHash,
    resHash: context.responseHash,
    verified: context.verified,
    scope: context.scopeId ?? "-",
  };
}

/**
 * Pluggable sink for KYA-OS audit records and events.
 *
 * Implementations persist to whatever store a deployment uses. The package
 * ships {@link MemoryAuditLogProvider} (dev/test) and {@link NoopAuditLogProvider}
 * (the default); production deployments supply a durable, append-only impl.
 */
export abstract class AuditLogProvider {
  /**
   * Persist one audit record per session (deduplicated by `sessionId`).
   * Called after a verified tool call; the context is mapped to a frozen
   * `audit.v1` record via {@link buildAuditRecord}.
   */
  abstract logAuditRecord(context: AuditContext): Promise<void>;

  /**
   * Persist an event without session deduplication (e.g. consent events),
   * allowing multiple events per session.
   */
  abstract logEvent(context: AuditEventContext): Promise<void>;
}

/**
 * In-memory {@link AuditLogProvider} for development and testing. Audit records
 * are deduplicated per session; events are not. Inspect via `records`/`events`.
 */
export class MemoryAuditLogProvider extends AuditLogProvider {
  readonly records: AuditRecord[] = [];
  readonly events: AuditEventContext[] = [];
  private readonly loggedSessions = new Set<string>();

  async logAuditRecord(context: AuditContext): Promise<void> {
    const sessionId = context.session.sessionId;
    if (this.loggedSessions.has(sessionId)) return;
    this.loggedSessions.add(sessionId);
    this.records.push(buildAuditRecord(context));
  }

  async logEvent(context: AuditEventContext): Promise<void> {
    this.events.push(context);
  }
}

/**
 * No-op {@link AuditLogProvider}. The default when no audit sink is configured,
 * so the middleware can always invoke the provider without null checks.
 */
export class NoopAuditLogProvider extends AuditLogProvider {
  async logAuditRecord(_context: AuditContext): Promise<void> {
    // intentionally empty
  }

  async logEvent(_context: AuditEventContext): Promise<void> {
    // intentionally empty
  }
}
