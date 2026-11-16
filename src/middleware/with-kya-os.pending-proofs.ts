/**
 * KYA-OS Middleware - the proofs a middleware's wrappers leave for the
 * transport to make.
 *
 * A wrapper leaves what its proof claims here, under a one-time id, and the
 * transport redeems the id where it sends the result (see
 * `./with-kya-os.session.ts`). A proof that waits past its window, or past
 * the count or the size budget, is closed as not sent. What a proof no
 * longer waiting was about is remembered, bounded, so a result sent after it
 * closed can be recorded against its tool and call.
 */

import type { McpAuditContext } from "../audit/adapters/mcp.js";
import { base64urlEncodeFromBytes } from "../utils/base64.js";
import type { MessageText } from "../utils/message-text.js";
import type { KyaOsAuthorizationOutcome } from "./with-kya-os.types.js";

/**
 * How long a proof left for the transport waits to be sent, unless
 * `pendingProofTtlMs` says otherwise. A result that the SDK never sends (a
 * cancelled call, or one the SDK replaced) is closed in the audit trail after
 * this, with `PROOF_NOT_SENT`; one sent later goes out unproven, recorded as
 * `PROOF_EXPIRED`.
 */
const PENDING_PROOF_TTL_MS = 5 * 60_000;

/** The largest audit context, in UTF-16 code units of JSON, kept for a proof no longer waiting. */
const CLOSED_PROOF_CONTEXT_LIMIT = 16 * 1024;

/** Roughly how much the record of proofs no longer waiting may hold, in UTF-16 code units of JSON. */
const CLOSED_PROOF_BYTE_BUDGET = 4 * 1024 * 1024;

/** How many proofs may wait at once; past this, the oldest is closed as not sent. */
const PENDING_PROOF_LIMIT = 10_000;

/**
 * Roughly how much the waiting proofs may hold, in UTF-16 code units of their
 * JSON. An entry holds a request hash, never the arguments, but its audit
 * context can carry strings a client influenced; past this, the oldest are
 * closed as not sent.
 */
const PENDING_PROOF_BYTE_BUDGET = 16 * 1024 * 1024;

/**
 * A response proof for a call the middleware let run. It holds the hash of
 * the request, computed when the call was recorded, never the arguments
 * themselves: later changes to them cannot reach what is signed, and a
 * waiting proof costs little however large they were.
 */
export interface PendingAllowedProof {
  kind: 'allowed';
  toolName: string;
  requestHash: string;
  /** Re-read when the proof is made; the proof's audience comes from it. */
  sessionId: string;
  scopeId?: string;
  context?: McpAuditContext;
}

/** A response proof recording an authorization outcome (SPEC §7.2); as above, by request hash. */
export interface PendingOutcomeProof {
  kind: 'outcome';
  toolName: string;
  requestHash: string;
  /** Re-read when the proof is made; the proof's audience comes from it. */
  sessionId: string;
  outcome: KyaOsAuthorizationOutcome;
  /** Constructed only through the message sanitizer at the shared outcome boundary. */
  reason: MessageText;
  /** Whether the outcome's terminal audit events were delivered. */
  terminalAuditDelivered: boolean;
}

/** What a wrapper's proof claims, wherever it is made. */
export type PendingProof = PendingAllowedProof | PendingOutcomeProof;

/** What a proof no longer waiting was about. */
interface ClosedProof {
  toolName: string;
  /** Not kept when it is large. */
  context?: McpAuditContext;
  size: number;
}

/** The proofs one middleware's wrappers left for the transport. */
export interface PendingProofs {
  /**
   * Leave `pending` to wait for the transport: the one-time id it waits
   * under. Past the count or the size budget, the oldest waiting proofs are
   * closed as not sent. The budget counts `pending`, which is all an entry
   * holds of a call.
   */
  leave(pending: PendingProof): string;
  /** Remove and return the proof waiting under `id`, if one is, remembering what it was about. */
  take(id: string): PendingProof | undefined;
  /** Close the proof waiting under `id`, if one is, as not sent. */
  closeUnsent(id: string): Promise<void>;
  /** The ids the proofs waiting now wait under, oldest first. */
  keys(): IterableIterator<string>;
  /** What the proof under `id`, no longer waiting, was about, while that is remembered. */
  closed(id: string): Pick<ClosedProof, 'toolName' | 'context'> | undefined;
}

/**
 * The proofs a middleware's wrappers leave, each waiting `ttlMs`, or five
 * minutes, to be sent. `close` records one that never was.
 */
export function createPendingProofs(
  ttlMs: number | undefined,
  close: (pending: PendingProof) => Promise<void>,
): PendingProofs {
  const windowMs = ttlMs ?? PENDING_PROOF_TTL_MS;
  // By id, each with the timer that closes it as not sent.
  const waiting = new Map<string, {
    pending: PendingProof;
    timer: ReturnType<typeof setTimeout>;
    size: number;
  }>();
  let waitingBytes = 0;
  // Bounded: the oldest are forgotten, and a large audit context is not kept.
  const closedProofs = new Map<string, ClosedProof>();
  let closedBytes = 0;

  const take = (id: string): PendingProof | undefined => {
    const entry = waiting.get(id);
    if (entry === undefined) return undefined;
    waiting.delete(id);
    waitingBytes -= entry.size;
    clearTimeout(entry.timer);
    const { toolName } = entry.pending;
    const context = entry.pending.kind === 'allowed' ? entry.pending.context : undefined;
    const contextSize = context === undefined ? 0 : JSON.stringify(context).length;
    const keepContext = context !== undefined && contextSize <= CLOSED_PROOF_CONTEXT_LIMIT;
    const size = toolName.length + (keepContext ? contextSize : 0);
    closedProofs.set(id, { toolName, ...(keepContext ? { context } : {}), size });
    closedBytes += size;
    // Oldest first, as the waiting proofs are evicted.
    while (closedProofs.size > PENDING_PROOF_LIMIT || closedBytes > CLOSED_PROOF_BYTE_BUDGET) {
      const oldest = closedProofs.keys().next().value as string;
      closedBytes -= closedProofs.get(oldest)!.size;
      closedProofs.delete(oldest);
    }
    return entry.pending;
  };

  const closeUnsent = async (id: string): Promise<void> => {
    const pending = take(id);
    if (pending !== undefined) await close(pending);
  };

  const leave = (pending: PendingProof): string => {
    const size = JSON.stringify(pending).length;
    while (
      waiting.size > 0 &&
      (waiting.size >= PENDING_PROOF_LIMIT || waitingBytes + size > PENDING_PROOF_BYTE_BUDGET)
    ) {
      const oldest = waiting.keys().next().value as string;
      // Taken now, so the loop sees it gone; recorded in the background.
      const evicted = take(oldest);
      if (evicted !== undefined) void close(evicted);
    }
    const id = base64urlEncodeFromBytes(globalThis.crypto.getRandomValues(new Uint8Array(16)));
    const timer = setTimeout(() => void closeUnsent(id), windowMs);
    // Do not hold a process open for an audit close-out.
    (timer as { unref?: () => void }).unref?.();
    waiting.set(id, { pending, timer, size });
    waitingBytes += size;
    return id;
  };

  return {
    leave,
    take,
    closeUnsent,
    keys: () => waiting.keys(),
    closed: (id) => closedProofs.get(id),
  };
}
