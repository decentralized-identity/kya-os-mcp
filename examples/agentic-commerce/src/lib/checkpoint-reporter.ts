/**
 * Sends audit events to Checkpoint (`POST /api/v1/kya-os/events`) so its
 * dashboard shows this store's decisions: Activity rows, the Delegations page,
 * and revocations.
 *
 * Off unless both KYA_OS_EVENTS_URL and KYA_OS_EVENTS_TOKEN are set.
 *
 * It must never block, slow down or fail an order:
 * - `report()` only queues. It never throws and never waits.
 * - Sending runs later, off the order path, one batch at a time, in order.
 * - Each request times out after `timeoutMs`. Network errors, 429 and 5xx are
 *   tried again a few times with a short backoff; other answers are not.
 * - The queue is small and bounded. When full, the oldest events are dropped.
 *
 * The token only ever goes into the `X-API-Key` header. It is never logged and
 * never put in an error message.
 */
import type { CheckpointEvent } from './checkpoint-events.js';

export const CHECKPOINT_EVENTS_PATH = '/api/v1/kya-os/events';

/** Checkpoint takes at most 100 events per batch. */
const MAX_BATCH_SIZE = 100;

export const CHECKPOINT_REPORTER_DEFAULTS = {
  timeoutMs: 3_000,
  queueLimit: 200,
  maxAttempts: 3,
  retryDelayMs: 500,
  flushDelayMs: 100,
} as const;

export interface CheckpointReporterConfig {
  /** The events endpoint, or Checkpoint's origin (the path is then added). https, or http on loopback. */
  readonly url: string;
  /** A project API key with write permission. */
  readonly token: string;
  readonly timeoutMs?: number;
  readonly queueLimit?: number;
  readonly maxAttempts?: number;
  readonly retryDelayMs?: number;
  readonly flushDelayMs?: number;
  /** Where warnings go. Defaults to console.warn. Messages never hold the token. */
  readonly log?: (message: string) => void;
}

export interface CheckpointReporterStats {
  readonly queued: number;
  readonly sent: number;
  readonly accepted: number;
  readonly skipped: number;
  readonly failed: number;
  readonly dropped: number;
}

export interface CheckpointReporter {
  /** Queue events to send. Never throws, never waits. */
  report(events: readonly CheckpointEvent[]): void;
  /** Resolves when everything queued so far has been sent or given up on. For tests and shutdown. */
  flush(): Promise<void>;
  stats(): CheckpointReporterStats;
  /** The endpoint, for the startup line. Holds no secret. */
  readonly endpoint: string;
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

function configError(reason: string): Error {
  return new Error(`Checkpoint events: ${reason}`);
}

/** The full events URL. Errors name the problem, never the value. */
export function eventsEndpoint(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw configError('KYA_OS_EVENTS_URL is not an absolute URL');
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname))) {
    throw configError('KYA_OS_EVENTS_URL must use https (plain http only on loopback)');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw configError('KYA_OS_EVENTS_URL must not carry credentials, a query or a fragment');
  }
  if (url.pathname === '' || url.pathname === '/') url.pathname = CHECKPOINT_EVENTS_PATH;
  return url;
}

function wholeNumber(name: string, value: number, minimum: number, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw configError(`${name} must be a whole number from ${minimum} to ${maximum}`);
  }
  return value;
}

type SendResult =
  | { readonly kind: 'delivered'; readonly accepted: number; readonly skipped: number; readonly reasons: readonly string[] }
  | { readonly kind: 'retry'; readonly status: number | 'network error or timeout' }
  | { readonly kind: 'rejected'; readonly status: number | 'unreadable response' };

/** Checkpoint's 202 body: `{ accepted, skipped, skipped_details: [{ index, type, reason }] }`. */
function readCounts(body: unknown): SendResult {
  const { accepted, skipped, skipped_details: details } = (body ?? {}) as Record<string, unknown>;
  if (!Number.isInteger(accepted) || !Number.isInteger(skipped)) return { kind: 'rejected', status: 'unreadable response' };
  const reasons = Array.isArray(details)
    ? details.map((detail) => String((detail as { reason?: unknown })?.reason ?? '').slice(0, 200))
    : [];
  return { kind: 'delivered', accepted: accepted as number, skipped: skipped as number, reasons };
}

/**
 * Creates the reporter. Throws on bad config, so a host can decide at start.
 *
 * @example
 * const reporter = createCheckpointReporter({ url: 'https://kya.vouched.id', token });
 * reporter.report([orderDecisionEvent(decision, source)]);
 */
export function createCheckpointReporter(config: CheckpointReporterConfig): CheckpointReporter {
  const endpoint = eventsEndpoint(config.url);
  if (config.token.trim() === '') throw configError('KYA_OS_EVENTS_TOKEN is empty');
  const defaults = CHECKPOINT_REPORTER_DEFAULTS;
  const timeoutMs = wholeNumber('timeoutMs', config.timeoutMs ?? defaults.timeoutMs, 1);
  const queueLimit = wholeNumber('queueLimit', config.queueLimit ?? defaults.queueLimit, 1);
  const maxAttempts = wholeNumber('maxAttempts', config.maxAttempts ?? defaults.maxAttempts, 1, 10);
  const retryDelayMs = wholeNumber('retryDelayMs', config.retryDelayMs ?? defaults.retryDelayMs, 0);
  const flushDelayMs = wholeNumber('flushDelayMs', config.flushDelayMs ?? defaults.flushDelayMs, 0);
  const token = config.token.trim();
  const hostLog = config.log ?? ((message: string) => console.warn(message));
  const log = (message: string): void => {
    try {
      hostLog(`[checkpoint-events] ${message}`);
    } catch {
      // A broken logger must not break reporting, and through it an order.
    }
  };

  const queue: CheckpointEvent[] = [];
  const counts = { sent: 0, accepted: 0, skipped: 0, failed: 0, dropped: 0 };
  let timer: ReturnType<typeof setTimeout> | undefined;
  let draining: Promise<void> | undefined;

  async function post(batch: readonly CheckpointEvent[]): Promise<SendResult> {
    let response: Response;
    try {
      response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-api-key': token },
        body: JSON.stringify({ events: batch }),
        signal: AbortSignal.timeout(timeoutMs),
        // A followed redirect would resend X-API-Key to wherever Location points.
        redirect: 'manual',
      });
    } catch {
      return { kind: 'retry', status: 'network error or timeout' };
    }
    if (response.status === 429 || response.status >= 500) {
      await response.body?.cancel().catch(() => undefined);
      return { kind: 'retry', status: response.status };
    }
    if (!response.ok) {
      // An error body may echo the request; it is not read.
      await response.body?.cancel().catch(() => undefined);
      return { kind: 'rejected', status: response.status };
    }
    try {
      return readCounts(await response.json());
    } catch {
      return { kind: 'rejected', status: 'unreadable response' };
    }
  }

  async function deliver(batch: readonly CheckpointEvent[]): Promise<void> {
    for (let attempt = 1; ; attempt++) {
      const result = await post(batch);
      if (result.kind === 'delivered') {
        counts.sent += batch.length;
        counts.accepted += result.accepted;
        counts.skipped += result.skipped;
        // Checkpoint answers 202 even when it drops a malformed event.
        if (result.skipped > 0) log(`Checkpoint skipped ${result.skipped} of ${batch.length} events: ${result.reasons.join('; ')}`);
        return;
      }
      if (result.kind === 'retry' && attempt < maxAttempts) {
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs * 2 ** (attempt - 1)).unref());
        continue;
      }
      counts.failed += batch.length;
      log(`gave up on ${batch.length} events after ${attempt} attempts (${result.status})`);
      return;
    }
  }

  function startDrain(): Promise<void> {
    draining ??= (async () => {
      try {
        while (queue.length > 0) await deliver(queue.splice(0, MAX_BATCH_SIZE));
      } catch (error) {
        log(`send error (${error instanceof Error ? error.name : typeof error})`);
      } finally {
        draining = undefined;
      }
    })();
    return draining;
  }

  function schedule(): void {
    if (timer !== undefined || draining !== undefined) return;
    timer = setTimeout(() => {
      timer = undefined;
      void startDrain().then(() => {
        // Events reported while a batch was in flight.
        if (queue.length > 0) schedule();
      });
    }, flushDelayMs);
    // A pending send must never keep the process alive.
    timer.unref();
  }

  return {
    endpoint: endpoint.toString(),
    report(events) {
      try {
        if (events.length === 0) return;
        queue.push(...events);
        const overflow = queue.length - queueLimit;
        if (overflow > 0) {
          queue.splice(0, overflow);
          counts.dropped += overflow;
          log(`queue full: dropped the ${overflow} oldest events`);
        }
        schedule();
      } catch (error) {
        log(`queue error (${error instanceof Error ? error.name : typeof error})`);
      }
    },
    async flush() {
      if (timer !== undefined) clearTimeout(timer);
      timer = undefined;
      while (queue.length > 0 || draining !== undefined) await (draining ?? startDrain());
    },
    stats() {
      return { ...counts, queued: queue.length };
    },
  };
}

/**
 * The reporter from KYA_OS_EVENTS_URL and KYA_OS_EVENTS_TOKEN, or null when
 * reporting is off. A half-set or invalid config logs one warning and stays
 * off: reporting is never a reason for the store not to start.
 */
export function checkpointReporterFromEnv(
  environment: NodeJS.ProcessEnv = process.env,
  log: (message: string) => void = (message) => console.warn(message),
): CheckpointReporter | null {
  const url = environment['KYA_OS_EVENTS_URL']?.trim() ?? '';
  const token = environment['KYA_OS_EVENTS_TOKEN']?.trim() ?? '';
  if (url === '' && token === '') return null;
  if (url === '' || token === '') {
    log('[checkpoint-events] off: set both KYA_OS_EVENTS_URL and KYA_OS_EVENTS_TOKEN');
    return null;
  }
  try {
    return createCheckpointReporter({ url, token, log });
  } catch (error) {
    log(`[checkpoint-events] off: ${error instanceof Error ? error.message : 'invalid configuration'}`);
    return null;
  }
}
