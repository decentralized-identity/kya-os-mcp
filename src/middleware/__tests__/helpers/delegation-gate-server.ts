/**
 * Test helper: a server behind the delegation gate, as the tests of what the
 * gate reads and records of a delegation (SPEC.md §7.8) run it, with the
 * audit events it records, and the faults and clocks they hold it to.
 */
import { vi } from 'vitest';
import {
  createKyaOsMiddleware,
  type KyaOsConfig,
  type KyaOsDelegationConfig,
} from '../../with-kya-os.js';
import { NodeCryptoProvider } from '../../../__tests__/utils/node-crypto-provider.js';
import { isCredentialDigestInput } from '../../../__tests__/utils/digests.js';
import type { AuditTrailService } from '../../../audit/service.js';
import type { AuthorizationEvidence, PartyRef } from '../../../audit/types.js';
import type { DelegationCredential } from '../../../types/protocol.js';
import { party } from './delegating-party.js';
import { connectTransport, served } from './received-proof.js';

/**
 * The server's crypto provider. It is not the one `./received-proof.js`
 * verifies with, so a test can make the server's fail and still verify what
 * the server sent.
 */
export const crypto = new NodeCryptoProvider();
export const hash = (bytes: Uint8Array) => crypto.hash(bytes);

export interface Recorded {
  eventType: string;
  /** The tool a `tool.call.*` event is about. */
  tool?: string;
  /** Who the event says acted. */
  actor?: PartyRef;
  outcome: string;
  /** The code of the reason an event gives, a failed call's say. */
  reason?: string;
  authorization?: AuthorizationEvidence;
  details: Record<string, unknown>;
}

/** Configuration a test sets beside the delegation's. */
export type OtherConfig = Partial<Omit<KyaOsConfig, 'identity' | 'delegation' | 'audit'>>;

/**
 * A middleware whose resolver hands back whatever `ancestors` holds when it
 * is asked, with the audit events it records. It keeps an audit trail unless
 * told to keep none, and fails to record an event `refuse` picks.
 */
async function makeMiddleware(
  delegation: KyaOsDelegationConfig = {},
  config: OtherConfig = {},
  { audit = true, refuse }: { audit?: boolean; refuse?: (eventType: string) => boolean } = {},
) {
  const server = await party();
  const ancestors: DelegationCredential[] = [];
  const recorded: Recorded[] = [];
  const record: AuditTrailService['record'] = async (event) => {
    if (refuse?.(event.eventType) === true) throw new Error('audit sink unavailable');
    recorded.push({
      eventType: event.eventType,
      ...(event.action.name === undefined ? {} : { tool: event.action.name }),
      ...(event.actor === undefined ? {} : { actor: event.actor }),
      outcome: event.outcome,
      ...(event.reason === undefined ? {} : { reason: event.reason.code }),
      authorization: event.authorization,
      details: event.details as unknown as Record<string, unknown>,
    });
    return { status: 'pending', event: event as never };
  };
  const kyaos = createKyaOsMiddleware(
    {
      identity: server,
      session: { sessionTtlMinutes: 60 },
      autoSession: true,
      ...(audit ? { audit: { record, includeToolNames: true } } : {}),
      delegation: { resolveDelegationChain: async () => [...ancestors], ...delegation },
      ...config,
    },
    crypto,
  );
  return { kyaos, server, ancestors, recorded };
}

/** That middleware as a server runs it: what a handler the test calls returns is what the client receives. */
export async function makeServer(
  delegation: KyaOsDelegationConfig = {},
  trail: Parameters<typeof makeMiddleware>[2] = {},
  config: OtherConfig = {},
) {
  const made = await makeMiddleware(delegation, config, trail);
  return { ...made, kyaos: await served(made.kyaos) };
}

/**
 * That middleware with its transport driven by hand, for a result the test
 * sends itself: one that answers no tracked call, or is no result at all.
 */
export async function makeUnserved(delegation: KyaOsDelegationConfig = {}, config: OtherConfig = {}) {
  const made = await makeMiddleware(delegation, config);
  return { ...made, wire: await connectTransport(made.kyaos) };
}

/**
 * Both ways a server may be set: with an audit trail, which records the
 * digest of every credential of a chain, or without one. What a server
 * decides must not turn on which it is.
 */
export const CONFIGURATIONS = [
  ['no audit trail', { audit: false }],
  ['an audit trail', { audit: true }],
] as const;

/**
 * Make the hash provider fail on a credential digest (SPEC §7.8) and on
 * nothing else: a fault in what the server runs on, not in what it was shown.
 * A fault throws what it likes, an Error or not.
 */
export function failCredentialDigests(fault: unknown): void {
  const real = crypto.hash.bind(crypto);
  vi.spyOn(crypto, 'hash').mockImplementation(async (bytes) => {
    if (isCredentialDigestInput(bytes)) throw fault;
    return real(bytes);
  });
}

/**
 * Run `body` with timers held: a proof left waiting stays so while a call is
 * answered, however long answering takes, and its window passes only when
 * `body` moves the clock past it.
 */
export async function withTimersHeld(body: () => Promise<void>): Promise<void> {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  try {
    await body();
  } finally {
    vi.useRealTimers();
  }
}
