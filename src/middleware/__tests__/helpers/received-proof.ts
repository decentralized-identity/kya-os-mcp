/**
 * Test helpers: a middleware with a fresh did:key identity, and verification
 * of a tool result's response proof as a client would run it, against the
 * result it received.
 */
import type { AuditTrailService } from '../../../audit/service.js';
import { AsyncLocalStorage } from 'node:async_hooks';
import {
  createKyaOsMiddleware,
  type KyaOsConfig,
  type KyaOsMiddleware,
  type KyaOsToolHandler,
  type KyaOsToolResult,
} from '../../with-kya-os.js';
import { createKyaOsTransport, type JSONRPCMessage, type Transport } from '../../kya-os-transport.js';
import { NodeCryptoProvider } from '../../../__tests__/utils/node-crypto-provider.js';
import { generateDidKeyFromBase64, didKeyFragment } from '../../../utils/did-helpers.js';
import { extractPublicKeyFromDidKey, publicKeyToJwk } from '../../../delegation/did-key-resolver.js';
import { KYA_OS_PROOF_META_KEY } from '../../../proof/generator.js';
import { ProofVerifier, type ProofVerificationResult } from '../../../proof/verifier.js';
import { MemoryNonceCacheProvider } from '../../../providers/memory.js';
import { SystemClockProvider } from '../../../providers/system-clock.js';
import { NoopFetchProvider } from '../../../providers/runtime-fetch.js';
import type { DetachedProof } from '../../../types/protocol.js';
import type { Ed25519JWK } from '../../../utils/crypto-service.js';

export const crypto = new NodeCryptoProvider();

export async function createMiddleware(
  config: Partial<Omit<KyaOsConfig, 'identity'>> = {},
): Promise<KyaOsMiddleware> {
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  return createKyaOsMiddleware(
    {
      identity: { did, kid: `${did}#${didKeyFragment(did)}`, ...keyPair },
      session: { sessionTtlMinutes: 60 },
      ...config,
    },
    crypto,
  );
}

/** Establish a session the way a KYA-OS client does, and return its id. */
export async function handshake(kyaos: KyaOsMiddleware): Promise<string> {
  const result = await kyaos.handleHandshake({
    nonce: `nonce-${Math.random().toString(36).slice(2)}`,
    audience: kyaos.identity.did,
    timestamp: Math.floor(Date.now() / 1000),
  });
  return JSON.parse(result.content[0]!.text).sessionId as string;
}

/** Audit events as `eventType:outcome`, in the order they were recorded. */
export function auditEvents(): {
  events: string[];
  record: Pick<AuditTrailService, 'record'>['record'];
} {
  const events: string[] = [];
  const record: Pick<AuditTrailService, 'record'>['record'] = async (event) => {
    events.push(`${event.eventType}:${event.outcome}`);
    return { status: 'pending', event: event as never };
  };
  return { events, record };
}

/** A withKyaOs transport over a far end that records what it is sent. */
export interface TransportHarness {
  /** Every message the far end received, as JSON it would have read off the wire. */
  sent: JSONRPCMessage[];
  /**
   * Send `result` as the answer to a `tools/call` of `toolName` with `args`, as
   * the MCP SDK hands a result to its transport, and return the result as it
   * left the process.
   */
  send(
    result: KyaOsToolResult,
    call?: { toolName?: string; args?: Record<string, unknown> },
  ): Promise<Record<string, unknown>>;
}

/**
 * Connect `kyaos` to a withKyaOs transport, so its wrappers have an outer
 * layer: under the envelope profile they leave their proofs to it. Connect
 * before calling a wrapper, as a server connects before it serves calls.
 */
export async function connectTransport(kyaos: KyaOsMiddleware): Promise<TransportHarness> {
  const sent: JSONRPCMessage[] = [];
  const inner: Transport = {
    start: async () => {},
    close: async () => {},
    send: async (message) => {
      sent.push(JSON.parse(JSON.stringify(message)) as JSONRPCMessage);
    },
  };
  const wrapper = createKyaOsTransport(inner, kyaos);
  await wrapper.start();
  let id = 0;
  return {
    sent,
    async send(result, call = {}) {
      id += 1;
      inner.onmessage!({
        jsonrpc: '2.0',
        id,
        method: 'tools/call',
        params: { name: call.toolName ?? 'tool', arguments: call.args ?? {} },
      });
      // The SDK hands the transport a result of its own making, not the
      // handler's object.
      await wrapper.send({ jsonrpc: '2.0', id, result: structuredClone(result) });
      return (sent.at(-1) as { result: Record<string, unknown> }).result;
    },
  };
}

/**
 * `kyaos` as a server runs it: connected to a withKyaOs transport, so the
 * proofs it makes are made there. A handler the test calls is the handler the
 * MCP SDK would call, so its result is sent through the transport and the
 * test gets what the client receives. A handler the middleware calls in turn
 * (a wrapped handler inside a gate) is not sent on its own, as in a server,
 * and neither is a `proveOutcome` result made inside a handler. The proxy
 * changes nothing else: sessions, the proof generator and the handshake are
 * the middleware's own.
 */
export async function served(kyaos: KyaOsMiddleware): Promise<KyaOsMiddleware & { wire: TransportHarness }> {
  const wire = await connectTransport(kyaos);
  const inCall = new AsyncLocalStorage<true>();
  const serve = (toolName: string, handler: KyaOsToolHandler): KyaOsToolHandler =>
    async (args, sessionId, context) => {
      if (inCall.getStore()) return handler(args, sessionId, context);
      const result = await inCall.run(true, () => handler(args, sessionId, context));
      return await wire.send(result, { toolName, args }) as KyaOsToolResult;
    };
  return new Proxy(kyaos, {
    get(target, key, receiver) {
      switch (key) {
        case 'wire':
          return wire;
        case 'wrapWithProof':
          return (toolName: string, handler: KyaOsToolHandler) =>
            serve(toolName, target.wrapWithProof(toolName, handler));
        case 'wrapWithDelegation':
          return (toolName: string, config: Parameters<KyaOsMiddleware['wrapWithDelegation']>[1], handler: KyaOsToolHandler) =>
            serve(toolName, target.wrapWithDelegation(toolName, config, handler));
        case 'withPolicyGate':
          return target.withPolicyGate === undefined
            ? undefined
            : (toolName: string, handler: KyaOsToolHandler, opts?: Parameters<NonNullable<KyaOsMiddleware['withPolicyGate']>>[2]) =>
                serve(toolName, target.withPolicyGate!(toolName, handler, opts));
        case 'proveOutcome':
          return target.proveOutcome === undefined
            ? undefined
            : async (request: Parameters<NonNullable<KyaOsMiddleware['proveOutcome']>>[0]) => {
                const result = await target.proveOutcome!(request);
                return inCall.getStore()
                  ? result
                  : await wire.send(result, { toolName: request.toolName, args: request.args });
              };
        default:
          return Reflect.get(target, key, receiver);
      }
    },
  }) as KyaOsMiddleware & { wire: TransportHarness };
}

export function proofOf(result: { _meta?: unknown }): DetachedProof | undefined {
  return (result._meta as Record<string, DetachedProof> | undefined)?.[KYA_OS_PROOF_META_KEY];
}

/**
 * Verify the proof a result carries, as its client would: signature, signer,
 * and the hashes recomputed over the request it sent and the result it got.
 * `binds` names what the proof is expected to cover of the result: the whole
 * envelope (less `_meta`), its content array, or nothing.
 */
export async function verifyReceived(
  result: Record<string, unknown>,
  expected: {
    signer: string;
    toolName: string;
    params: Record<string, unknown>;
    binds: 'envelope' | 'content' | 'nothing';
  },
): Promise<ProofVerificationResult> {
  const proof = proofOf(result);
  if (proof === undefined) throw new Error('the result carries no response proof');
  const jwk = publicKeyToJwk(extractPublicKeyFromDidKey(expected.signer)!) as Ed25519JWK;
  jwk.kid = proof.meta.kid;
  const verifier = new ProofVerifier({
    cryptoProvider: crypto,
    clockProvider: new SystemClockProvider(),
    nonceCacheProvider: new MemoryNonceCacheProvider(),
    fetchProvider: new NoopFetchProvider(),
  });
  const response =
    expected.binds === 'envelope' ? { data: result }
      : expected.binds === 'content' ? { data: result.content }
        : undefined;
  return verifier.verifyProof(
    proof,
    jwk,
    { request: { method: expected.toolName, params: expected.params }, ...(response ? { response } : {}) },
    { expectedDid: expected.signer },
  );
}
