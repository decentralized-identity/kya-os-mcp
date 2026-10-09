/**
 * Test helpers: a middleware with a fresh did:key identity, and verification
 * of a tool result's response proof as a client would run it, against the
 * result it received.
 */
import type { AuditTrailService } from '../../../audit/service.js';
import { createKyaOsMiddleware, type KyaOsConfig, type KyaOsMiddleware } from '../../with-kya-os.js';
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
