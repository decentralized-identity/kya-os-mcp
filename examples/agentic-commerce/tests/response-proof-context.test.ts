import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  createHandshakeRequest,
  createKyaOsMiddleware,
  generateDidKeyFromBase64,
  KYA_OS_PROOF_META_KEY,
  MemoryNonceCacheProvider,
  NodeCryptoProvider,
  NoopFetchProvider,
  ProofVerifier,
  SessionManager,
  SystemClockProvider,
  type DetachedProof,
} from '@kya-os/mcp';
import { ResponseProofContext } from '../src/lib/response-proof-context.js';
import { requireCredentialStore } from '../src/merchant/require-credential-store.js';

const crypto = new NodeCryptoProvider();
const audience = 'did:web:merchant.example';
const sessions = () => new SessionManager(crypto, {
  serverDid: audience, sessionTtlMinutes: 1, nonceCache: new MemoryNonceCacheProvider(),
});

afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });

describe('internal response proof context for stateless HTTP', () => {
  it('keeps real merchant responses signed after concurrent first calls and an unrelated handshake', async () => {
    const keys = await crypto.generateKeyPair();
    const did = generateDidKeyFromBase64(keys.publicKey);
    const middleware = createKyaOsMiddleware({
      identity: { did, kid: `${did}#${did.slice(8)}`, privateKey: keys.privateKey, publicKey: keys.publicKey },
      autoSession: false,
      nonceCache: new MemoryNonceCacheProvider(),
      grantStore: requireCredentialStore,
    }, crypto);
    const context = new ResponseProofContext(middleware.sessionManager, did);
    const read = middleware.wrapWithProof('catalog', async () => ({ content: [{ type: 'text', text: '[]' }] }));
    const call = async () => read({}, await context.getSessionId());
    const results = await Promise.all(Array.from({ length: 12 }, call));
    const proofOf = (result: Record<string, unknown>) =>
      (result._meta as Record<string, unknown> | undefined)?.[KYA_OS_PROOF_META_KEY] as DetachedProof;
    const proofs = results.map(proofOf);
    expect(proofs.every((proof) => proof?.meta.did === did)).toBe(true);
    const verifier = new ProofVerifier({
      cryptoProvider: crypto, clockProvider: new SystemClockProvider(),
      nonceCacheProvider: new MemoryNonceCacheProvider(), fetchProvider: new NoopFetchProvider(),
    });
    const publicKey = { kty: 'OKP' as const, crv: 'Ed25519' as const, kid: `${did}#${did.slice(8)}`, x: Buffer.from(keys.publicKey, 'base64').toString('base64url') };
    for (const [index, proof] of proofs.entries()) {
      expect(await verifier.verifyProof(proof, publicKey, {
        request: { method: 'catalog', params: {} }, response: { data: results[index]!.content },
      })).toMatchObject({ valid: true });
    }
    expect(new Set(proofs.map((proof) => proof.meta.sessionId)).size).toBe(1);
    expect(middleware.sessionManager.getStats().activeSessions).toBe(1);
    const ownId = await context.getSessionId();
    const unrelated = await middleware.sessionManager.validateHandshake(createHandshakeRequest(did));
    expect(unrelated.success).toBe(true);
    const next = await call();
    const nextProof = proofOf(next);
    expect(nextProof.meta.sessionId).toBe(ownId);
    expect(nextProof.meta.sessionId).not.toBe(unrelated.session?.sessionId);
    expect(await verifier.verifyProof(nextProof, publicKey, {
      request: { method: 'catalog', params: {} }, response: { data: next.content },
    })).toMatchObject({ valid: true });
  });

  it('renews an expired context once for concurrent requests using the real session expiry policy', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-09-08T12:00:00Z'));
    const manager = sessions();
    const context = new ResponseProofContext(manager, audience);
    const first = await context.getSessionId();
    vi.setSystemTime(new Date('2026-09-08T12:01:01Z'));
    const renewed = await Promise.all(Array.from({ length: 12 }, () => context.getSessionId()));
    expect(new Set(renewed).size).toBe(1);
    expect(renewed[0]).not.toBe(first);
    expect(await manager.getSession(first)).toBeNull();
    expect(manager.getStats().activeSessions).toBe(1);
    expect(await manager.getSession(renewed[0]!)).toMatchObject({ audience, identityState: 'anonymous' });
  });

  it('fails closed when the SDK refuses the response context audience', async () => {
    const manager = sessions();
    const context = new ResponseProofContext(manager, 'did:web:wrong.example');
    await expect(context.getSessionId()).rejects.toThrow(/response proof context/i);
    expect(manager.getStats().activeSessions).toBe(0);
  });

  it('shares a failed establishment and allows a later request to recover', async () => {
    const manager = sessions();
    const create = vi.spyOn(manager, 'validateHandshake').mockResolvedValueOnce({
      success: false, error: { code: 'handshake_failed', message: 'Store temporarily unavailable' },
    });
    const context = new ResponseProofContext(manager, audience);
    const failures = await Promise.allSettled(Array.from({ length: 12 }, () => context.getSessionId()));
    expect(failures.every((result) => result.status === 'rejected')).toBe(true);
    expect(create).toHaveBeenCalledTimes(1);
    const recovered = await context.getSessionId();
    expect(await manager.getSession(recovered)).not.toBeNull();
    expect(create).toHaveBeenCalledTimes(2);
  });

  it('never returns a cached context when its validity cannot be checked', async () => {
    const manager = sessions();
    const context = new ResponseProofContext(manager, audience);
    const first = await context.getSessionId();
    vi.spyOn(manager, 'getSession').mockRejectedValueOnce(new Error('Store unavailable'));
    await expect(context.getSessionId()).rejects.toThrow('Store unavailable');
    expect(await context.getSessionId()).toBe(first);
  });
});
