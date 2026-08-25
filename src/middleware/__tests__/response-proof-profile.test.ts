/**
 * Middleware plumbing for the response-proof profile (`responseProofProfile`).
 *
 * Default is v1 — proofs stay wire-identical to pre-v2 releases (no `prf`,
 * `responseHash` over the content array). Opting into v2 makes every emitted
 * proof carry the signature-covered `prf` discriminator and bind the FULL
 * result envelope (minus top-level `_meta`), closing the v1 blind spot where
 * `structuredContent` / `isError` / `resultType` were unauthenticated.
 */

import { describe, it, expect } from 'vitest';
import { canonicalize } from 'json-canonicalize';
import { createKyaOsMiddleware } from '../with-kya-os.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { generateDidKeyFromBase64 } from '../../utils/did-helpers.js';
import {
  KYA_OS_PROOF_META_KEY,
  RESPONSE_PROOF_PROFILE_V2,
} from '../../proof/index.js';
import type { DetachedProof, ResponseProofProfile } from '../../types/protocol.js';

async function createTestMiddleware(options?: {
  responseProofProfile?: ResponseProofProfile;
}) {
  const crypto = new NodeCryptoProvider();
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  const kid = `${did}#${did.replace('did:key:', '')}`;

  const middleware = createKyaOsMiddleware(
    {
      identity: { did, kid, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey },
      session: { sessionTtlMinutes: 60 },
      ...(options?.responseProofProfile !== undefined
        ? { responseProofProfile: options.responseProofProfile }
        : {}),
    },
    crypto,
  );

  return { middleware, did, crypto };
}

async function handshake(middleware: Awaited<ReturnType<typeof createTestMiddleware>>['middleware'], did: string) {
  const hs = await middleware.handleHandshake({
    nonce: `nonce-${Math.random().toString(36).slice(2)}`,
    audience: did,
    timestamp: Math.floor(Date.now() / 1000),
  });
  return JSON.parse(hs.content[0]!.text).sessionId as string;
}

function proofOf(result: { _meta?: Record<string, unknown> }): DetachedProof {
  return result._meta![KYA_OS_PROOF_META_KEY] as DetachedProof;
}

async function sha256Of(crypto: NodeCryptoProvider, value: unknown): Promise<string> {
  return crypto.hash(new TextEncoder().encode(canonicalize(value)));
}

/** A tool result with members OUTSIDE the v1-covered content array. */
const RICH_RESULT = {
  content: [{ type: 'text', text: 'hi' }],
  structuredContent: { msg: 'hi' },
  isError: false,
  resultType: 'complete',
};

describe('responseProofProfile — wrapWithProof', () => {
  it('defaults to v1: no prf, responseHash over the content array only', async () => {
    const { middleware, did, crypto } = await createTestMiddleware();
    const sessionId = await handshake(middleware, did);

    const handler = middleware.wrapWithProof('rich', async () => ({ ...RICH_RESULT }));
    const result = await handler({ q: 1 }, sessionId);

    const proof = proofOf(result);
    expect(proof.meta.prf).toBeUndefined();
    expect(proof.meta.responseHash).toBe(await sha256Of(crypto, RICH_RESULT.content));
  });

  it('v2: prf present, responseHash over the full envelope minus _meta', async () => {
    const { middleware, did, crypto } = await createTestMiddleware({
      responseProofProfile: RESPONSE_PROOF_PROFILE_V2,
    });
    const sessionId = await handshake(middleware, did);

    const handler = middleware.wrapWithProof('rich', async () => ({ ...RICH_RESULT }));
    const result = await handler({ q: 1 }, sessionId);

    const proof = proofOf(result);
    expect(proof.meta.prf).toBe(RESPONSE_PROOF_PROFILE_V2);
    // The envelope the client receives, minus _meta (where this proof rides).
    const { _meta: _m, ...received } = result as Record<string, unknown>;
    expect(proof.meta.responseHash).toBe(await sha256Of(crypto, received));
    // And that hash genuinely covers the v1 blind-spot members.
    expect(proof.meta.responseHash).not.toBe(
      await sha256Of(crypto, { ...received, structuredContent: { msg: 'TAMPERED' } }),
    );
  });

  it('v2 round-trips through the generator verify path with the received result', async () => {
    const { middleware, did } = await createTestMiddleware({
      responseProofProfile: RESPONSE_PROOF_PROFILE_V2,
    });
    const sessionId = await handshake(middleware, did);

    const handler = middleware.wrapWithProof('rich', async () => ({ ...RICH_RESULT }));
    const result = await handler({ q: 1 }, sessionId);
    const proof = proofOf(result);

    // A client passes the result AS RECEIVED (proof still in _meta) — the
    // profile-aware hashing strips _meta itself.
    await expect(
      middleware.proofGenerator.verifyProof(proof, { method: 'rich', params: { q: 1 } }, { data: result }),
    ).resolves.toBe(true);

    await expect(
      middleware.proofGenerator.verifyProof(
        proof,
        { method: 'rich', params: { q: 1 } },
        { data: { ...result, resultType: 'input_required' } },
      ),
    ).resolves.toBe(false);
  });
});

describe('responseProofProfile — needs_authorization challenge', () => {
  it('v2 challenge proof binds the challenge envelope (minus _meta) and carries prf', async () => {
    const { middleware, did, crypto } = await createTestMiddleware({
      responseProofProfile: RESPONSE_PROOF_PROFILE_V2,
    });
    const sessionId = await handshake(middleware, did);

    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
      async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
    );
    const result = await handler({ name: 'world' }, sessionId);

    const parsed = JSON.parse(result.content[0]!.text);
    expect(parsed.error).toBe('needs_authorization');

    const proof = proofOf(result);
    expect(proof.meta.prf).toBe(RESPONSE_PROOF_PROFILE_V2);
    expect(proof.meta.outcome).toBe('needs_authorization');
    const { _meta: _m, ...received } = result as Record<string, unknown>;
    expect(proof.meta.responseHash).toBe(await sha256Of(crypto, received));
  });

  it('v1 (default) challenge proof still binds the bare challenge content — unchanged', async () => {
    const { middleware, did, crypto } = await createTestMiddleware();
    const sessionId = await handshake(middleware, did);

    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
      async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
    );
    const result = await handler({ name: 'world' }, sessionId);

    const proof = proofOf(result);
    expect(proof.meta.prf).toBeUndefined();
    expect(proof.meta.responseHash).toBe(await sha256Of(crypto, result.content));
  });

  it('denial proofs remain body-free under v2 (no responseHash, prf still declared)', async () => {
    const { middleware, did } = await createTestMiddleware({
      responseProofProfile: RESPONSE_PROOF_PROFILE_V2,
    });
    const sessionId = await handshake(middleware, did);

    const handler = middleware.wrapWithDelegation(
      'my-tool',
      { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
      async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
    );
    // A malformed delegation arg produces a denied outcome (no challenge body).
    const result = await handler({ _kyaos_delegation: { not: 'a-credential' } }, sessionId);

    const proof = proofOf(result);
    expect(proof.meta.outcome).toBe('denied');
    expect(proof.meta.responseHash).toBeUndefined();
    // The profile declaration is uniform across every proof the server mints —
    // inert on a body-free proof, but it keeps "this server emits v2" coherent.
    expect(proof.meta.prf).toBe(RESPONSE_PROOF_PROFILE_V2);
  });
});
