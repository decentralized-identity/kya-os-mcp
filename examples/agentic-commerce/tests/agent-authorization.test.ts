import { beforeAll, describe, expect, it, vi } from 'vitest';
import {
  KYA_OS_PROOF_META_KEY,
  NodeCryptoProvider,
  ProofGenerator,
  RESPONSE_PROOF_PROFILE_ENVELOPE,
  generateDidKeyFromBase64,
  type DetachedProof,
  type ProofAgentIdentity,
  type ProofOptions,
} from '@kya-os/mcp';
import { createAuthorizationVerifier, createOrderResponseVerifier, type MerchantToolResult } from '../src/agent/authorization.js';

const crypto = new NodeCryptoProvider();
const scope = 'https://id.gs1.org/01/09506000134352';
const agentDid = 'did:key:test-agent';
const sentArgs = { product: 'risotto', quantity: 2, _kyaos_proof: { request: 'holder-signed' } };
let merchant: ProofAgentIdentity;
let attacker: ProofAgentIdentity;

beforeAll(async () => {
  const identity = async () => {
    const keys = await crypto.generateKeyPair();
    const did = generateDidKeyFromBase64(keys.publicKey);
    return { did, kid: `${did}#${did.slice(8)}`, privateKey: keys.privateKey, publicKey: keys.publicKey };
  };
  merchant = await identity();
  attacker = await identity();
});

function challenge(overrides: Record<string, unknown> = {}) {
  const url = new URL('http://127.0.0.1:4950/consent');
  url.searchParams.set('tool', 'place_order');
  url.searchParams.set('resume_token', 'single-use-authorization-token');
  url.searchParams.set('agent_did', agentDid);
  url.searchParams.set('scopes', JSON.stringify([scope]));
  return {
    error: 'needs_authorization', message: 'Approve the shopping grant.',
    authorizationUrl: url.href, resumeToken: 'single-use-authorization-token',
    expiresAt: Math.floor(Date.now() / 1000) + 600, scopes: [scope], ...overrides,
  };
}

async function signed(options: {
  body?: Record<string, unknown>; signer?: ProofAgentIdentity; args?: Record<string, unknown>;
  proof?: ProofOptions; bodyless?: boolean;
} = {}): Promise<MerchantToolResult> {
  const result: MerchantToolResult = { content: [{ type: 'text', text: JSON.stringify(options.body ?? challenge()) }] };
  const now = Date.now();
  const proof = await new ProofGenerator(options.signer ?? merchant, crypto).generateProof(
    { method: 'place_order', params: options.args ?? sentArgs },
    options.bodyless ? undefined : { data: options.proof?.profile === RESPONSE_PROOF_PROFILE_ENVELOPE ? result : result.content },
    { sessionId: 'merchant-session', audience: merchant.did, nonce: 'session-nonce', timestamp: now, createdAt: now, lastActivity: now, ttlMinutes: 30, identityState: 'anonymous' },
    { outcome: 'needs_authorization', ...options.proof },
  );
  result._meta = { [KYA_OS_PROOF_META_KEY]: proof };
  return result;
}

const verify = (result: MerchantToolResult, args = sentArgs, verifier = createAuthorizationVerifier()) => verifier(result, {
  args, merchantDid: merchant.did, agentDid, consentOrigin: 'http://127.0.0.1:4950', scope,
});

describe('merchant authorization challenge trust boundary', () => {
  it.each([undefined, RESPONSE_PROOF_PROFILE_ENVELOPE] as const)('accepts a merchant signature binding the actual request and URL (%s)', async (profile) => {
    const body = challenge();
    const result = await signed({ body, proof: { profile } });
    expect(await verify(result)).toEqual(body);
  });

  it('does not interpret a normal policy denial as consent', async () => {
    expect(await verify({ content: [{ type: 'text', text: JSON.stringify({ error: 'PRODUCT_OUT_OF_SCOPE' }) }] })).toBeNull();
  });

  it('rejects an unsigned challenge', async () => {
    await expect(verify({ content: [{ type: 'text', text: JSON.stringify(challenge()) }] })).rejects.toThrow(/proof/i);
  });

  it('rejects a valid signature from a different DID', async () => {
    await expect(verify(await signed({ signer: attacker }))).rejects.toThrow(/merchant/i);
  });

  it('rejects a swapped authorization URL before exposing it', async () => {
    const result = await signed();
    result.content![0]!.text = JSON.stringify(challenge({ authorizationUrl: 'https://evil.example/consent' }));
    await expect(verify(result)).rejects.toThrow(/binding|proof/i);
  });

  it('rejects a proof for a different order', async () => {
    await expect(verify(await signed({ args: { ...sentArgs, quantity: 1 } }))).rejects.toThrow(/binding/i);
  });

  it('rejects unknown proof profiles rather than downgrading verification', async () => {
    const result = await signed();
    const proof = result._meta![KYA_OS_PROOF_META_KEY] as DetachedProof;
    (proof.meta as unknown as Record<string, unknown>)['prf'] = 'unknown-profile';
    await expect(verify(result)).rejects.toThrow(/proof|profile/i);
  });

  it('requires responseHash and needs_authorization outcome', async () => {
    await expect(verify(await signed({ bodyless: true }))).rejects.toThrow(/response|proof/i);
    await expect(verify(await signed({ proof: { outcome: 'allowed' } }))).rejects.toThrow(/outcome|proof/i);
  });

  it('rejects a replayed signed challenge', async () => {
    const result = await signed();
    const verifier = createAuthorizationVerifier();
    await verify(result, sentArgs, verifier);
    await expect(verify(result, sentArgs, verifier)).rejects.toThrow(/nonce|replay/i);
  });

  it('rejects an old response proof even while the embedded consent expiry is still future', async () => {
    const now = Date.now();
    const clock = vi.spyOn(Date, 'now').mockReturnValue(now - 900_000);
    let result: MerchantToolResult;
    try { result = await signed({ body: challenge({ expiresAt: Math.floor(now / 1000) + 600 }) }); }
    finally { clock.mockRestore(); }
    await expect(verify(result!)).rejects.toThrow(/timestamp|skew/i);
  });

  it('accepts either loopback name on the configured RP port after authenticating the URL', async () => {
    const body = challenge();
    body.authorizationUrl = body.authorizationUrl.replace('127.0.0.1', 'localhost');
    expect(await verify(await signed({ body }))).toEqual(body);
  });

  it.each([
    { expiresAt: Math.floor(Date.now() / 1000) - 1 },
    { expiresAt: 'tomorrow' },
    { scopes: ['tool:place_order'] },
    { authorizationUrl: 'https://evil.example/consent' },
    { authorizationUrl: 'http://127.0.0.1:4950/admin' },
    { authorizationUrl: 'http://127.0.0.1:4951/consent' },
    { authorizationUrl: 'http://user:secret@127.0.0.1:4950/consent' },
    { resumeToken: 'swapped-token' },
  ])('rejects an authentic but unsafe challenge: %j', async (overrides) => {
    await expect(verify(await signed({ body: challenge(overrides) }))).rejects.toThrow(/authorization/i);
  });

  it('rejects a mismatched agent or scope in the signed URL', async () => {
    for (const [key, value] of [['agent_did', 'did:key:another-agent'], ['scopes', JSON.stringify(['tool:place_order'])], ['tool', 'transfer_money']]) {
      const body = challenge();
      const url = new URL(body.authorizationUrl);
      url.searchParams.set(key!, value!);
      await expect(verify(await signed({ body: { ...body, authorizationUrl: url.href } }))).rejects.toThrow(/authorization/i);
    }
  });
});

describe('merchant receipt proof boundary', () => {
  const receiptBody = { ok: true, orderId: 'ORD-proof-test', order: { quantity: 2, name: 'Risotto', total: 'CHF 39.80' } };
  const cleanArgs = { product: 'risotto', quantity: 2 };
  const check = (result: MerchantToolResult) => createOrderResponseVerifier()(result, {
    args: sentArgs, merchantDid: merchant.did, agentDid, consentOrigin: 'http://127.0.0.1:4950', scope,
  });

  it.each([undefined, RESPONSE_PROOF_PROFILE_ENVELOPE] as const)('verifies a success proof over the clean request and received receipt (%s)', async (profile) => {
    const result = await signed({ body: receiptBody, args: cleanArgs, proof: { outcome: undefined, profile } });
    expect(await check(result)).toBeNull();
  });

  it('rejects an unsigned success instead of claiming a signed order receipt', async () => {
    await expect(check({ content: [{ type: 'text', text: JSON.stringify(receiptBody) }] })).rejects.toThrow(/proof/i);
  });

  it('rejects tampered success contents', async () => {
    const result = await signed({ body: receiptBody, args: cleanArgs, proof: { outcome: undefined } });
    result.content![0]!.text = JSON.stringify({ ...receiptBody, orderId: 'ORD-swapped' });
    await expect(check(result)).rejects.toThrow(/binding/i);
  });

  it.each([
    { x402Version: 2, error: 'PAYMENT_REQUIRED', accepts: [{ amount: '39800000' }] },
    { error: 'SETTLEMENT_PENDING', message: 'Do not create a second payment.' },
  ])('authenticates an error-shaped payment control result before acting on it', async body => {
    const result = await signed({ body, args: cleanArgs, proof: { outcome: 'allowed' } });
    result.isError = true; // The MCP transport sets this after the handler signs.
    expect(await check(result)).toBeNull();
    const unsigned = { content: result.content, isError: true };
    await expect(check(unsigned)).rejects.toThrow(/proof/i);
    result.content![0]!.text = JSON.stringify({ ...body, altered: true });
    await expect(check(result)).rejects.toThrow(/binding/i);
  });
});
