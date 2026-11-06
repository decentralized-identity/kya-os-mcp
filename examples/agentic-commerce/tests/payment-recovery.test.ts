import { afterEach, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { KYA_OS_PROOF_META_KEY, NodeCryptoProvider, ProofGenerator, generateDidKeyFromBase64, toHolderBindingRequest } from '@kya-os/mcp';
import { createUcpBackend } from '../src/commerce/backend.js';
import { CommerceJournal } from '../src/commerce/journal.js';
import { PaymentCoordinator } from '../src/commerce/payments.js';
import { X402Rail } from '../src/payments/x402.js';
import { signMessage } from '../src/lib/consent-protocol.js';
import { createOrderResponseVerifier, responseBody, type MerchantToolResult } from '../src/agent/authorization.js';
import type { KeyedIdentity } from '../src/lib/wiring.js';
import type { OrderExecution } from '../src/merchant/server.js';
import { ucpPlatformProfile, type UcpBackendRequest } from '../src/commerce/ucp.js';

const directories: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  directories.splice(0).forEach(dir => fs.rmSync(dir, { recursive: true, force: true }));
});
async function identity(): Promise<KeyedIdentity> {
  const keys = await new NodeCryptoProvider().generateKeyPair();
  const did = generateDidKeyFromBase64(keys.publicKey);
  return { did, kid: `${did}#${did.slice(8)}`, privateKeyBase64: keys.privateKey, publicKeyBase64: keys.publicKey };
}

async function fixture(challengeOnly = false) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ucp-receipt-recovery-')); directories.push(directory);
  const [owner, merchant] = await Promise.all([identity(), identity()]);
  const origin = 'https://merchant.example';
  const profile = `${origin}/agent/.well-known/ucp`;
  const scope = 'https://id.gs1.org/01/09506000134352';
  const rail = new X402Rail({ mode: 'sandbox' });
  const journal = new CommerceJournal(path.join(directory, 'journal.json'));
  const generator = new ProofGenerator({ did: merchant.did, kid: merchant.kid, privateKey: merchant.privateKeyBase64, publicKey: merchant.publicKeyBase64 }, new NodeCryptoProvider());
  const signResult = async (args: Record<string, unknown>, body: Record<string, unknown>): Promise<MerchantToolResult> => {
    const result: MerchantToolResult = { content: [{ type: 'text', text: JSON.stringify(body) }] };
    const now = Date.now();
    const { _kyaos_delegation: ignored, ...challengeArgs } = args;
    const challenge = body['error'] === 'needs_authorization';
    const proof = await generator.generateProof(challenge ? { method: 'place_order', params: challengeArgs } : toHolderBindingRequest('place_order', args), { data: result.content },
      { sessionId: 'receipt-fixture', audience: merchant.did, nonce: 'session-nonce', timestamp: now, createdAt: now, lastActivity: now, ttlMinutes: 30, identityState: 'anonymous' },
      { outcome: challenge ? 'needs_authorization' : 'allowed' });
    result._meta = { [KYA_OS_PROOF_META_KEY]: proof };
    return result;
  };
  const authorize = vi.fn(async (args: Record<string, unknown>, execute?: OrderExecution) => {
    if (challengeOnly) {
      const url = new URL('https://rp.example/consent');
      Object.entries({ resume_token: 'same-consent-token', agent_did: owner.did, tool: 'place_order', scopes: scope }).forEach(([key, value]) => url.searchParams.set(key, value));
      return signResult(args, { error: 'needs_authorization', message: 'Approve this grant.', resumeToken: 'same-consent-token', authorizationUrl: url.href,
        expiresAt: Math.floor(Date.now() / 1000) + 600, scopes: [scope] });
    }
    const effect = await execute!({ vc: { credentialSubject: { id: owner.did } } as never,
      outcome: { ok: true, quantity: 2, total: 'CHF 39.80', currency: 'CHF', item: { uri: scope, unitPrice: '19.90' } } as never,
      evidence: { merchant: { did: merchant.did }, order: { quantity: 2, total: 'CHF 39.80' } },
    });
    return signResult(args, effect.body);
  });
  const coordinator = new PaymentCoordinator({ journal, rail, authorize, origin });
  const backend = createUcpBackend({ coordinator, merchantDid: merchant.did, origin, signResult });
  const record = await coordinator.prepare({ id: 'delayed-receipt', owner: owner.did, product: 'risotto', quantity: 2, protocol: 'ucp', rail: 'sandbox-token' });
  await coordinator.confirm(record.id, record.reviewToken, record.termsDigest);
  const token = await coordinator.tokenize(record.id, owner.did);
  const body = { payment: { instruments: [{ id: 'payment-fixture', handler_id: 'kya_sandbox_token', type: 'sandbox-token', credential: { type: 'sandbox-token', token } }] } };
  const cleanArgs = { product: record.product, quantity: record.quantity, checkout: { id: record.id, protocol: 'ucp', termsDigest: record.termsDigest } };
  const makeRequest = async (idempotencyKey = 'same-completion') => {
    const proof = await signMessage('place_order', cleanArgs, owner, merchant.did);
    const args = { ...cleanArgs, _kyaos_proof: proof.proof };
    const binding = { id: record.id, body, idempotencyKey, profile };
    const requestProof = await signMessage('ucp.complete', binding, owner, merchant.did);
    const request: UcpBackendRequest = {
      operation: 'complete', id: record.id, body, rawBody: JSON.stringify(body), requestId: crypto.randomUUID(), idempotencyKey,
      headers: { 'x-kya-request': Buffer.from(JSON.stringify(requestProof)).toString('base64'), 'x-kya-order': Buffer.from(JSON.stringify({ args })).toString('base64') },
      platform: { url: profile, profile: ucpPlatformProfile(origin), handlers: ['sandbox-token'] },
    };
    return { request, args };
  };
  const expected = { merchantDid: merchant.did, agentDid: owner.did, consentOrigin: 'https://rp.example', scope };
  return { backend, coordinator, journal, authorize, makeRequest, expected };
}

it('recovers completed receipts after proof and grant expiry without authorizing or settling again', async () => {
  const { backend, journal, authorize, makeRequest, expected } = await fixture();
  const verify = createOrderResponseVerifier();
  const first = await makeRequest();
  const original = await backend.execute(first.request);
  if (!('checkout' in original)) throw new Error(JSON.stringify(original));
  const receipt = original.checkout.kya?.['result'] as MerchantToolResult;
  await expect(verify(receipt, { ...expected, args: first.args })).resolves.toBeNull();

  // The first HTTP response was lost. Grant expiry or revocation must not
  // prevent the owner from retrieving the already committed historical order.
  vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 900_000);
  authorize.mockRejectedValue(new Error('Grant has since expired or been revoked'));
  for (const key of ['same-completion', 'new-recovery-key']) {
    const retried = await makeRequest(key);
    const recovered = await backend.execute(retried.request);
    if (!('checkout' in recovered)) throw new Error(JSON.stringify(recovered));
    const recoveredReceipt = recovered.checkout.kya?.['result'] as MerchantToolResult;
    expect(recovered.checkout.order?.id).toBe(original.checkout.order?.id);
    expect(responseBody(recoveredReceipt)).toEqual(responseBody(receipt));
    await expect(verify(recoveredReceipt, { ...expected, args: retried.args })).resolves.toBeNull();
  }
  expect(authorize).toHaveBeenCalledOnce();
  expect(Object.values(journal.read().records).filter(entry => entry.state === 'settled')).toHaveLength(1);
  expect(Object.keys(journal.read().payments)).toHaveLength(1);
});

it('refreshes a cached consent proof for the fresh holder request while retaining its original challenge', async () => {
  const { backend, authorize, makeRequest, expected, journal } = await fixture(true);
  const verify = createOrderResponseVerifier();
  const original = await makeRequest();
  const first = await backend.execute(original.request);
  if (!('checkout' in first)) throw new Error(JSON.stringify(first));
  const receipt = first.checkout.kya?.['result'] as MerchantToolResult;
  await expect(verify(receipt, { ...expected, args: original.args })).resolves.toMatchObject({ error: 'needs_authorization' });
  const retry = await makeRequest();
  const recovered = await backend.execute(retry.request);
  if (!('checkout' in recovered)) throw new Error(JSON.stringify(recovered));
  const freshReceipt = recovered.checkout.kya?.['result'] as MerchantToolResult;
  expect(responseBody(freshReceipt)).toEqual(responseBody(receipt));
  await expect(verify(freshReceipt, { ...expected, args: retry.args })).resolves.toMatchObject({ error: 'needs_authorization' });
  expect(authorize).toHaveBeenCalledOnce();
  expect(Object.keys(journal.read().payments)).toHaveLength(0);
});

it('does not fresh-sign a cached receipt with a forged inner order proof', async () => {
  const { backend, authorize, makeRequest } = await fixture();
  await backend.execute((await makeRequest()).request);
  const retry = await makeRequest();
  const forgedArgs = { ...retry.args, _kyaos_proof: { ...retry.args._kyaos_proof, jws: 'forged-signature' } };
  retry.request.headers['x-kya-order'] = Buffer.from(JSON.stringify({ args: forgedArgs })).toString('base64');
  const result = await backend.execute(retry.request);
  expect(result).not.toHaveProperty('checkout');
  expect(authorize).toHaveBeenCalledOnce();
});

it('returns an explicit expired-consent refusal instead of refreshing an unusable challenge', async () => {
  const { backend, authorize, makeRequest, journal } = await fixture(true);
  await backend.execute((await makeRequest()).request);
  vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 601_000);
  const recovered = await backend.execute((await makeRequest()).request);
  expect(recovered).toMatchObject({ checkout: { status: 'incomplete', messages: [{ code: 'CONSENT_EXPIRED' }] } });
  if (!('checkout' in recovered)) throw new Error(JSON.stringify(recovered));
  expect(recovered.checkout.continueUrl).toBeUndefined();
  expect(responseBody(recovered.checkout.kya?.['result'] as MerchantToolResult)).toMatchObject({ error: 'CONSENT_EXPIRED' });
  expect(authorize).toHaveBeenCalledOnce();
  expect(Object.keys(journal.read().payments)).toHaveLength(0);
});
