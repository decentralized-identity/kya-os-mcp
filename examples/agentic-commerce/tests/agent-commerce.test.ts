import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { X402Rail, X402_SANDBOX_PAY_TO } from '../src/payments/x402.js';
import type { AgentOrderOptions } from '../src/agent/agent.js';
import { generateDidKeyFromBase64, NodeCryptoProvider } from '@kya-os/mcp';
import { ucpBusinessProfile, UCP_HANDLER_IDS } from '../src/commerce/ucp.js';
import type { KeyedIdentity } from '../src/lib/wiring.js';

const { order, prepare, accept } = vi.hoisted(() => ({ order: vi.fn(), prepare: vi.fn(), accept: vi.fn() }));
vi.mock('../src/agent/agent.js', async () => ({ ...(await vi.importActual('../src/agent/agent.js')), performAgentOrder: order, prepareAgentOrder: prepare, acceptMerchantOrderResult: accept }));
let commerce: typeof import('../src/agent/commerce.js');
let store: typeof import('../src/agent/store.js');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-commerce-'));
const merchant = 'http://127.0.0.1:43210';
const audience = 'did:key:merchant-test';
let identity: KeyedIdentity;
const input = { product: 'risotto', quantity: 2, serverUrl: `${merchant}/mcp`, audience, paymentProtocol: 'x402' as const };
const outcome = (body: Record<string, unknown>) => ({ result: { content: [{ type: 'text', text: JSON.stringify(body) }] }, elapsedMs: 1, agentDid: 'did:key:agent', presented: { product: 'risotto', quantity: 2, credentialId: 'vc:1', audience } });
beforeAll(async () => {
  vi.stubEnv('DEMO_VAR_DIR', dir);
  vi.stubEnv('PAYMENT_MODE', 'sandbox');
  vi.stubEnv('X402_PAY_TO', X402_SANDBOX_PAY_TO);
  vi.stubEnv('MERCHANT_ORIGIN', merchant);
  commerce = await import('../src/agent/commerce.js');
  store = await import('../src/agent/store.js');
  const key = await new NodeCryptoProvider().generateKeyPair();
  const did = generateDidKeyFromBase64(key.publicKey);
  identity = { did, kid: `${did}#${did.slice(8)}`, privateKeyBase64: key.privateKey, publicKeyBase64: key.publicKey };
});
beforeEach(() => {
  order.mockReset(); accept.mockReset(); prepare.mockReset(); vi.unstubAllGlobals();
  prepare.mockImplementation(async (options: AgentOrderOptions) => ({ identity, audience, credential: { id: 'vc:1' }, quantity: options.quantity ?? 1,
    args: { product: options.product, quantity: options.quantity ?? 1, ...(options.checkout ? { checkout: options.checkout } : {}), _kyaos_delegation: { id: 'vc:1' }, _kyaos_proof: { test: 'fresh-holder-proof' } }, pendingResult: null }));
  fs.rmSync(path.join(dir, 'agent'), { recursive: true, force: true });
});
afterAll(() => { fs.rmSync(dir, { recursive: true, force: true }); vi.unstubAllEnvs(); vi.unstubAllGlobals(); });
async function paymentRequired(id: string) {
  const rail = new X402Rail({ mode: 'sandbox' });
  const quote = await rail.createRequirements({ id, resource: `${merchant}/payments/checkouts/${id}`, amountMinor: '3980', currency: 'CHF' });
  return { ...quote.paymentRequired, error: 'PAYMENT_REQUIRED', extensions: { 'org.kya-os/checkout': {
    info: { id, termsDigest: 'sha256:exact-terms', pricing: quote.pricing, mode: 'sandbox' },
    schema: { type: 'object' },
  } } };
}

describe('agent payment orchestration', () => {
  it('persists an SDK-signed payload before the paid retry and binds the retry to the quoted terms', async () => {
    order.mockImplementation(async (options: AgentOrderOptions) => {
      const id = options.checkout!.id;
      if (!options.payment) return outcome(await paymentRequired(id));
      const stored = store.readAgentCheckouts()[id]!;
      expect(stored.payload).toEqual(options.payment);
      expect(stored.state).toBe('submitted');
      expect(options.checkout).toEqual({ id, protocol: 'x402', termsDigest: 'sha256:exact-terms' });
      return outcome({ ok: true, orderId: 'order-1', checkoutId: id, payment: { status: 'simulated' } });
    });
    const result = await commerce.runAgentCommerce(input);
    expect(result.result.content![0]!.text).toContain('order-1');
    expect(order).toHaveBeenCalledTimes(2);
    expect(Object.values(store.readAgentCheckouts())[0]!.state).toBe('completed');
    const wallet = fs.statSync(store.AGENT_PAYMENT_WALLET_FILE);
    expect(wallet.mode & 0o777).toBe(0o600);
  });

  it('reuses exactly the same checkout and signature after a lost paid response', async () => {
    const { signMessage } = await import('../src/lib/consent-protocol.js');
    const keys = await new NodeCryptoProvider().generateKeyPair();
    const did = generateDidKeyFromBase64(keys.publicKey);
    const merchantIdentity = { did, kid: `${did}#${did.slice(8)}`, privateKeyBase64: keys.privateKey, publicKeyBase64: keys.publicKey };
    const options = { ...input, audience: did, identity };
    let paid = 0;
    order.mockImplementation(async (options: AgentOrderOptions) => {
      if (!options.payment) return outcome(await paymentRequired(options.checkout!.id));
      if (++paid === 1) throw new Error('connection lost');
      return outcome({ ok: true, orderId: 'recovered-order', checkoutId: options.checkout!.id });
    });
    await expect(commerce.runAgentCommerce(options)).rejects.toThrow('connection lost');
    const before = structuredClone(Object.values(store.readAgentCheckouts())[0]!);
    const status = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(init?.method).toBe('GET');
      const request = JSON.parse(Buffer.from(new Headers(init?.headers).get('X-KYA-Request')!, 'base64').toString());
      return Response.json(await signMessage('payment.status.result', { id: before.id, state: 'open', protocol: 'x402',
        termsDigest: before.termsDigest, requestNonce: request.proof.meta.nonce }, merchantIdentity, identity.did));
    });
    vi.stubGlobal('fetch', status);
    await commerce.runAgentCommerce(options);
    expect(status).toHaveBeenCalledOnce();
    const paidCalls = order.mock.calls.map(([arg]) => arg as AgentOrderOptions).filter(arg => arg.payment);
    expect(paidCalls).toHaveLength(2);
    expect(paidCalls[1]!.payment).toEqual(before.payload);
    expect(paidCalls[1]!.checkout!.id).toBe(before.id);
  });

  it.each([404, 503])('does not resubmit or claim failure when a submitted checkout status returns HTTP %s', async status => {
    order.mockImplementation(async (options: AgentOrderOptions) => {
      if (!options.payment) return outcome(await paymentRequired(options.checkout!.id));
      throw new Error('connection lost after submission');
    });
    await expect(commerce.runAgentCommerce({ ...input, identity })).rejects.toThrow('connection lost');
    const before = structuredClone(Object.values(store.readAgentCheckouts())[0]!);
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ error: 'unavailable' }, { status })));
    await expect(commerce.runAgentCommerce({ ...input, identity, checkoutId: before.id })).rejects.toThrow('PAYMENT_STATUS_UNAVAILABLE');
    expect(store.readAgentCheckouts()[before.id]).toEqual(before);
    expect(order).toHaveBeenCalledTimes(2);
  });

  it('retains a pending settlement signature and refuses to silently start a new checkout', async () => {
    order.mockImplementation(async (options: AgentOrderOptions) => !options.payment
      ? outcome(await paymentRequired(options.checkout!.id))
      : outcome({ error: 'SETTLEMENT_PENDING', message: 'Reconcile before paying again' }));
    await commerce.runAgentCommerce(input);
    const old = structuredClone(Object.values(store.readAgentCheckouts())[0]!);
    await commerce.runAgentCommerce(input);
    expect(Object.values(store.readAgentCheckouts())).toHaveLength(1);
    expect(store.readAgentCheckouts()[old.id]!.payload).toEqual(old.payload);
    expect(store.readAgentCheckouts()[old.id]!.state).toBe('pending');
  });

  it.each(['x402', 'ucp'] as const)('recovers %s pending status only on an explicit retry without another payment or grant lookup', async protocol => {
    const { signMessage, ConsentProtocol } = await import('../src/lib/consent-protocol.js');
    const keys = await new NodeCryptoProvider().generateKeyPair();
    const did = generateDidKeyFromBase64(keys.publicKey);
    const merchantIdentity = { did, kid: `${did}#${did.slice(8)}`, privateKeyBase64: keys.privateKey, publicKeyBase64: keys.publicKey };
    const id = `pending-${protocol}`;
    const attempt = { id, protocol, rail: 'x402' as const, product: 'risotto', quantity: 2, merchantOrigin: merchant, audience: did,
      state: 'pending' as const, termsDigest: 'sha256:exact-terms', ...(protocol === 'ucp' ? { remoteId: `ucp_${id}` } : {}),
      lastResult: outcome({ error: 'SETTLEMENT_PENDING' }).result };
    const remoteId = attempt.remoteId ?? id;
    store.saveAgentCheckout(attempt);
    let state = 'settling';
    const fetcher = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe(`${merchant}/payments/checkouts/${remoteId}`);
      expect(init?.method).toBe('GET');
      const request = JSON.parse(Buffer.from(new Headers(init?.headers).get('X-KYA-Request')!, 'base64').toString());
      expect(await new ConsentProtocol().verify('payment.status', request, identity.did, did)).toEqual({ id: remoteId });
      return Response.json(await signMessage('payment.status.result', {
        id: remoteId, state, protocol, termsDigest: attempt.termsDigest, requestNonce: request.proof.meta.nonce,
        ...(state === 'settled' ? { result: { ok: true, orderId: 'order-from-ledger', checkoutId: remoteId, termsDigest: attempt.termsDigest,
          order: { quantity: 2, total: 'CHF 39.80' }, payment: { status: 'simulated', simulated: true } } } : {}),
      }, merchantIdentity, identity.did));
    });
    vi.stubGlobal('fetch', fetcher);
    const options = { ...input, paymentProtocol: protocol, audience: did, identity };
    await commerce.runAgentCommerce(options);
    expect(fetcher).not.toHaveBeenCalled();
    const pending = await commerce.runAgentCommerce({ ...options, checkoutId: remoteId });
    expect(pending.result.content![0]!.text).toContain('SETTLEMENT_PENDING');
    expect(fetcher).toHaveBeenCalledTimes(1);
    state = 'settled';
    const completed = await commerce.runAgentCommerce({ ...options, checkoutId: remoteId });
    expect(completed.result.content![0]!.text).toContain('order-from-ledger');
    expect(store.readAgentCheckouts()[id]!.state).toBe('completed');
    expect(order).not.toHaveBeenCalled();
    expect(prepare).not.toHaveBeenCalled();
    expect(fs.existsSync(store.AGENT_PAYMENT_WALLET_FILE)).toBe(false);
  });

  it.each(['nonce', 'id', 'terms', 'protocol', 'signature'] as const)('rejects a substituted %s in an authenticated payment status', async attack => {
    const { signMessage } = await import('../src/lib/consent-protocol.js');
    const keys = await new NodeCryptoProvider().generateKeyPair();
    const did = generateDidKeyFromBase64(keys.publicKey);
    const merchantIdentity = { did, kid: `${did}#${did.slice(8)}`, privateKeyBase64: keys.privateKey, publicKeyBase64: keys.publicKey };
    const attempt = { id: 'pending-substitution', protocol: 'x402' as const, rail: 'x402' as const, product: 'risotto', quantity: 2,
      merchantOrigin: merchant, audience: did, state: 'pending' as const, termsDigest: 'sha256:exact-terms', lastResult: outcome({ error: 'SETTLEMENT_PENDING' }).result };
    store.saveAgentCheckout(attempt);
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
      const request = JSON.parse(Buffer.from(new Headers(init?.headers).get('X-KYA-Request')!, 'base64').toString());
      const message = await signMessage('payment.status.result', {
        id: attack === 'id' ? 'other-checkout' : attempt.id, state: 'settling',
        protocol: attack === 'protocol' ? 'ucp' : attempt.protocol, termsDigest: attack === 'terms' ? 'changed' : attempt.termsDigest,
        requestNonce: attack === 'nonce' ? 'other-request' : request.proof.meta.nonce,
      }, merchantIdentity, identity.did);
      if (attack === 'signature') message.body['state'] = 'settled';
      return Response.json(message);
    }));
    await expect(commerce.runAgentCommerce({ ...input, audience: did, identity, checkoutId: attempt.id })).rejects.toThrow(/PAYMENT_STATUS|CONSENT_PROTOCOL/);
    expect(store.readAgentCheckouts()[attempt.id]).toEqual(attempt);
    expect(order).not.toHaveBeenCalled();
    expect(prepare).not.toHaveBeenCalled();
  });

  it('returns human consent without creating a payment wallet or signature', async () => {
    order.mockResolvedValue(outcome({ error: 'needs_authorization', authorizationUrl: 'http://127.0.0.1:4950/consent?signed=1' }));
    const result = await commerce.runAgentCommerce(input);
    expect(result.result.content![0]!.text).toContain('needs_authorization');
    expect(fs.existsSync(store.AGENT_PAYMENT_WALLET_FILE)).toBe(false);
    expect(order).toHaveBeenCalledTimes(1);
  });

  it.each(['mode', 'recipient', 'amount', 'id', 'resource'] as const)('refuses an unsafe %s quote before signing', async attack => {
    order.mockImplementation(async (options: AgentOrderOptions) => {
      const required = await paymentRequired(options.checkout!.id);
      if (attack === 'mode') required.extensions['org.kya-os/checkout'].info.mode = 'testnet';
      if (attack === 'recipient') required.accepts[0]!.payTo = '0x0000000000000000000000000000000000000001';
      if (attack === 'amount') required.accepts[0]!.amount = '999999999999';
      if (attack === 'id') required.extensions['org.kya-os/checkout'].info.id = 'other';
      if (attack === 'resource') required.resource.url = 'https://attacker.example/pay';
      return outcome(required);
    });
    await expect(commerce.runAgentCommerce(input)).rejects.toThrow(/PAYMENT_QUOTE/);
    expect(fs.existsSync(store.AGENT_PAYMENT_WALLET_FILE)).toBe(false);
    expect(order).toHaveBeenCalledTimes(1);
  });

  it.each(['x402', 'sandbox-token'] as const)('hands UCP %s checkout to the human and submits bound completion only after review', async rail => {
    const remoteId = `ucp_${rail}`;
    const required = await paymentRequired(remoteId);
    const intent = { product: 'risotto', quantity: 2, checkout: { id: remoteId, protocol: 'ucp', termsDigest: 'sha256:exact-terms' } };
    let confirmed = false;
    let completeBody: Record<string, unknown> | undefined;
    const requestKeys: string[] = [];
    const fetcher = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith('/.well-known/ucp')) return Response.json(ucpBusinessProfile({ origin: merchant }));
      const headers = new Headers(init?.headers);
      const signed = JSON.parse(Buffer.from(headers.get('X-KYA-Request')!, 'base64').toString());
      expect(signed.proof.meta.did).toBe(identity.did);
      expect(signed.proof.meta.audience).toBe(audience);
      if (url.endsWith('/payments/sandbox/tokenize')) {
        expect(confirmed).toBe(true);
        expect(signed.body).toEqual({ id: remoteId });
        return Response.json({ token: 'sandbox_test-secret' });
      }
      expect(headers.get('UCP-Agent')).toBe(`profile="${merchant}/agent/.well-known/ucp"`);
      const body = init?.body ? JSON.parse(String(init.body)) : {};
      expect(signed.body).toEqual({ id: url.endsWith('/checkout-sessions') ? null : remoteId,
        body, idempotencyKey: headers.get('Idempotency-Key'), profile: `${merchant}/agent/.well-known/ucp` });
      if (headers.has('Idempotency-Key')) requestKeys.push(headers.get('Idempotency-Key')!);
      if (url.endsWith('/complete')) {
        expect(confirmed).toBe(true);
        completeBody = body;
        const signedOrder = JSON.parse(Buffer.from(headers.get('X-KYA-Order')!, 'base64').toString());
        expect(signedOrder.args).toMatchObject(intent);
        const saved = Object.values(store.readAgentCheckouts())[0]!;
        expect(saved.state).toBe('submitted');
        expect(saved.completeKey).toBe(headers.get('Idempotency-Key'));
        const result = outcome({ ok: true, orderId: `order-${remoteId}`, checkoutId: remoteId, payment: { status: 'simulated' } }).result;
        return Response.json({ ucp: ucpBusinessProfile({ origin: merchant }).ucp, id: remoteId, status: 'completed', kya: { intent, result } });
      }
      return Response.json({ ucp: ucpBusinessProfile({ origin: merchant }).ucp, id: remoteId, status: confirmed ? 'ready_for_complete' : 'requires_escalation',
        ...(confirmed ? {} : { continue_url: `${merchant}/checkout/${remoteId}?token=review-token` }), kya: { intent, payment_required: required } });
    });
    vi.stubGlobal('fetch', fetcher);
    const first = await commerce.runAgentCommerce({ ...input, paymentProtocol: 'ucp', paymentMethod: rail });
    expect(first.result.content![0]!.text).toContain('requires_escalation');
    expect(fetcher.mock.calls.every(([url]) => !url.includes('/complete') && !url.includes('/confirm'))).toBe(true);
    expect(fs.existsSync(store.AGENT_PAYMENT_WALLET_FILE)).toBe(false);
    confirmed = true; // The human, outside the agent, reviews the exact terms.
    const completed = await commerce.runAgentCommerce({ ...input, paymentProtocol: 'ucp', paymentMethod: rail, checkoutId: remoteId });
    expect(completed.result.content![0]!.text).toContain(`order-${remoteId}`);
    expect(completeBody).toMatchObject({ payment: { instruments: [{ handler_id: UCP_HANDLER_IDS[rail], type: rail, credential: { type: rail } }] } });
    expect(new Set(requestKeys).size).toBe(2);
    expect(accept).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(completed)).not.toContain('sandbox_test-secret');
  });
});
