/** Agent-owned wallet and durable checkout retries. No payment secrets reach the LLM. */
import fs from 'node:fs';
import { randomUUID } from 'node:crypto';
import { generatePrivateKey } from 'viem/accounts';
import type { PaymentRequired } from '@x402/core/types';
import { createX402Payment } from '../payments/x402-client.js';
import { X402_ASSET, X402_NETWORK, X402_SANDBOX_PAY_TO } from '../payments/x402.js';
import { writeJsonAtomic } from '../lib/atomic-json.js';
import { ConsentProtocol, signMessage, type SignedMessage } from '../lib/consent-protocol.js';
import { findCatalogItem, toMinor } from '../lib/product.js';
import { loadAgentIdentity, merchantOrigin, requiredEnv, type KeyedIdentity } from '../lib/wiring.js';
import { UCP_CHECKOUT, UCP_DELEGATION, UCP_HANDLER_IDS, UCP_VERSION } from '../commerce/ucp.js';
import { acceptMerchantOrderResult, performAgentOrder, prepareAgentOrder, serializeAgentOperation, type AgentOrderOptions, type AgentOrderOutcome } from './agent.js';
import { responseBody, type MerchantToolResult } from './authorization.js';
import { AGENT_PAYMENT_WALLET_FILE, readAgentCheckout, readAgentCheckouts, saveAgentCheckout, type AgentCheckout } from './store.js';

export interface AgentCommerceOptions extends Omit<AgentOrderOptions, 'checkout' | 'payment' | 'forge'> {
  paymentProtocol: 'x402' | 'ucp';
  paymentMethod?: 'x402' | 'sandbox-token';
  checkoutId?: string;
}
const dict = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
function configuredMode(): 'sandbox' | 'testnet' {
  const mode = process.env['PAYMENT_MODE'] ?? 'sandbox';
  if (mode !== 'sandbox' && mode !== 'testnet') throw new Error('Unsupported payment environment');
  return mode;
}
function recipient(): string {
  return process.env['X402_PAY_TO'] || (configuredMode() === 'sandbox' ? X402_SANDBOX_PAY_TO : requiredEnv('X402_PAY_TO'));
}
function walletKey(): `0x${string}` {
  if (configuredMode() === 'testnet') {
    const key = requiredEnv('AGENT_EVM_PRIVATE_KEY');
    if (!/^0x[0-9a-fA-F]{64}$/.test(key)) throw new Error('AGENT_EVM_PRIVATE_KEY must be an EVM private key');
    return key as `0x${string}`;
  }
  if (fs.existsSync(AGENT_PAYMENT_WALLET_FILE)) {
    const wallet: unknown = JSON.parse(fs.readFileSync(AGENT_PAYMENT_WALLET_FILE, 'utf8'));
    if (!dict(wallet) || wallet['mode'] !== 'sandbox' || typeof wallet['privateKey'] !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(wallet['privateKey'])) throw new Error('AGENT_PAYMENT_WALLET_INVALID');
    return wallet['privateKey'] as `0x${string}`;
  }
  const privateKey = generatePrivateKey();
  writeJsonAtomic(AGENT_PAYMENT_WALLET_FILE, { mode: 'sandbox', privateKey });
  return privateKey;
}
function asOutcome(result: MerchantToolResult, attempt: AgentCheckout, agentDid = ''): AgentOrderOutcome {
  return { result, checkoutId: attempt.remoteId ?? attempt.id, elapsedMs: 0, agentDid, presented: { product: attempt.product, quantity: attempt.quantity, credentialId: null, audience: attempt.audience } };
}
function localResult(body: Record<string, unknown>, isError = false): MerchantToolResult {
  return { ...(isError ? { isError: true } : {}), content: [{ type: 'text', text: JSON.stringify(body) }] };
}
function getAttempt(options: AgentCommerceOptions): AgentCheckout {
  const origin = new URL(process.env['MERCHANT_ORIGIN'] || options.serverUrl || merchantOrigin()).origin;
  const audience = options.audience ?? requiredEnv('MERCHANT_DID');
  const rail = options.paymentMethod ?? 'x402';
  if (!['x402', 'ucp'].includes(options.paymentProtocol) || !['x402', 'sandbox-token'].includes(rail)
    || (options.paymentProtocol === 'x402' && rail !== 'x402')) throw new Error('PAYMENT_RAIL_UNSUPPORTED');
  const quantity = options.quantity ?? 1;
  if (!Number.isSafeInteger(quantity) || quantity < 1 || quantity > 999) throw new Error('INVALID_QUANTITY');
  const same = (a: AgentCheckout) => a.product === options.product && a.quantity === quantity && a.protocol === options.paymentProtocol
    && a.rail === rail && a.merchantOrigin === origin && a.audience === audience;
  const previous = options.checkoutId ? readAgentCheckout(options.checkoutId)
    : Object.values(readAgentCheckouts()).reverse().find(a => same(a) && ['open', 'submitted', 'pending'].includes(a.state));
  if (previous) {
    if (!same(previous)) throw new Error('CHECKOUT_BINDING_MISMATCH: retry the same products, quantity, protocol and merchant');
    return previous;
  }
  if (options.checkoutId) throw new Error('CHECKOUT_NOT_FOUND: this agent does not own that checkout');
  const attempt: AgentCheckout = { id: randomUUID(), protocol: options.paymentProtocol, rail, product: options.product, quantity, merchantOrigin: origin, audience, state: 'open' };
  saveAgentCheckout(attempt);
  return attempt;
}

/** Validate the merchant's authenticated quote against locally pinned wallet policy. */
function validatePaymentQuote(input: unknown, attempt: AgentCheckout): { required: PaymentRequired; termsDigest: string; maxAtomicAmount: string } {
  if (!dict(input) || input['x402Version'] !== 2 || !Array.isArray(input['accepts']) || input['accepts'].length !== 1
    || !dict(input['resource']) || !dict(input['extensions'])) throw new Error('PAYMENT_QUOTE_INVALID');
  const requirement = input['accepts'][0];
  const advertised = input['extensions']['org.kya-os/checkout'];
  if (!dict(advertised) || !dict(advertised['info']) || !dict(advertised['schema'])) throw new Error('PAYMENT_QUOTE_EXTENSION_INVALID');
  const extension = advertised['info'];
  const id = attempt.remoteId ?? attempt.id;
  if (!dict(requirement) || !dict(extension) || !dict(extension['pricing']) || extension['id'] !== id || typeof extension['termsDigest'] !== 'string'
    || !extension['termsDigest'] || extension['mode'] !== configuredMode()
    || input['resource']['url'] !== `${attempt.merchantOrigin}/payments/checkouts/${id}`
    || requirement['network'] !== X402_NETWORK || requirement['asset'] !== X402_ASSET
    || typeof requirement['payTo'] !== 'string' || requirement['payTo'].toLowerCase() !== recipient().toLowerCase()) throw new Error('PAYMENT_QUOTE_BINDING_MISMATCH');
  const pricing = extension['pricing'];
  const item = findCatalogItem(attempt.product);
  const rate = process.env['X402_ATOMIC_UNITS_PER_CHF_CENT'] ?? '10000';
  if (!item || item.currency !== 'CHF' || !/^[1-9]\d{0,77}$/.test(rate)) throw new Error('PAYMENT_QUOTE_CURRENCY_MISMATCH');
  const minor = toMinor(item.unitPrice) * BigInt(attempt.quantity);
  const expected = (minor * BigInt(rate)).toString();
  if (pricing['kind'] !== 'fixed-demo-rate' || pricing['currency'] !== 'CHF' || pricing['amountMinor'] !== minor.toString()
    || pricing['atomicUnitsPerChfCent'] !== rate || pricing['amountAtomic'] !== expected || requirement['amount'] !== expected) throw new Error('PAYMENT_QUOTE_AMOUNT_MISMATCH');
  if (attempt.termsDigest && attempt.termsDigest !== extension['termsDigest']) throw new Error('PAYMENT_QUOTE_CHANGED: prepare and review a new checkout');
  return { required: input as unknown as PaymentRequired, termsDigest: extension['termsDigest'], maxAtomicAmount: expected };
}

function recordOutcome(attempt: AgentCheckout, result: MerchantToolResult): void {
  const body = responseBody(result);
  attempt.lastResult = result;
  if (body['ok'] === true && typeof body['orderId'] === 'string') attempt.state = 'completed';
  else if (body['error'] === 'SETTLEMENT_PENDING') attempt.state = 'pending';
  else if (body['error'] && !['needs_authorization', 'CHECKOUT_CONFIRMATION_REQUIRED'].includes(String(body['error']))) attempt.state = 'failed';
  else attempt.state = 'open';
  saveAgentCheckout(attempt);
}
export function runAgentCommerce(options: AgentCommerceOptions): Promise<AgentOrderOutcome> {
  return serializeAgentOperation(async () => {
    const attempt = getAttempt(options);
    if (attempt.state === 'pending' && options.checkoutId) return refreshPaymentStatus(options, attempt);
    if ((attempt.state === 'pending' || attempt.state === 'completed') && attempt.lastResult) return asOutcome(attempt.lastResult, attempt);
    if (attempt.state === 'submitted') {
      const recovered = await refreshPaymentStatus(options, attempt, true);
      if (recovered) return recovered;
      // Only a fresh, authenticated open state proves that this durable
      // checkout has not submitted payment. Reuse its existing authorization.
    }
    const outcome = await (attempt.protocol === 'x402' ? runX402(options, attempt) : runUcp(options, attempt));
    return { ...outcome, checkoutId: attempt.remoteId ?? attempt.id };
  });
}
const paymentStatusVerifier = new ConsentProtocol();
/** Recovery reads the merchant's durable result. It does not need a current
 * grant and never sends a payment authorization or invokes settlement again. */
function refreshPaymentStatus(options: AgentCommerceOptions, attempt: AgentCheckout): Promise<AgentOrderOutcome>;
function refreshPaymentStatus(options: AgentCommerceOptions, attempt: AgentCheckout, resumeIfOpen: true): Promise<AgentOrderOutcome | null>;
async function refreshPaymentStatus(options: AgentCommerceOptions, attempt: AgentCheckout, resumeIfOpen = false): Promise<AgentOrderOutcome | null> {
  const identity = options.identity ?? loadAgentIdentity();
  const id = attempt.remoteId ?? attempt.id;
  if (!attempt.termsDigest) throw new Error('PAYMENT_STATUS_BINDING_MISSING');
  const request = await signMessage('payment.status', { id }, identity, attempt.audience);
  const response = await fetch(`${attempt.merchantOrigin}/payments/checkouts/${encodeURIComponent(id)}`, {
    method: 'GET', redirect: 'error', signal: AbortSignal.timeout(10_000),
    headers: { Accept: 'application/json', 'X-KYA-Request': Buffer.from(JSON.stringify(request)).toString('base64') },
  });
  if (!response.ok) throw new Error('PAYMENT_STATUS_UNAVAILABLE: retain this checkout and inspect its existing payment');
  const message = await response.json() as SignedMessage;
  const status = await paymentStatusVerifier.verify('payment.status.result', message, attempt.audience, identity.did);
  if (status['id'] !== id || status['protocol'] !== attempt.protocol || status['termsDigest'] !== attempt.termsDigest
    || status['requestNonce'] !== request.proof.meta.nonce) throw new Error('PAYMENT_STATUS_BINDING_MISMATCH');
  if (status['state'] === 'open' && resumeIfOpen) return null;
  let body: Record<string, unknown>;
  if (status['state'] === 'settled') {
    if (!dict(status['result']) || status['result']['ok'] !== true || typeof status['result']['orderId'] !== 'string'
      || status['result']['checkoutId'] !== id || status['result']['termsDigest'] !== attempt.termsDigest) throw new Error('PAYMENT_STATUS_RESULT_INVALID');
    body = status['result'];
  } else if (['open', 'settling'].includes(String(status['state']))) {
    body = { error: 'SETTLEMENT_PENDING', checkoutId: id,
      message: 'The existing payment is still unresolved. Retry this checkout_id to check status; do not start another payment.' };
  } else if (['failed', 'canceled'].includes(String(status['state']))) {
    body = { error: status['state'] === 'canceled' ? 'CHECKOUT_CANCELED' : 'PAYMENT_FAILED', checkoutId: id,
      message: 'The merchant has closed this checkout without an order.' };
  } else throw new Error('PAYMENT_STATUS_STATE_INVALID');
  const result = localResult(body, Boolean(body['error']));
  // Keep the actual signed status envelope with the recovered historical
  // result, without presenting it as a new place_order decision or effect.
  result._meta = { 'org.kya-os/payment-status': message };
  recordOutcome(attempt, result);
  return asOutcome(result, attempt, identity.did);
}
async function signQuote(required: unknown, attempt: AgentCheckout): Promise<void> {
  const quote = validatePaymentQuote(required, attempt);
  attempt.termsDigest = quote.termsDigest;
  attempt.paymentRequired = quote.required;
  if (!attempt.payload) {
    try { attempt.payload = await createX402Payment(quote.required, { privateKey: walletKey(), payTo: recipient(), maxAtomicAmount: quote.maxAtomicAmount }); }
    catch { throw new Error('PAYMENT_SIGNING_FAILED: check the agent wallet configuration and approved quote'); }
  }
  saveAgentCheckout(attempt);
}
async function runX402(options: AgentCommerceOptions, attempt: AgentCheckout): Promise<AgentOrderOutcome> {
  if (!attempt.payload) {
    const initial = await performAgentOrder({ ...options, checkout: { id: attempt.id, protocol: 'x402' } });
    const body = responseBody(initial.result);
    if (body['x402Version'] !== 2) { recordOutcome(attempt, initial.result); return initial; }
    await signQuote(body, attempt);
  }
  // Persist BEFORE network I/O. Lost replies reuse exactly this payload/id.
  attempt.state = 'submitted';
  saveAgentCheckout(attempt);
  const paid = await performAgentOrder({ ...options, checkout: { id: attempt.id, protocol: 'x402', termsDigest: attempt.termsDigest }, payment: attempt.payload });
  recordOutcome(attempt, paid.result);
  return paid;
}

async function ucpRequest(attempt: AgentCheckout, identity: KeyedIdentity, operation: 'create' | 'get' | 'complete', body: Record<string, unknown>, idempotencyKey?: string, args?: Record<string, unknown>): Promise<Record<string, unknown>> {
  const profile = `${attempt.merchantOrigin}/agent/.well-known/ucp`;
  const id = operation === 'create' ? null : attempt.remoteId!;
  const message = await signMessage(`ucp.${operation}`, { id, body, idempotencyKey: idempotencyKey ?? null, profile }, identity, attempt.audience);
  const route = operation === 'create' ? '/ucp/checkout-sessions' : `/ucp/checkout-sessions/${encodeURIComponent(id!)}${operation === 'complete' ? '/complete' : ''}`;
  const response = await fetch(`${attempt.merchantOrigin}${route}`, { method: operation === 'get' ? 'GET' : 'POST', redirect: 'error', signal: AbortSignal.timeout(60_000),
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'UCP-Agent': `profile="${profile}"`, 'Request-Id': randomUUID(),
      'X-KYA-Request': Buffer.from(JSON.stringify(message)).toString('base64'), ...(idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}),
      ...(args ? { 'X-KYA-Order': Buffer.from(JSON.stringify({ args })).toString('base64') } : {}) },
    ...(operation === 'get' ? {} : { body: JSON.stringify(body) }),
  });
  const reply: unknown = await response.json();
  if (!dict(reply)) throw new Error('UCP_RESPONSE_INVALID');
  if (!response.ok) throw new Error(`UCP_REQUEST_FAILED: ${String(reply['code'] ?? response.status)}`);
  if (!dict(reply['ucp']) || reply['ucp']['version'] !== UCP_VERSION || !dict(reply['ucp']['capabilities'])
    || !Array.isArray(reply['ucp']['capabilities'][UCP_DELEGATION]) || !Array.isArray(reply['ucp']['capabilities'][UCP_CHECKOUT])) throw new Error('UCP_NEGOTIATION_FAILED');
  if (typeof reply['id'] !== 'string' || !/^[a-zA-Z0-9_-]{1,100}$/.test(reply['id']) || (id && reply['id'] !== id)) throw new Error('UCP_CHECKOUT_BINDING_MISMATCH');
  return reply;
}
function ucpIntent(view: Record<string, unknown>, attempt: AgentCheckout): NonNullable<AgentCheckout['intent']> {
  const kya = view['kya'];
  const intent = dict(kya) ? kya['intent'] : null;
  const item = findCatalogItem(attempt.product);
  if (!dict(intent) || !item || intent['product'] !== item.sku || intent['quantity'] !== attempt.quantity || !dict(intent['checkout'])
    || intent['checkout']['id'] !== attempt.remoteId || intent['checkout']['protocol'] !== 'ucp' || typeof intent['checkout']['termsDigest'] !== 'string') throw new Error('UCP_INTENT_MISMATCH');
  return intent as unknown as NonNullable<AgentCheckout['intent']>;
}
function handoff(view: Record<string, unknown>, attempt: AgentCheckout): AgentOrderOutcome {
  const url = new URL(String(view['continue_url']));
  if (url.origin !== attempt.merchantOrigin || url.pathname !== `/checkout/${attempt.remoteId}` || url.username || url.password || url.hash) throw new Error('UCP_UNTRUSTED_CONTINUE_URL');
  return asOutcome(localResult({ status: 'requires_escalation', checkoutId: attempt.remoteId, protocol: 'ucp', paymentMethod: attempt.rail,
    continue_url: url.href, message: 'Open this merchant checkout and have the human confirm the exact purchase. Then retry place_order with this checkout_id. No payment or order has been made.' }), attempt);
}
async function runUcp(options: AgentCommerceOptions, attempt: AgentCheckout): Promise<AgentOrderOutcome> {
  const prepared = await prepareAgentOrder(options);
  if (prepared.pendingResult) return asOutcome(prepared.pendingResult, attempt, prepared.identity.did);
  if (!prepared.credential) {
    // This authority preflight cannot charge or place an order: the no-grant
    // KYA gate returns a human-consent challenge before the payment handler.
    return performAgentOrder({ ...options, checkout: { id: `auth-${attempt.id}`, protocol: 'x402' } });
  }
  const identity = prepared.identity;
  // Read the public business profile before presenting payment capabilities.
  const discovery = await fetch(`${attempt.merchantOrigin}/.well-known/ucp`, { redirect: 'error', signal: AbortSignal.timeout(8000) });
  const profile: unknown = await discovery.json();
  const ucp = dict(profile) && dict(profile['ucp']) ? profile['ucp'] : null;
  const services = ucp && dict(ucp['services']) ? ucp['services']['dev.ucp.shopping'] : null;
  const capabilities = ucp && dict(ucp['capabilities']) ? ucp['capabilities'] : null;
  const handlers = ucp && dict(ucp['payment_handlers']) ? ucp['payment_handlers'] : null;
  if (!discovery.ok || ucp?.['version'] !== UCP_VERSION || !Array.isArray(services)
    || !services.some(s => dict(s) && s['version'] === UCP_VERSION && s['transport'] === 'rest' && s['endpoint'] === `${attempt.merchantOrigin}/ucp`)
    || !capabilities || ![UCP_CHECKOUT, UCP_DELEGATION].every(k => Array.isArray(capabilities[k]) && capabilities[k].some((c: unknown) => dict(c) && c['version'] === UCP_VERSION))
    || !handlers || !Array.isArray(handlers[`org.kya-os.${attempt.rail}`])) throw new Error('UCP_NEGOTIATION_FAILED');
  let view: Record<string, unknown>;
  if (!attempt.remoteId) {
    attempt.createKey ??= randomUUID(); saveAgentCheckout(attempt);
    view = await ucpRequest(attempt, identity, 'create', { line_items: [{ item: { id: attempt.product }, quantity: attempt.quantity }], kya: { rail: attempt.rail } }, attempt.createKey);
    attempt.remoteId = String(view['id']); saveAgentCheckout(attempt);
  } else view = await ucpRequest(attempt, identity, 'get', {});
  const intent = ucpIntent(view, attempt);
  if (attempt.termsDigest && attempt.termsDigest !== intent.checkout.termsDigest) throw new Error('UCP_TERMS_CHANGED: create and review a new checkout');
  attempt.intent = intent; attempt.termsDigest = intent.checkout.termsDigest; saveAgentCheckout(attempt);
  const kya = view['kya'] as Record<string, unknown>;
  if (view['status'] === 'requires_escalation') return handoff(view, attempt);
  if (view['status'] === 'complete_in_progress') {
    attempt.state = 'pending'; attempt.lastResult = localResult({ error: 'SETTLEMENT_PENDING', checkoutId: attempt.remoteId, message: 'Payment is unresolved. Do not start another payment.' }, true); saveAgentCheckout(attempt);
    return asOutcome(attempt.lastResult, attempt);
  }
  if (view['status'] === 'completed') {
    // A lost complete response is recovered by replaying the same complete
    // operation below, receiving a fresh signed merchant receipt from the backend.
    if (!attempt.completeKey) throw new Error('UCP_UNEXPECTED_COMPLETION');
  } else if (view['status'] !== 'ready_for_complete') throw new Error(`UCP_CHECKOUT_NOT_READY: ${String(view['status'])}`);
  let credential: Record<string, unknown>;
  if (attempt.rail === 'x402') {
    await signQuote(kya['payment_required'], attempt);
    credential = { type: 'x402', payload: attempt.payload };
  } else {
    if (!attempt.token) {
      const signed = await signMessage('payment.tokenize', { id: attempt.remoteId }, identity, attempt.audience);
      const response = await fetch(`${attempt.merchantOrigin}/payments/sandbox/tokenize`, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10_000),
        headers: { 'Content-Type': 'application/json', 'X-KYA-Request': Buffer.from(JSON.stringify(signed)).toString('base64') }, body: JSON.stringify({ id: attempt.remoteId }) });
      const body: unknown = await response.json();
      if (!response.ok || !dict(body) || typeof body['token'] !== 'string' || !body['token'].startsWith('sandbox_')) throw new Error('SANDBOX_TOKEN_UNAVAILABLE');
      attempt.token = body['token']; saveAgentCheckout(attempt);
    }
    credential = { type: 'sandbox-token', token: attempt.token };
  }
  const completion = await prepareAgentOrder({ ...options, product: intent.product, quantity: intent.quantity, checkout: intent.checkout });
  if (completion.pendingResult) return asOutcome(completion.pendingResult, attempt, identity.did);
  attempt.completeKey ??= randomUUID(); attempt.state = 'submitted'; saveAgentCheckout(attempt);
  const completed = await ucpRequest(attempt, identity, 'complete', { payment: { instruments: [{ id: `${attempt.rail}-${attempt.remoteId}`, handler_id: UCP_HANDLER_IDS[attempt.rail], type: attempt.rail, credential }] } }, attempt.completeKey, completion.args!);
  const completedKya = completed['kya'];
  if (!dict(completedKya) || !dict(completedKya['result'])) throw new Error('UCP_MERCHANT_RECEIPT_MISSING');
  const result = completedKya['result'] as MerchantToolResult;
  await acceptMerchantOrderResult(result, completion.args!, identity, attempt.audience);
  recordOutcome(attempt, result);
  if (responseBody(result)['error'] && responseBody(result)['error'] !== 'SETTLEMENT_PENDING') {
    // A definitive refusal has no financial effect; the next business attempt
    // needs a fresh key. Unknown transport outcomes retain the previous key.
    delete attempt.completeKey; saveAgentCheckout(attempt);
  }
  return asOutcome(result, attempt, identity.did);
}
