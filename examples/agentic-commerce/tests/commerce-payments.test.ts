import { afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PaymentCoordinator } from '../src/commerce/payments.js';
import { CommerceJournal } from '../src/commerce/journal.js';
import { X402Rail } from '../src/payments/x402.js';
import { createX402Payment } from '../src/payments/x402-client.js';
import { privateKeyToAccount } from 'viem/accounts';
import type { OrderExecution } from '../src/merchant/server.js';
import type { FacilitatorClient } from '@x402/core/server';

const key = `0x${'1'.repeat(64)}` as const;
const owner = 'did:key:fixture-agent';
const directories: string[] = [];
afterEach(() => { vi.restoreAllMocks(); directories.splice(0).forEach(dir => fs.rmSync(dir, { recursive: true, force: true })); });
function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'commerce-payment-')); directories.push(dir);
  const rail = new X402Rail({ mode: 'sandbox' });
  const journal = new CommerceJournal(path.join(dir, 'journal.json'));
  let allowed = true;
  const authorize = async (_args: Record<string, unknown>, execute?: OrderExecution) => {
    if (!allowed) return { isError: true, content: [{ type: 'text', text: '{"error":"delegation_invalid","reason":"revoked"}' }] };
    const result = await execute!({ vc: { credentialSubject: { id: owner } } as never,
      outcome: { ok: true, quantity: 2, total: 'CHF 39.80', currency: 'CHF', item: { uri: 'https://id.gs1.org/01/09506000134352', unitPrice: '19.90' } } as never,
      evidence: { merchant: { did: 'did:key:merchant' }, order: { quantity: 2, total: 'CHF 39.80' } },
    });
    return { content: [{ type: 'text', text: JSON.stringify(result.body) }] };
  };
  const coordinator = new PaymentCoordinator({ journal, rail, authorize, origin: 'https://merchant.example' });
  return { coordinator, journal, rail, authorize, revoke: () => { allowed = false; } };
}
const argsFor = (record: Awaited<ReturnType<PaymentCoordinator['prepare']>>) => ({ product: record.product, quantity: record.quantity,
  checkout: { id: record.id, protocol: record.protocol, termsDigest: record.termsDigest } });
const body = (result: { content?: Array<{ text?: string }> }) => JSON.parse(result.content?.[0]?.text ?? '{}');
async function sign(record: Awaited<ReturnType<PaymentCoordinator['prepare']>>, rail: X402Rail) {
  return createX402Payment(record.quote.paymentRequired, { privateKey: key, payTo: rail.payTo, maxAtomicAmount: record.quote.requirements.amount });
}

describe('authority before rail effects and durable recovery', () => {
  it('preparation makes no payment; concurrent completed retries return the same order and settle once', async () => {
    const { coordinator, rail } = setup();
    const settle = vi.spyOn(rail, 'settle');
    const record = await coordinator.prepare({ owner, protocol: 'x402', product: 'risotto', quantity: 2, rail: 'x402', id: 'intent-1' });
    expect(settle).not.toHaveBeenCalled();
    const payment = await sign(record, rail);
    const results = await Promise.all([coordinator.complete(argsFor(record), payment), coordinator.complete(argsFor(record), payment)]);
    expect(settle).toHaveBeenCalledTimes(1);
    expect(body(results[0]).orderId).toBe(body(results[1]).orderId);
    expect(body(results[0]).payment.status).toBe('simulated');
    expect(body(results[0]).payment.response.transaction).toBe('');
    expect(JSON.stringify(body(results[0]))).not.toContain(privateKeyToAccount(key).address.toLowerCase() + key);
  });

  it('a valid payment with a revoked grant never reaches settlement', async () => {
    const { coordinator, rail, revoke } = setup();
    const settle = vi.spyOn(rail, 'settle');
    const record = await coordinator.prepare({ owner, protocol: 'x402', product: 'risotto', quantity: 2, rail: 'x402', id: 'intent-2' });
    const payment = await sign(record, rail);
    revoke();
    expect(body(await coordinator.complete(argsFor(record), payment)).reason).toBe('revoked');
    expect(settle).not.toHaveBeenCalled();
  });

  it('reserves the signed payment nonce across different checkouts and merchant restart', async () => {
    const { coordinator, rail, journal, authorize } = setup();
    const settle = vi.spyOn(rail, 'settle');
    const first = await coordinator.prepare({ owner, protocol: 'x402', product: 'risotto', quantity: 2, rail: 'x402', id: 'nonce-original' });
    const second = await coordinator.prepare({ owner, protocol: 'x402', product: 'risotto', quantity: 2, rail: 'x402', id: 'nonce-reuse' });
    const payment = await sign(first, rail);
    expect(body(await coordinator.complete(argsFor(first), payment))).toHaveProperty('orderId');

    // EIP-3009 authenticates the transfer, not the outer x402 resource URL.
    // Re-enveloping the same signed authorization must never buy a second order.
    const reused = { ...payment, resource: second.quote.paymentRequired.resource, accepted: second.quote.requirements };
    expect(await rail.verify(second.quote, reused)).toMatchObject({ isValid: true });
    const restarted = new PaymentCoordinator({ journal: new CommerceJournal(journal.file), rail, authorize, origin: 'https://merchant.example' });
    expect(body(await restarted.complete(argsFor(second), reused))).toMatchObject({ error: 'PAYMENT_REPLAY' });
    expect(settle).toHaveBeenCalledTimes(1);
    expect(restarted.get(second.id)?.state).toBe('open');
  });

  it('refuses checkout, quantity, protocol and terms substitution before settlement', async () => {
    const { coordinator, rail } = setup();
    const settle = vi.spyOn(rail, 'settle');
    const record = await coordinator.prepare({ owner, protocol: 'x402', product: 'risotto', quantity: 2, rail: 'x402', id: 'intent-3' });
    const payment = await sign(record, rail);
    for (const changed of [{ ...argsFor(record), quantity: 1 }, { ...argsFor(record), checkout: { ...argsFor(record).checkout, protocol: 'ucp' } }, { ...argsFor(record), checkout: { ...argsFor(record).checkout, termsDigest: 'changed' } }]) {
      expect(body(await coordinator.complete(changed, payment)).error).toBe('CHECKOUT_BINDING_MISMATCH');
    }
    expect(settle).not.toHaveBeenCalled();
  });

  it('holds an indeterminate payment across restart without creating a second authorization or order', async () => {
    const { coordinator, rail, journal, authorize } = setup();
    const settle = vi.spyOn(rail, 'settle').mockRejectedValue(new Error('response lost after broadcast'));
    const record = await coordinator.prepare({ owner, protocol: 'x402', product: 'risotto', quantity: 2, rail: 'x402', id: 'intent-4' });
    const payment = await sign(record, rail);
    expect(body(await coordinator.complete(argsFor(record), payment)).error).toBe('SETTLEMENT_PENDING');
    const restarted = new PaymentCoordinator({ journal: new CommerceJournal(journal.file), rail, authorize, origin: 'https://merchant.example' });
    expect(body(await restarted.complete(argsFor(record), payment)).error).toBe('SETTLEMENT_PENDING');
    expect(settle).toHaveBeenCalledTimes(1);
    expect(restarted.get(record.id)?.state).toBe('settling');
  });

  it('requires exact checkout confirmation for UCP and invalidates it when terms change', async () => {
    const { coordinator, rail } = setup();
    const settle = vi.spyOn(rail, 'settle');
    const record = await coordinator.prepare({ owner, protocol: 'ucp', product: 'risotto', quantity: 2, rail: 'x402', id: 'intent-5' });
    const payment = await sign(record, rail);
    expect(body(await coordinator.complete(argsFor(record), payment)).error).toBe('CHECKOUT_CONFIRMATION_REQUIRED');
    await coordinator.confirm(record.id, record.reviewToken, record.termsDigest);
    const updated = await coordinator.update(record.id, owner, { product: 'risotto', quantity: 1, rail: 'x402' });
    expect(updated.confirmedDigest).toBeUndefined();
    expect(updated.termsDigest).not.toBe(record.termsDigest);
    expect(settle).not.toHaveBeenCalled();
  });

  it('does not turn a sandbox-approved checkout into a testnet transfer after restart', async () => {
    const { coordinator, rail, journal, authorize } = setup();
    const record = await coordinator.prepare({ owner, protocol: 'ucp', product: 'risotto', quantity: 2, rail: 'x402', id: 'mode-bound-intent' });
    await coordinator.confirm(record.id, record.reviewToken, record.termsDigest);
    const payment = await sign(record, rail);
    const facilitator: FacilitatorClient = {
      verify: vi.fn(async () => ({ isValid: true })),
      settle: vi.fn<FacilitatorClient['settle']>(async () => ({ success: true, network: 'eip155:84532', transaction: `0x${'a'.repeat(64)}` })),
      getSupported: vi.fn(async () => ({ kinds: [], extensions: [], signers: {} })),
    };
    const testnetRail = new X402Rail({ mode: 'testnet', payTo: rail.payTo, facilitator });
    const restarted = new PaymentCoordinator({ journal: new CommerceJournal(journal.file), rail: testnetRail, authorize, origin: 'https://merchant.example' });
    expect(record.paymentMode).toBe('sandbox');
    expect(restarted.paymentRequired(record).extensions).toMatchObject({ 'org.kya-os/checkout': { info: { mode: 'sandbox' } } });
    expect(body(await restarted.complete(argsFor(record), payment))).toMatchObject({ error: 'PAYMENT_MODE_CHANGED' });
    expect(facilitator.verify).not.toHaveBeenCalled();
    expect(facilitator.settle).not.toHaveBeenCalled();
    expect(restarted.get(record.id)?.state).toBe('open');
    const newQuote = await restarted.prepare({ owner, protocol: 'ucp', product: 'risotto', quantity: 2, rail: 'x402', id: 'new-testnet-intent' });
    expect(newQuote.paymentMode).toBe('testnet');
    expect(newQuote.confirmedDigest).toBeUndefined();
  });

  it('the alternate sandbox token is checkout-bound and still needs the same authority gate', async () => {
    const { coordinator, revoke } = setup();
    const record = await coordinator.prepare({ owner, protocol: 'ucp', product: 'risotto', quantity: 2, rail: 'sandbox-token', id: 'intent-6' });
    await coordinator.confirm(record.id, record.reviewToken, record.termsDigest);
    const token = await coordinator.tokenize(record.id, owner);
    expect(body(await coordinator.complete(argsFor(record), 'forged-token')).error).toBe('PAYMENT_INVALID');
    revoke();
    expect(body(await coordinator.complete(argsFor(record), token)).reason).toBe('revoked');
    expect(coordinator.get(record.id)?.state).toBe('open');
  });

  it('recovers a lost tokenization response by replacing the token and commits only once', async () => {
    const { coordinator } = setup();
    const record = await coordinator.prepare({ owner, protocol: 'ucp', product: 'risotto', quantity: 2, rail: 'sandbox-token', id: 'token-response-lost' });
    await coordinator.confirm(record.id, record.reviewToken, record.termsDigest);
    const lostToken = await coordinator.tokenize(record.id, owner);
    const recoveredToken = await coordinator.tokenize(record.id, owner);
    expect(recoveredToken).not.toBe(lostToken);
    expect(body(await coordinator.complete(argsFor(record), lostToken))).toMatchObject({ error: 'PAYMENT_INVALID' });
    const original = body(await coordinator.complete(argsFor(record), recoveredToken));
    const retried = body(await coordinator.complete(argsFor(record), recoveredToken));
    expect(original.orderId).toEqual(expect.any(String));
    expect(retried.orderId).toBe(original.orderId);
    expect(original.payment.status).toBe('simulated');
  });

  it('rechecks authority after asynchronous audit work before the sandbox-token effect', async () => {
    const { journal, rail, authorize } = setup();
    let current = true;
    const coordinator = new PaymentCoordinator({ journal, rail, authorize, origin: 'https://merchant.example',
      beforeSettlement: async () => { if (!current) throw new Error('revoked during audit'); },
      onPayment: async event => { if (event['phase'] === 'authorized') current = false; },
    });
    const record = await coordinator.prepare({ owner, protocol: 'ucp', product: 'risotto', quantity: 2, rail: 'sandbox-token', id: 'token-late-revocation' });
    await coordinator.confirm(record.id, record.reviewToken, record.termsDigest);
    const token = await coordinator.tokenize(record.id, owner);
    expect(body(await coordinator.complete(argsFor(record), token))).toMatchObject({ error: 'AUTHORITY_CHANGED' });
    expect(coordinator.get(record.id)?.state).toBe('open');
    expect(coordinator.get(record.id)?.result).toBeUndefined();
    expect(journal.read().payments).toEqual({});
  });

  it('retains completion audit evidence across failure and restart without repeating a payment', async () => {
    const { journal, rail, authorize } = setup();
    const settle = vi.spyOn(rail, 'settle');
    const audit = vi.fn(async (event: Record<string, unknown>) => {
      if (event['phase'] === 'completed') throw new Error('audit storage temporarily unavailable');
    });
    const coordinator = new PaymentCoordinator({ journal, rail, authorize, origin: 'https://merchant.example', onPayment: audit });
    const record = await coordinator.prepare({ owner, protocol: 'x402', product: 'risotto', quantity: 2, rail: 'x402', id: 'audit-response-lost' });
    const result = body(await coordinator.complete(argsFor(record), await sign(record, rail)));
    expect(result.ok).toBe(true);
    const committed = coordinator.get(record.id)!;
    expect(committed.state).toBe('settled');
    expect(committed.completionEvidence?.deliveredAt).toBeUndefined();
    expect(committed.completionEvidence?.event).toMatchObject({ phase: 'completed', orderId: result.orderId });
    expect(committed.paymentIdentity).toEqual(expect.any(String));
    expect(JSON.stringify(result)).not.toContain('paymentIdentity');
    const recoveredAudit = vi.fn(async () => {});
    const noNewAuthority = vi.fn(async () => { throw new Error('The grant has since been revoked'); });
    const restarted = new PaymentCoordinator({ journal: new CommerceJournal(journal.file), rail, authorize: noNewAuthority,
      origin: 'https://merchant.example', onPayment: recoveredAudit });
    await expect(restarted.recoverCompletionEvidence(record.id)).resolves.toBe(true);
    expect(recoveredAudit).toHaveBeenCalledWith(committed.completionEvidence?.event);
    expect(restarted.get(record.id)?.completionEvidence?.deliveredAt).toEqual(expect.any(String));
    await expect(restarted.recoverCompletionEvidence(record.id)).resolves.toBe(true);
    expect(recoveredAudit).toHaveBeenCalledOnce();
    expect(noNewAuthority).not.toHaveBeenCalled();
    expect(settle).toHaveBeenCalledOnce();
    expect(restarted.get(record.id)?.result).toEqual(result);
  });

});
