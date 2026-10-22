import { afterEach, describe, expect, it, vi } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import type { FacilitatorClient } from '@x402/core/server';
import type { SettleResponse } from '@x402/core/types';
import { authorizationTypes } from '@x402/evm';
import { X402Rail, X402_NETWORK, X402_ASSET, type X402Quote } from '../src/payments/x402.js';
import { createX402Payment } from '../src/payments/x402-client.js';

// Public test keys. These accounts must never hold real funds.
const privateKey = `0x${'01'.padStart(64, '0')}` as const;
const payTo = privateKeyToAccount(`0x${'02'.padStart(64, '0')}`).address;
const payer = privateKeyToAccount(privateKey).address;
const now = new Date('2026-09-09T10:00:00Z');
afterEach(() => vi.useRealTimers());
function clock() { vi.useFakeTimers(); vi.setSystemTime(now); }
function request(rail: X402Rail) {
  return rail.createRequirements({ id: 'quote-1', resource: 'https://merchant.example/checkout/quote-1', amountMinor: '3980', currency: 'CHF' });
}
function sign(quote: X402Quote) {
  return createX402Payment(quote.paymentRequired, { privateKey, payTo, maxAtomicAmount: quote.requirements.amount });
}
function facilitator(overrides: Partial<FacilitatorClient> = {}): FacilitatorClient {
  return {
    getSupported: vi.fn(async () => ({ kinds: [{ x402Version: 2, scheme: 'exact', network: X402_NETWORK }], extensions: [], signers: {} })),
    verify: vi.fn(async () => ({ isValid: true, payer })),
    settle: vi.fn(async () => ({ success: true, payer, network: X402_NETWORK, transaction: `0x${'a'.repeat(64)}` })),
    ...overrides,
  };
}

describe('x402 exact EVM payments', () => {
  it('prices a CHF order with an explicit fixed demo rate and verifies a real SDK EIP-3009 signature', async () => {
    clock();
    const rail = new X402Rail({ mode: 'sandbox', payTo, atomicUnitsPerChfCent: '10000' });
    const quote = await request(rail);
    expect(quote.pricing).toMatchObject({ kind: 'fixed-demo-rate', currency: 'CHF', amountMinor: '3980', atomicUnitsPerChfCent: '10000', amountAtomic: '39800000' });
    expect(quote.requirements).toMatchObject({ scheme: 'exact', network: X402_NETWORK, asset: X402_ASSET, amount: '39800000', payTo });
    const payload = await sign(quote);
    const verification = await rail.verify(quote, payload);
    expect(verification).toMatchObject({ isValid: true, payer });
    expect(verification.isValid && verification.paymentIdentity).toContain(payload.payload.authorization.nonce);
    const settlement = await rail.settle(quote, payload);
    expect(settlement).toMatchObject({ status: 'simulated', simulated: true, response: { success: true, transaction: '', network: X402_NETWORK, payer } });
    expect(settlement).toHaveProperty('simulationId');
  });

  it.each(['recipient', 'amount', 'signature', 'network', 'resource', 'nonce', 'domain'] as const)('refuses a changed %s before facilitator verification or settlement', async attack => {
    clock();
    const upstream = facilitator();
    const rail = new X402Rail({ mode: 'testnet', payTo, facilitator: upstream });
    const quote = await request(rail);
    const payload = await sign(quote);
    if (attack === 'recipient') payload.payload.authorization.to = payer;
    if (attack === 'amount') payload.payload.authorization.value = '1';
    if (attack === 'signature') payload.payload.signature = `0x${'00'.repeat(65)}`;
    if (attack === 'network') payload.accepted.network = 'eip155:8453';
    if (attack === 'resource') payload.resource!.url = 'https://merchant.example/checkout/other';
    if (attack === 'nonce') payload.payload.authorization.nonce = `0x${'00'.repeat(32)}`;
    if (attack === 'domain') payload.accepted.extra!.name = 'Other Coin';
    expect(await rail.verify(quote, payload)).toMatchObject({ isValid: false });
    expect(await rail.settle(quote, payload)).toMatchObject({ status: 'failed' });
    expect(upstream.verify).not.toHaveBeenCalled();
    expect(upstream.settle).not.toHaveBeenCalled();
  });

  it('refuses expired authorizations and quotes', async () => {
    clock();
    const rail = new X402Rail({ mode: 'sandbox', payTo });
    const quote = await request(rail);
    const payload = await sign(quote);
    vi.setSystemTime(new Date(now.getTime() + 301_000));
    expect(await rail.verify(quote, payload)).toMatchObject({ isValid: false, reason: 'X402_QUOTE_EXPIRED' });
  });

  it.each(['expired', 'future'] as const)('rejects a cryptographically authentic but %s authorization while the quote remains valid', async timing => {
    clock();
    const rail = new X402Rail({ mode: 'sandbox', payTo });
    const quote = await request(rail);
    const payload = await sign(quote);
    const a = payload.payload.authorization;
    const seconds = Math.floor(now.getTime() / 1000);
    if (timing === 'expired') a.validBefore = String(seconds - 1);
    else a.validAfter = String(seconds + 60);
    payload.payload.signature = await privateKeyToAccount(privateKey).signTypedData({
      domain: { name: 'USDC', version: '2', chainId: 84532, verifyingContract: X402_ASSET },
      types: authorizationTypes, primaryType: 'TransferWithAuthorization',
      message: { ...a, value: BigInt(a.value), validAfter: BigInt(a.validAfter), validBefore: BigInt(a.validBefore) },
    });
    expect(await rail.verify(quote, payload)).toMatchObject({ isValid: false, reason: 'X402_AUTHORIZATION_EXPIRED' });
  });

  it('does not claim a successful testnet payment when facilitator verification fails', async () => {
    clock();
    const upstream = facilitator({ verify: vi.fn(async () => ({ isValid: false, invalidReason: 'insufficient_funds' })) });
    const rail = new X402Rail({ mode: 'testnet', payTo, facilitator: upstream });
    const quote = await request(rail);
    const result = await rail.verify(quote, await sign(quote));
    expect(result).toMatchObject({ isValid: false, reason: 'insufficient_funds' });
    expect(await rail.settle(quote, await sign(quote))).toMatchObject({ status: 'failed', reason: 'insufficient_funds' });
    expect(upstream.settle).not.toHaveBeenCalled();
  });

  it('never sends a sandbox authorization to a facilitator, including an injected one', async () => {
    clock();
    const upstream = facilitator();
    const rail = new X402Rail({ mode: 'sandbox', payTo, facilitator: upstream });
    const quote = await request(rail);
    const payload = await sign(quote);
    const one = await rail.settle(quote, payload);
    const two = await rail.settle(quote, payload);
    expect(one).toEqual(two);
    expect(upstream.getSupported).not.toHaveBeenCalled();
    expect(upstream.verify).not.toHaveBeenCalled();
    expect(upstream.settle).not.toHaveBeenCalled();
  });

  it('separates a definitive settlement refusal from a broadcast still awaiting confirmation', async () => {
    clock();
    for (const [errorReason, status] of [['insufficient_funds', 'failed'], ['settlement_pending', 'pending']] as const) {
      const upstream = facilitator({ settle: vi.fn(async () => ({ success: false, errorReason, network: X402_NETWORK, transaction: errorReason === 'settlement_pending' ? `0x${'a'.repeat(64)}` : '' })) });
      const rail = new X402Rail({ mode: 'testnet', payTo, facilitator: upstream });
      const quote = await request(rail);
      expect(await rail.settle(quote, await sign(quote))).toMatchObject({ status, reason: errorReason, simulated: false });
      expect(upstream.settle).toHaveBeenCalledTimes(1);
    }
  });

  it('reports settlement failures and indeterminate outcomes without creating a new payment', async () => {
    clock();
    const upstream = facilitator({ settle: vi.fn(async () => { throw new Error('connection lost after broadcast'); }) });
    const rail = new X402Rail({ mode: 'testnet', payTo, facilitator: upstream });
    const quote = await request(rail);
    const payload = await sign(quote);
    expect(await rail.settle(quote, payload)).toMatchObject({ status: 'pending', reason: 'X402_SETTLEMENT_UNRESOLVED', simulated: false });
    expect(upstream.settle).toHaveBeenCalledTimes(1);
    expect(upstream.settle).toHaveBeenCalledWith(payload, quote.requirements);
  });

  it('returns real testnet transaction evidence only after the facilitator confirms settlement', async () => {
    clock();
    const upstream = facilitator();
    const rail = new X402Rail({ mode: 'testnet', payTo, facilitator: upstream });
    const quote = await request(rail);
    const result = await rail.settle(quote, await sign(quote));
    expect(result).toMatchObject({ status: 'settled', simulated: false, response: { success: true, transaction: `0x${'a'.repeat(64)}` } });
  });

  it('does not submit payment when authority is revoked during the final facilitator verification', async () => {
    clock();
    let revoked = false;
    let calls = 0;
    const upstream = facilitator({ verify: vi.fn(async () => {
      calls += 1;
      if (calls === 2) revoked = true;
      return { isValid: true, payer };
    }) });
    const rail = new X402Rail({ mode: 'testnet', payTo, facilitator: upstream });
    const quote = await request(rail);
    const payload = await sign(quote);
    expect(await rail.verify(quote, payload)).toMatchObject({ isValid: true });
    expect(revoked).toBe(false);
    const checkAuthority = vi.fn(async () => { if (revoked) throw new Error('Grant revoked while awaiting verification'); });
    expect(await rail.settle(quote, payload, checkAuthority)).toMatchObject({ status: 'failed', reason: 'AUTHORITY_CHANGED', simulated: false });
    expect(checkAuthority).toHaveBeenCalledTimes(1);
    expect(upstream.verify).toHaveBeenCalledTimes(2);
    expect(upstream.settle).not.toHaveBeenCalled();
  });

  it('checks final authority after payment verification and immediately before submission', async () => {
    clock();
    const events: string[] = [];
    const upstream = facilitator({
      verify: vi.fn(async () => { events.push('payment_verified'); return { isValid: true, payer }; }),
      settle: vi.fn(async () => { events.push('payment_submitted'); return { success: true, payer, network: X402_NETWORK, transaction: `0x${'a'.repeat(64)}` }; }),
    });
    const rail = new X402Rail({ mode: 'testnet', payTo, facilitator: upstream });
    const quote = await request(rail);
    await rail.settle(quote, await sign(quote), async () => { events.push('authority_current'); });
    expect(events).toEqual(['payment_verified', 'authority_current', 'payment_submitted']);
  });

  it('also gates sandbox simulation on current authority', async () => {
    clock();
    const rail = new X402Rail({ mode: 'sandbox', payTo });
    const quote = await request(rail);
    expect(await rail.settle(quote, await sign(quote), async () => { throw new Error('Authority expired'); })).toMatchObject({ status: 'failed', reason: 'AUTHORITY_CHANGED', simulated: true });
  });

  it('rejects a facilitator success with no transaction or the wrong network or payer', async () => {
    clock();
    const cases: Partial<SettleResponse>[] = [{ transaction: '' }, { network: 'eip155:8453' }, { payer: payTo }];
    for (const bad of cases) {
      const upstream = facilitator({ settle: vi.fn(async () => ({ success: true, payer, network: X402_NETWORK, transaction: `0x${'a'.repeat(64)}`, ...bad })) });
      const rail = new X402Rail({ mode: 'testnet', payTo, facilitator: upstream });
      const quote = await request(rail);
      expect(await rail.settle(quote, await sign(quote))).toMatchObject({ status: 'pending', reason: 'X402_SETTLEMENT_UNRESOLVED' });
    }
  });

  it('requires explicit testnet recipient configuration and rejects unsupported configuration', () => {
    expect(() => new X402Rail({ mode: 'testnet' })).toThrow(/payTo/);
    expect(() => new X402Rail({ mode: 'sandbox', payTo, network: 'eip155:8453' })).toThrow(/Base Sepolia/);
    expect(() => new X402Rail({ mode: 'sandbox', payTo, atomicUnitsPerChfCent: '1.2' })).toThrow(/integer/);
  });

  it('checks the buyer recipient, amount ceiling and exact testnet scheme before signing', async () => {
    clock();
    const rail = new X402Rail({ mode: 'sandbox', payTo });
    const quote = await request(rail);
    await expect(createX402Payment(quote.paymentRequired, { privateKey, payTo, maxAtomicAmount: '1' })).rejects.toThrow(/amount/);
    await expect(createX402Payment(quote.paymentRequired, { privateKey, payTo: payer, maxAtomicAmount: quote.requirements.amount })).rejects.toThrow(/recipient/);
    quote.paymentRequired.accepts[0]!.network = 'eip155:8453';
    await expect(sign(quote)).rejects.toThrow(/Base Sepolia/);
  });
});
