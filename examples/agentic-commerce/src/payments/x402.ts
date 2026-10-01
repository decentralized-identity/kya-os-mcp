/**
 * x402 v2 exact EIP-3009 rail. KYA authorization and order idempotency belong
 * to the merchant orchestrator and must run before this payment boundary.
 * Sandbox verifies genuine signatures but never contacts a chain/facilitator.
 * Testnet is deliberately restricted to Base Sepolia USDC.
 * See https://github.com/x402-foundation/x402/tree/main/specs.
 */
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { HTTPFacilitatorClient, type FacilitatorClient } from '@x402/core/server';
import type { PaymentPayload, PaymentRequired, PaymentRequirements, SettleResponse } from '@x402/core/types';
import { authorizationTypes, type ExactEIP3009Payload } from '@x402/evm';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { getAddress, isAddress, verifyTypedData, type Address } from 'viem';

export const X402_NETWORK = 'eip155:84532' as const;
export const X402_ASSET = '0x036CbD53842c5426634e7929541eC2318f3dCF7e' as const;
export const X402_TEST_FACILITATOR = 'https://x402.org/facilitator';
export const X402_SANDBOX_PAY_TO = '0x000000000000000000000000000000000000dEaD' as const;
export type X402PaymentPayload = PaymentPayload & { payload: ExactEIP3009Payload & { signature: `0x${string}` } };
export interface X402Quote {
  id: string;
  expiresAt: string;
  requirements: PaymentRequirements;
  paymentRequired: PaymentRequired;
  pricing: {
    kind: 'fixed-demo-rate';
    currency: 'CHF';
    amountMinor: string;
    atomicUnitsPerChfCent: string;
    amountAtomic: string;
    asset: 'USDC';
    decimals: 6;
    note: string;
  };
}
export type X402Verification =
  | { isValid: true; payer: Address; paymentIdentity: string }
  | { isValid: false; reason: string };
export type X402Settlement =
  | { status: 'simulated'; simulated: true; paymentIdentity: string; simulationId: string; response: SettleResponse }
  | { status: 'settled'; simulated: false; paymentIdentity: string; response: SettleResponse }
  | { status: 'pending'; simulated: false; reason: string; paymentIdentity: string; response?: SettleResponse }
  | { status: 'failed'; simulated: boolean; reason: string; response?: SettleResponse };
export interface X402RailOptions {
  mode: 'sandbox' | 'testnet';
  /** Required in testnet. Sandbox's default is a public burn address. */
  payTo?: string;
  /** Reject all other networks even if supplied through configuration. */
  network?: string;
  /** Explicit workshop quote, NOT a market CHF/USD exchange rate. */
  atomicUnitsPerChfCent?: string;
  maxTimeoutSeconds?: number;
  facilitator?: FacilitatorClient;
  /** Millisecond Unix time; injection is for deterministic tests. */
  now?: () => number;
}

function positiveInteger(value: string | bigint, name: string): bigint {
  const text = String(value);
  if (!/^[1-9]\d{0,77}$/.test(text) || BigInt(text) > (1n << 256n) - 1n) throw new Error(`${name} must be a positive uint256 integer`);
  return BigInt(text);
}
function unsignedInteger(value: unknown): value is string {
  return typeof value === 'string' && /^(0|[1-9]\d{0,77})$/.test(value) && BigInt(value) <= (1n << 256n) - 1n;
}
function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function fail(reason: string): X402Verification { return { isValid: false, reason }; }

export class X402Rail {
  readonly mode: 'sandbox' | 'testnet';
  readonly payTo: Address;
  readonly atomicUnitsPerChfCent: string;
  readonly maxTimeoutSeconds: number;
  private readonly facilitator?: FacilitatorClient;
  private readonly now: () => number;
  private readonly scheme = new ExactEvmScheme();

  constructor(options: X402RailOptions) {
    if (!['sandbox', 'testnet'].includes(options.mode)) throw new Error('Unsupported x402 mode');
    if (options.network !== undefined && options.network !== X402_NETWORK) throw new Error('Only Base Sepolia is supported');
    if (options.mode === 'testnet' && !options.payTo) throw new Error('Testnet x402 requires configured payTo');
    const payTo = options.payTo ?? X402_SANDBOX_PAY_TO;
    if (!isAddress(payTo) || /^0x0{40}$/i.test(payTo)) throw new Error('x402 payTo must be a nonzero EVM address');
    this.payTo = getAddress(payTo);
    this.mode = options.mode;
    this.atomicUnitsPerChfCent = positiveInteger(options.atomicUnitsPerChfCent ?? '10000', 'atomicUnitsPerChfCent').toString();
    this.maxTimeoutSeconds = options.maxTimeoutSeconds ?? 300;
    if (!Number.isInteger(this.maxTimeoutSeconds) || this.maxTimeoutSeconds < 1 || this.maxTimeoutSeconds > 3600) throw new Error('x402 maxTimeoutSeconds must be 1-3600');
    this.now = options.now ?? Date.now;
    if (this.mode === 'testnet') this.facilitator = options.facilitator ?? new HTTPFacilitatorClient({ url: X402_TEST_FACILITATOR, timeoutMs: 30_000 });
  }

  async createRequirements(input: { id: string; resource: string; amountMinor: string | bigint; currency: 'CHF' }): Promise<X402Quote> {
    if (!input.id || input.id.length > 200) throw new Error('A bounded quote id is required');
    if (input.currency !== 'CHF') throw new Error('x402 demo quotes require CHF');
    const resource = new URL(input.resource);
    if (!['https:', 'http:', 'mcp:'].includes(resource.protocol) || resource.username || resource.password) throw new Error('Unsupported x402 resource URL');
    const amountMinor = positiveInteger(input.amountMinor, 'amountMinor');
    const amount = positiveInteger(amountMinor * BigInt(this.atomicUnitsPerChfCent), 'amountAtomic').toString();
    const price = await this.scheme.parsePrice({ amount, asset: X402_ASSET, extra: { name: 'USDC', version: '2' } }, X402_NETWORK);
    const requirements: PaymentRequirements = { scheme: 'exact', network: X402_NETWORK, amount: price.amount, asset: price.asset, payTo: this.payTo, maxTimeoutSeconds: this.maxTimeoutSeconds, extra: price.extra ?? {} };
    return {
      id: input.id,
      expiresAt: new Date(this.now() + this.maxTimeoutSeconds * 1000).toISOString(),
      requirements,
      paymentRequired: { x402Version: 2, resource: { url: resource.href, description: `Checkout ${input.id}`, mimeType: 'application/json' }, accepts: [structuredClone(requirements)] },
      pricing: { kind: 'fixed-demo-rate', currency: 'CHF', amountMinor: amountMinor.toString(), atomicUnitsPerChfCent: this.atomicUnitsPerChfCent, amountAtomic: amount, asset: 'USDC', decimals: 6,
        note: 'Fixed workshop quote in test USDC. This is not a market CHF/USD exchange rate.' },
    };
  }

  /** Read-only. A valid signature does not itself reserve or spend anything. */
  async verify(quote: X402Quote, payload: unknown): Promise<X402Verification> {
    const local = await this.verifyLocally(quote, payload);
    if (!local.isValid || this.mode === 'sandbox') return local;
    try {
      const result = await this.facilitator!.verify(payload as PaymentPayload, quote.requirements);
      if (!result.isValid) return fail(result.invalidReason ?? 'X402_PAYMENT_INVALID');
      if (result.payer && result.payer.toLowerCase() !== local.payer.toLowerCase()) return fail('X402_PAYER_MISMATCH');
      return local;
    } catch { return fail('X402_FACILITATOR_UNAVAILABLE'); }
  }

  /**
   * Caller must durably reserve paymentIdentity and the order before entering.
   * Never create a new signature after an indeterminate settlement response.
   */
  async settle(quote: X402Quote, payload: unknown, beforeSubmit?: () => Promise<void>): Promise<X402Settlement> {
    const checked = await this.verify(quote, payload);
    if (!checked.isValid) return { status: 'failed', simulated: this.mode === 'sandbox', reason: checked.reason };
    // Remote verification may take seconds. Refresh authority after that wait,
    // before the first irreversible provider call or simulated commit.
    try { await beforeSubmit?.(); }
    catch (error) {
      const code = error instanceof Error ? error.message.split(':')[0] : '';
      const reason = ['AUTHORITY_REVOKED', 'AUTHORITY_EXPIRED', 'AUTHORITY_STATUS_UNAVAILABLE'].includes(code ?? '') ? code! : 'AUTHORITY_CHANGED';
      return { status: 'failed', simulated: this.mode === 'sandbox', reason };
    }
    if (this.mode === 'sandbox') {
      const simulationId = `sandbox:${createHash('sha256').update(`${quote.id}|${checked.paymentIdentity}`).digest('hex')}`;
      return { status: 'simulated', simulated: true, simulationId, paymentIdentity: checked.paymentIdentity,
        response: { success: true, network: X402_NETWORK, transaction: '', payer: checked.payer, amount: quote.requirements.amount,
          extensions: { 'kya-os/sandbox': {
            info: { simulated: true, simulationId, note: 'Signature verified. No blockchain transaction or funds movement.' },
            schema: { type: 'object', required: ['simulated', 'simulationId', 'note'], properties: { simulated: { const: true }, simulationId: { type: 'string', pattern: '^sandbox:' }, note: { type: 'string' } }, additionalProperties: false },
          } } } };
    }
    let response: SettleResponse;
    try { response = await this.facilitator!.settle(payload as PaymentPayload, quote.requirements); }
    catch { return { status: 'pending', simulated: false, reason: 'X402_SETTLEMENT_UNRESOLVED', paymentIdentity: checked.paymentIdentity }; }
    if (response.success) {
      if (response.network !== X402_NETWORK || !/^0x[0-9a-fA-F]{64}$/.test(response.transaction)
        || (response.payer && response.payer.toLowerCase() !== checked.payer.toLowerCase())
        || (response.amount !== undefined && response.amount !== quote.requirements.amount)) {
        return { status: 'pending', simulated: false, reason: 'X402_SETTLEMENT_UNRESOLVED', paymentIdentity: checked.paymentIdentity, response };
      }
      return { status: 'settled', simulated: false, paymentIdentity: checked.paymentIdentity, response };
    }
    if (response.errorReason === 'settlement_pending') return { status: 'pending', simulated: false, reason: 'settlement_pending', paymentIdentity: checked.paymentIdentity, response };
    return { status: 'failed', simulated: false, reason: response.errorReason ?? 'X402_SETTLEMENT_FAILED', response };
  }

  private async verifyLocally(quote: X402Quote, input: unknown): Promise<X402Verification> {
    if (!Number.isFinite(Date.parse(quote.expiresAt)) || this.now() >= Date.parse(quote.expiresAt)) return fail('X402_QUOTE_EXPIRED');
    const expected = quote.requirements;
    if (expected.scheme !== 'exact' || expected.network !== X402_NETWORK || expected.asset !== X402_ASSET || expected.payTo !== this.payTo
      || expected.maxTimeoutSeconds !== this.maxTimeoutSeconds || !isDeepStrictEqual(expected.extra, { name: 'USDC', version: '2' })) return fail('X402_REQUIREMENTS_INVALID');
    if (!object(input) || input.x402Version !== 2 || !isDeepStrictEqual(input.accepted, expected)
      || !object(input.resource) || input.resource.url !== quote.paymentRequired.resource.url) return fail('X402_REQUIREMENTS_MISMATCH');
    if (!object(input.payload) || !object(input.payload.authorization)) return fail('X402_PAYLOAD_INVALID');
    const p = input.payload;
    const a = input.payload.authorization;
    if (typeof p.signature !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(p.signature)
      || typeof a.from !== 'string' || !isAddress(a.from) || typeof a.to !== 'string' || !isAddress(a.to)
      || typeof a.nonce !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(a.nonce)
      || !unsignedInteger(a.value) || !unsignedInteger(a.validAfter) || !unsignedInteger(a.validBefore)) return fail('X402_PAYLOAD_INVALID');
    if (a.to.toLowerCase() !== this.payTo.toLowerCase()) return fail('X402_RECIPIENT_MISMATCH');
    if (a.value !== expected.amount) return fail('X402_AMOUNT_MISMATCH');
    const now = BigInt(Math.floor(this.now() / 1000));
    if (BigInt(a.validAfter) > now || BigInt(a.validBefore) <= now || BigInt(a.validBefore) > now + BigInt(this.maxTimeoutSeconds)) return fail('X402_AUTHORIZATION_EXPIRED');
    try {
      const valid = await verifyTypedData({ address: a.from as Address,
        domain: { name: 'USDC', version: '2', chainId: 84532, verifyingContract: X402_ASSET },
        types: authorizationTypes, primaryType: 'TransferWithAuthorization',
        message: { from: a.from as Address, to: a.to as Address, value: BigInt(a.value), validAfter: BigInt(a.validAfter), validBefore: BigInt(a.validBefore), nonce: a.nonce as `0x${string}` },
        signature: p.signature as `0x${string}` });
      if (!valid) return fail('X402_SIGNATURE_INVALID');
      const payer = getAddress(a.from);
      return { isValid: true, payer, paymentIdentity: `${X402_NETWORK}/${X402_ASSET.toLowerCase()}/${payer.toLowerCase()}/${a.nonce.toLowerCase()}` };
    } catch { return fail('X402_SIGNATURE_INVALID'); }
  }
}
