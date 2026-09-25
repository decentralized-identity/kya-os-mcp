/** Buyer-side signing only. Persist the returned payload before sending it. */
import { x402Client } from '@x402/core/client';
import type { PaymentRequired } from '@x402/core/types';
import { ExactEvmScheme } from '@x402/evm/exact/client';
import { privateKeyToAccount } from 'viem/accounts';
import { X402_ASSET, X402_NETWORK, type X402PaymentPayload } from './x402.js';

export async function createX402Payment(required: PaymentRequired, options: {
  privateKey: `0x${string}`;
  payTo: string;
  maxAtomicAmount: string;
}): Promise<X402PaymentPayload> {
  if (required.x402Version !== 2 || required.accepts.length !== 1) throw new Error('A single x402 v2 exact quote is required');
  const accepted = required.accepts[0]!;
  if (accepted.scheme !== 'exact' || accepted.network !== X402_NETWORK || accepted.asset !== X402_ASSET
    || accepted.extra?.name !== 'USDC' || accepted.extra?.version !== '2'
    || (accepted.extra?.assetTransferMethod !== undefined && accepted.extra.assetTransferMethod !== 'eip3009')
    || (accepted.extra?.paymentFlow !== undefined && accepted.extra.paymentFlow !== 'authorization')) throw new Error('Only exact Base Sepolia USDC EIP-3009 payments are supported');
  if (accepted.payTo.toLowerCase() !== options.payTo.toLowerCase()) throw new Error('x402 recipient differs from the trusted merchant');
  if (!/^[1-9]\d{0,77}$/.test(accepted.amount) || !/^[1-9]\d{0,77}$/.test(options.maxAtomicAmount)
    || BigInt(accepted.amount) > BigInt(options.maxAtomicAmount)) throw new Error('x402 amount exceeds the approved quote');
  if (!Number.isInteger(accepted.maxTimeoutSeconds) || accepted.maxTimeoutSeconds < 1 || accepted.maxTimeoutSeconds > 3600) throw new Error('Unsupported x402 payment validity window');
  const client = new x402Client().register(X402_NETWORK, new ExactEvmScheme(privateKeyToAccount(options.privateKey)))
    .setSpendControls({ allowedAssets: [{ network: X402_NETWORK, asset: X402_ASSET, maxAmountPerPayment: options.maxAtomicAmount }] });
  // SDK payloads may retain references to the input requirement/resource.
  // Keep the immutable merchant quote separate from the outgoing payload.
  return await client.createPaymentPayload(structuredClone(required)) as X402PaymentPayload;
}
