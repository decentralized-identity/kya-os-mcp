/**
 * The delegated action: a real bank send from the AGENT's wallet on cheqd
 * testnet, plus the in-credential spend-cap reader.
 *
 * The cap is enforced from the SAME credential the delegation gate verified
 * (constraints.crisp.scopes[payments.transfer].constraints.maxAmountNcheq) —
 * the credential constrains the agent; app code just reads it.
 */
import { DirectSecp256k1HdWallet } from '@cosmjs/proto-signing';
import { SigningStargateClient, StargateClient, GasPrice, assertIsDeliverTxSuccess, coins } from '@cosmjs/stargate';
import type { DelegationCredential } from '@kya-os/mcp';
import { requiredEnv, env, explorerTxUrl } from './lib/wiring.js';

export const NCHEQ_PER_CHEQ = 1_000_000_000n;

const PREFIX = 'cheqd';
const rpcUrl = () => env('CHEQD_RPC_URL', 'https://rpc.cheqd.network');
const denom = () => env('CHEQD_DENOM', 'ncheq');
// cheqd testnet min gas price 5000ncheq; 'auto' estimation lands short → 2x
const gasPrice = () => GasPrice.fromString(env('CHEQD_GAS_PRICE', `5000${env('CHEQD_DENOM', 'ncheq')}`));

export function toNcheq(amountCheq: number | string): bigint {
  const value = Number(amountCheq);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`amount must be a positive number of CHEQ, got "${amountCheq}"`);
  }
  return BigInt(Math.round(value * 1e9));
}

export async function agentWallet(): Promise<DirectSecp256k1HdWallet> {
  return DirectSecp256k1HdWallet.fromMnemonic(requiredEnv('AGENT_MNEMONIC'), { prefix: PREFIX });
}

export async function agentAddress(): Promise<string> {
  const [account] = await (await agentWallet()).getAccounts();
  return account!.address;
}

export async function feePayerAddress(): Promise<string> {
  const wallet = await DirectSecp256k1HdWallet.fromMnemonic(requiredEnv('ISSUER_FEE_MNEMONIC'), { prefix: PREFIX });
  const [account] = await wallet.getAccounts();
  return account!.address;
}

export async function agentBalanceNcheq(): Promise<bigint> {
  const client = await StargateClient.connect(rpcUrl());
  const balance = await client.getBalance(await agentAddress(), denom());
  client.disconnect();
  return BigInt(balance.amount);
}

export interface WalletSendResult {
  txHash: string;
  explorer: string;
  gasUsed: string;
  amountNcheq: string;
  from: string;
  to: string;
}

export async function walletSend(options: {
  amountNcheq: bigint;
  to?: string;
  memo?: string;
}): Promise<WalletSendResult> {
  const wallet = await agentWallet();
  const [account] = await wallet.getAccounts();
  const from = account!.address;
  const to = options.to ?? await feePayerAddress();

  const client = await SigningStargateClient.connectWithSigner(rpcUrl(), wallet, {
    gasPrice: gasPrice(),
  });
  const result = await client.sendTokens(
    from, to, coins(options.amountNcheq.toString(), denom()), 2,
    options.memo ?? 'revoked-example wallet_send',
  );
  client.disconnect();
  assertIsDeliverTxSuccess(result);

  return {
    txHash: result.transactionHash,
    explorer: explorerTxUrl(result.transactionHash),
    gasUsed: result.gasUsed.toString(),
    amountNcheq: options.amountNcheq.toString(),
    from,
    to,
  };
}

/** Read the spend cap OUT OF the verified credential. Fail-closed: no cap → 0. */
export function extractSpendCapNcheq(vc: DelegationCredential): bigint {
  const crisp = vc.credentialSubject?.delegation?.constraints?.crisp;
  const scopes = Array.isArray(crisp?.scopes) ? crisp.scopes : [];
  for (const scope of scopes) {
    if (scope?.resource !== 'payments.transfer') continue;
    const cap = (scope.constraints as Record<string, unknown> | undefined)?.['maxAmountNcheq'];
    if (typeof cap === 'string' && /^[0-9]+$/.test(cap)) return BigInt(cap);
  }
  return 0n;
}
