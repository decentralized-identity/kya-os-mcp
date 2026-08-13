#!/usr/bin/env npx tsx
/**
 * WP0 assumption check B — cosmjs bank send on cheqd testnet.
 *
 * Sends 1 CHEQ from the AGENT wallet to the fee-payer wallet and prints the
 * tx hash + explorer link. Confirms RPC endpoint, chain-id, denom, and gas
 * settings before the demo depends on them.
 */
import { DirectSecp256k1HdWallet } from '@cosmjs/proto-signing';
import { SigningStargateClient, GasPrice, assertIsDeliverTxSuccess, coins } from '@cosmjs/stargate';
import { requiredEnv, env, explorerTxUrl } from '../src/lib/wiring.js';

const NCHEQ_PER_CHEQ = 1_000_000_000n; // cheqd exponent 9

async function main() {
  const rpcUrl = env('CHEQD_RPC_URL', 'https://rpc.cheqd.network');
  const denom = env('CHEQD_DENOM', 'ncheq');
  // cheqd testnet min gas price is 5000ncheq (verified live: 50ncheq → code 13 insufficient fees)
  const gasPrice = env('CHEQD_GAS_PRICE', `5000${denom}`);
  const amountCheq = BigInt(env('CHECK_B_AMOUNT_CHEQ', '1'));

  const agentWallet = await DirectSecp256k1HdWallet.fromMnemonic(
    requiredEnv('AGENT_MNEMONIC'), { prefix: 'cheqd' },
  );
  const feeWallet = await DirectSecp256k1HdWallet.fromMnemonic(
    requiredEnv('ISSUER_FEE_MNEMONIC'), { prefix: 'cheqd' },
  );
  const [agent] = await agentWallet.getAccounts();
  const [fee] = await feeWallet.getAccounts();

  console.log(`RPC:        ${rpcUrl}`);
  console.log(`Agent:      ${agent!.address}`);
  console.log(`Recipient:  ${fee!.address}`);

  const client = await SigningStargateClient.connectWithSigner(rpcUrl, agentWallet, {
    gasPrice: GasPrice.fromString(gasPrice),
  });

  const chainId = await client.getChainId();
  console.log(`Chain id:   ${chainId}`);
  const expectedChainId = process.env['CHEQD_CHAIN_ID'];
  if (expectedChainId && chainId !== expectedChainId) {
    console.warn(`WARNING: expected ${expectedChainId} — update CHEQD_CHAIN_ID in .env.local to ${chainId}`);
  }

  const before = await client.getBalance(agent!.address, denom);
  console.log(`Balance:    ${before.amount} ${denom}`);
  if (BigInt(before.amount) === 0n) {
    throw new Error('Agent wallet has zero balance — fund it via the faucet first (npm run gen:accounts prints addresses).');
  }

  const amount = coins((amountCheq * NCHEQ_PER_CHEQ).toString(), denom);
  console.log(`\nSending ${amountCheq} CHEQ…`);
  const started = Date.now();
  // multiplier 2: 'auto' (1.4×) landed 300 gas short on cheqd testnet (code 11)
  const result = await client.sendTokens(
    agent!.address, fee!.address, amount, 2, 'revoked-example check-b',
  );
  assertIsDeliverTxSuccess(result);

  const after = await client.getBalance(agent!.address, denom);

  console.log('\n================ CHECK B RESULT ================');
  console.log(JSON.stringify({
    txHash: result.transactionHash,
    explorer: explorerTxUrl(result.transactionHash),
    gasUsed: result.gasUsed.toString(),
    elapsedMs: Date.now() - started,
    chainId,
    balanceBefore: before.amount,
    balanceAfter: after.amount,
  }, null, 2));
  console.log('PASS — RPC, chain-id, denom, and gas all confirmed.');
}

main().catch((err) => {
  console.error('\nCHECK B FAILED:', err);
  process.exit(1);
});
