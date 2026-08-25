#!/usr/bin/env npx tsx
/**
 * Generate the two testnet wallets the demo needs:
 *   1. the AGENT wallet (the AI agent's own spending account), and
 *   2. the ISSUER fee-payer wallet.
 *
 * Mnemonics are written to .env.local (0600, gitignored) and NEVER printed.
 * Fund the printed addresses via the cheqd testnet faucet, then run check:b.
 */
import { DirectSecp256k1HdWallet } from '@cosmjs/proto-signing';
import { readEnvLocal, writeEnvLocal } from './lib/env-local.js';

const PREFIX = 'cheqd';

async function addressOf(mnemonic: string): Promise<string> {
  const wallet = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, { prefix: PREFIX });
  const [account] = await wallet.getAccounts();
  return account!.address;
}

async function main() {
  const existing = readEnvLocal();
  const updates: Record<string, string> = {};

  let agentMnemonic = existing['AGENT_MNEMONIC'];
  if (!agentMnemonic) {
    const wallet = await DirectSecp256k1HdWallet.generate(24, { prefix: PREFIX });
    agentMnemonic = wallet.mnemonic;
    updates['AGENT_MNEMONIC'] = agentMnemonic;
    console.log('Generated new AGENT wallet.');
  } else {
    console.log('AGENT wallet already present in .env.local — keeping it.');
  }

  let feeMnemonic = existing['ISSUER_FEE_MNEMONIC'];
  if (!feeMnemonic) {
    const wallet = await DirectSecp256k1HdWallet.generate(24, { prefix: PREFIX });
    feeMnemonic = wallet.mnemonic;
    updates['ISSUER_FEE_MNEMONIC'] = feeMnemonic;
    console.log('Generated new ISSUER fee-payer wallet.');
  } else {
    console.log('ISSUER fee-payer wallet already present in .env.local — keeping it.');
  }

  if (Object.keys(updates).length > 0) {
    writeEnvLocal(updates);
  }

  const agentAddress = await addressOf(agentMnemonic);
  const feeAddress = await addressOf(feeMnemonic);

  console.log('\nFund BOTH addresses via the cheqd testnet faucet');
  console.log('(https://testnet-faucet.cheqd.io — or the faucet channel in the cheqd Discord):\n');
  console.log(`  AGENT wallet:  ${agentAddress}`);
  console.log(`  FEE payer:     ${feeAddress}`);
  console.log('\nThen: npm run check:b');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
