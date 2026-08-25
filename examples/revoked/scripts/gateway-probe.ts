#!/usr/bin/env npx tsx
/**
 * Stand-in for Claude Desktop: spawns the gateway over stdio exactly as
 * Claude Desktop's local config would, lists its tools, and calls
 * check_balance + wallet_send. Proves the whole chain
 * (client → gateway → protected server → cheqd) minus the LLM.
 *
 *   npm run gateway:probe -- --amount 1
 *   npm run gateway:probe -- --amount 100   # over the cap
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

async function main() {
  const amountArg = process.argv.indexOf('--amount');
  const amount = amountArg > -1 ? process.argv[amountArg + 1]! : '1';

  // Absolute path + a deliberately foreign cwd (/) — exactly how Claude Desktop
  // spawns a local stdio server. Proves the gateway anchors .env.local / var/
  // to the repo, not to the working directory.
  const gatewayPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'gateway.ts');
  const transport = new StdioClientTransport({
    command: 'npx',
    args: ['tsx', gatewayPath],
    cwd: '/',
    env: process.env as Record<string, string>,
  });
  const client = new Client({ name: 'gateway-probe', version: '0.1.0' });
  await client.connect(transport);

  const tools = await client.listTools();
  console.log('gateway tools:', tools.tools.map((t) => t.name).join(', '));

  const balance = await client.callTool({ name: 'check_balance', arguments: {} });
  console.log('\ncheck_balance →\n' + (balance.content as Array<{ text: string }>)[0]!.text);

  console.log(`\nwallet_send { amount: ${amount} } →`);
  const send = await client.callTool({ name: 'wallet_send', arguments: { amount } });
  console.log((send.content as Array<{ text: string }>)[0]!.text);
  console.log('isError:', send.isError ?? false);

  await client.close();
  process.exit(0);
}

main().catch((err) => {
  console.error('probe error:', err);
  process.exit(1);
});
