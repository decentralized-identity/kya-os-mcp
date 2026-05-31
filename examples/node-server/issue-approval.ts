#!/usr/bin/env npx tsx
/**
 * Mint a signed step-up approval grant for a `delete_record` call.
 *
 * Usage:
 *   1. Call `delete_record` in the Inspector → you get a `needs_approval` error
 *      carrying a `requestHash`.
 *   2. npx tsx examples/node-server/issue-approval.ts <requestHash>
 *   3. Paste the printed array as the `_kyaos_approvals` argument and re-call
 *      `delete_record` with the SAME `record` value → it proceeds.
 */
import { mintSignedApproval } from './approval-demo.js';

async function main() {
  const requestHash = process.argv[2];
  if (!requestHash) {
    process.stderr.write(
      'Usage: npx tsx examples/node-server/issue-approval.ts <requestHash>\n' +
        '  (copy requestHash from the delete_record needs_approval response)\n',
    );
    process.exit(1);
  }
  const { grant, approverDid } = await mintSignedApproval(requestHash);
  process.stderr.write(`[issue-approval] Approver DID: ${approverDid}\n`);
  process.stderr.write('[issue-approval] Paste this as the _kyaos_approvals argument (an ARRAY):\n');
  process.stdout.write(JSON.stringify([grant], null, 2) + '\n');
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${err}\n`);
  process.exit(1);
});
