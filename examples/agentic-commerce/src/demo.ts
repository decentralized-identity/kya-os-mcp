#!/usr/bin/env npx tsx
/**
 * One command for the stage: start the Responsible Party's hub and the
 * merchant edge in one process (two ports, two identities, real HTTP between
 * them), then open the console.
 *
 *   npm run demo
 *   KEY_WEBAUTHN=1 npm run demo      # revocation requires an authenticator touch
 *   OFFLINE=1 npm run demo           # RP DID document from the local mirror
 */
import { MERCHANT_PORT, RP_PORT } from './lib/wiring.js';
import { startRpServer } from './rp/server.js';
import { startMerchantServer } from './merchant/server.js';

startRpServer(RP_PORT);
await startMerchantServer();
console.log(`\nConsole: http://localhost:${MERCHANT_PORT}/   (keys: 0 discover · 1 order · 2 wrong product · 3 over cap · 5 stolen credential · K revoke · 4 retry · V python re-verify · A anchor ledger · T tamper · E export bundle · R reset · P presenter · C contrast)`);
