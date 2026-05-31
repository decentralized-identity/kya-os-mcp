#!/usr/bin/env npx tsx
/**
 * Run this to get a delegation VC you can pass to restricted_greet.
 *
 * Usage:
 *   npx tsx examples/node-server/issue-delegation.ts
 *
 * Then copy the printed JSON and pass it as `_kyaos_delegation` when calling
 * restricted_greet via MCP Inspector.
 */

import { NodeCryptoProvider } from './node-crypto.js';
import {
  generateDidKeyFromBase64,
  DelegationCredentialIssuer,
  base64urlEncodeFromBytes,
  type Proof,
} from '@kya-os/mcp';

async function main() {
  const crypto = new NodeCryptoProvider();
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  
  const kid = `${did}#${did.replace('did:key:', '')}`;

  process.stderr.write(`[issue-delegation] Issuer DID: ${did}\n`);

  const signingFunction = async (
    canonicalVC: string,
    _issuerDid: string,
    kidArg: string,
  ): Promise<Proof> => {
    const data = new TextEncoder().encode(canonicalVC);
    const sigBytes = await crypto.sign(data, keyPair.privateKey);
    const proofValue = base64urlEncodeFromBytes(sigBytes);
    return {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: kidArg,
      proofPurpose: 'assertionMethod',
      proofValue,
    };
  };

  const issuer = new DelegationCredentialIssuer(
    {
      getDid: () => did,
      getKeyId: () => kid,
      getPrivateKey: () => keyPair.privateKey,
    },
    signingFunction,
  );

  const delegationId = `delegation-${Date.now()}`;
  const vc = await issuer.createAndIssueDelegation(
    {
      id: delegationId,
      issuerDid: did,
      subjectDid: did,
      constraints: {
        scopes: ['greeting:restricted'],
        notAfter: Math.floor(Date.now() / 1000) + 3600, // valid for 1 hour
      },
    },
  );

  process.stdout.write(JSON.stringify(vc, null, 2) + '\n');
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${err}\n`);
  process.exit(1);
});
