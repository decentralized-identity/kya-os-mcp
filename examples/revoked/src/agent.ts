#!/usr/bin/env npx tsx
/**
 * THE AGENT — a real MCP client, the thing being governed.
 *
 * Connects to the protected MCP server over Streamable HTTP and calls
 * `wallet_send`, presenting:
 *   1. its Delegation Credential (`_kyaos_delegation`) — the scoped authority
 *      issued by the did:cheqd Responsible Party, and
 *   2. a per-request holder proof (`_kyaos_proof`) — a detached proof signed
 *      by the agent's OWN did:key, minted with the shipped
 *      `generateRequestProof`. The server runs holderBinding: 'enforce', so a
 *      stolen credential without the agent's key is refused (spec §11.8).
 *
 * The wallet never leaves the server (custodian); the agent holds authority,
 * not keys to the funds. Runnable standalone for the live demo:
 *
 *   npm run agent -- --amount 1
 *   npm run agent -- --amount 100        # over the in-credential cap
 */
import fs from 'node:fs';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {
  generateRequestProof,
  type DelegationCredential,
} from '@kya-os/mcp';
import { cryptoProvider, env, requiredEnv, VAR_DIR } from './lib/wiring.js';

export interface AgentIdentity {
  did: string;
  kid: string;
  privateKey: string;
  publicKey: string;
}

export function loadAgentIdentity(): AgentIdentity {
  const did = requiredEnv('AGENT_DID');
  return {
    did,
    kid: `${did}#${did.replace('did:key:', '')}`,
    privateKey: requiredEnv('AGENT_ED25519_PRIVATE_KEY_BASE64'),
    publicKey: requiredEnv('AGENT_ED25519_PUBLIC_KEY_BASE64'),
  };
}

function activeCredential(): DelegationCredential {
  const indexFile = path.join(VAR_DIR, 'active-index');
  const index = fs.existsSync(indexFile) ? fs.readFileSync(indexFile, 'utf-8').trim() : '94';
  const file = path.join(VAR_DIR, `delegation-${index}.json`);
  if (!fs.existsSync(file)) {
    throw new Error(`Agent has no credential at ${file} — the issuer must run issue:delegation first`);
  }
  return JSON.parse(fs.readFileSync(file, 'utf-8')) as DelegationCredential;
}

export interface AgentSendOutcome {
  /** The raw MCP tool result (content, isError, _meta with the server's signed receipt). */
  result: {
    content?: Array<{ type: string; text?: string }>;
    isError?: boolean;
    _meta?: Record<string, unknown>;
  };
  elapsedMs: number;
  agentDid: string;
}

/**
 * One delegated spend, over the wire: connect → tools/call wallet_send with
 * credential + fresh holder proof → disconnect.
 */
export async function runAgentSend(options: {
  amount: string;
  to?: string;
  serverUrl?: string;
  /**
   * Theft-replay simulation: present the agent's REAL credential but sign the
   * holder proof with a freshly generated key — a thief who stole the VC
   * string but not the agent's private key. Must be refused
   * (holder_binding_failed) before the handler is entered.
   */
  forge?: boolean;
}): Promise<AgentSendOutcome> {
  const serverUrl = options.serverUrl ?? `http://localhost:${env('DEMO_PORT', '4949')}/mcp`;
  let identity = loadAgentIdentity();
  if (options.forge) {
    const { generateDidKeyFromBase64 } = await import('@kya-os/mcp');
    const stolen = await cryptoProvider.generateKeyPair();
    const thiefDid = generateDidKeyFromBase64(stolen.publicKey);
    identity = {
      did: thiefDid,
      kid: `${thiefDid}#${thiefDid.replace('did:key:', '')}`,
      privateKey: stolen.privateKey,
      publicKey: stolen.publicKey,
    };
  }
  const credential = activeCredential();
  const audience = requiredEnv('CHEQD_DID'); // the server's DID (the Responsible Party)

  const args: Record<string, unknown> = {
    amount: options.amount,
    ...(options.to ? { to: options.to } : {}),
    _kyaos_delegation: credential,
  };

  // Holder proof binds tool name + business args (control args stripped) with a
  // fresh nonce — a thief replaying the credential without this key gets
  // holder_binding_failed before the handler is ever entered.
  //
  // sessionId quirk (still present in 1.14.0): generateRequestProof defaults a
  // sessionless call to sessionId '' — which validateDetachedProof then
  // rejects as INVALID_PROOF_STRUCTURE (non-empty required), so sessionless
  // holder binding can never verify. A synthetic id satisfies structure;
  // replay safety rides on the per-call nonce.
  args['_kyaos_proof'] = await generateRequestProof({
    identity,
    crypto: cryptoProvider,
    toolName: 'wallet_send',
    args,
    audience,
    sessionId: `sessionless-${Date.now().toString(36)}`,
  });

  const client = new Client({ name: 'revoked-agent', version: '0.1.0' });
  const transport = new StreamableHTTPClientTransport(new URL(serverUrl));
  const started = Date.now();
  await client.connect(transport);
  try {
    const result = await client.callTool({ name: 'wallet_send', arguments: args });
    return {
      result: result as AgentSendOutcome['result'],
      elapsedMs: Date.now() - started,
      agentDid: identity.did,
    };
  } finally {
    await client.close();
  }
}

const isMain = process.argv[1]?.endsWith('agent.ts');
if (isMain) {
  const amountArg = process.argv.indexOf('--amount');
  const amount = amountArg > -1 ? process.argv[amountArg + 1]! : '1';
  const toArg = process.argv.indexOf('--to');
  const forge = process.argv.includes('--forge');

  runAgentSend({ amount, forge, ...(toArg > -1 ? { to: process.argv[toArg + 1]! } : {}) })
    .then((outcome) => {
      const text = outcome.result.content?.[0]?.text ?? '';
      let body: Record<string, unknown> = {};
      try { body = JSON.parse(text); } catch { body = { raw: text }; }
      console.log(JSON.stringify({
        agent: outcome.agentDid,
        tool: 'wallet_send',
        amountCheq: amount,
        elapsedMs: outcome.elapsedMs,
        verdict: outcome.result.isError ? 'DENIED' : 'ALLOWED',
        ...body,
      }, null, 2));
      process.exit(outcome.result.isError ? 1 : 0);
    })
    .catch((err) => {
      console.error('agent error:', err instanceof Error ? err.message : err);
      process.exit(2);
    });
}
