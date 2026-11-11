#!/usr/bin/env npx tsx
/**
 * One-time setup. Idempotent: existing keys are kept.
 *
 *   1. Responsible Party: Ed25519 key + did:web document → var/rp/did.json
 *      (publish it at the DID's /.well-known/did.json for a public did:web; the
 *      hub serves the same document locally either way)
 *   2. Merchant edge: Ed25519 key, did:key
 *   3. Shopping agent: Ed25519 key, did:key
 *   4. The RP's revocation list (all clear) → var/rp/status-list.json
 *   5. Start the agent with no active delegation; the human issues through consent.
 */
import { generateDidKeyFromBase64 } from '@kya-os/mcp';
import { readEnvLocal, writeEnvLocal } from '../src/lib/env-local.js';
import { cryptoProvider, RP_DID, STATUS_LIST_URL } from '../src/lib/wiring.js';

async function ensureKey(prefix: 'RP' | 'MERCHANT' | 'AGENT', privName: string, pubName: string): Promise<{ privateKey: string; publicKey: string }> {
  const current = readEnvLocal();
  if (current[privName] && current[pubName]) return { privateKey: current[privName]!, publicKey: current[pubName]! };
  const kp = await cryptoProvider.generateKeyPair();
  writeEnvLocal({ [privName]: kp.privateKey, [pubName]: kp.publicKey });
  console.log(`generated ${prefix} key`);
  return kp;
}

async function main() {
  // 1. Responsible Party (did:web)
  const rp = await ensureKey('RP', 'RP_PRIVATE_KEY_BASE64', 'RP_PUBLIC_KEY_BASE64');
  // The kid is derived from the DID, so it follows a changed RP_DID.
  writeEnvLocal({ RP_DID });
  writeEnvLocal({ RP_KID: `${RP_DID}#key-1` }, { overwrite: true });

  // 2. Merchant (did:key)
  const merchant = await ensureKey('MERCHANT', 'MERCHANT_PRIVATE_KEY_BASE64', 'MERCHANT_PUBLIC_KEY_BASE64');
  const merchantDid = generateDidKeyFromBase64(merchant.publicKey);
  writeEnvLocal({ MERCHANT_DID: merchantDid });

  // 3. Agent (did:key)
  const agent = await ensureKey('AGENT', 'AGENT_ED25519_PRIVATE_KEY_BASE64', 'AGENT_ED25519_PUBLIC_KEY_BASE64');
  const agentDid = generateDidKeyFromBase64(agent.publicKey);
  writeEnvLocal({ AGENT_DID: agentDid });

  // Reload env so the modules below see the fresh values.
  for (const [k, v] of Object.entries(readEnvLocal())) process.env[k] = v;

  // 4 + 5: the list and a clean agent store (imports after env is populated).
  const { ensureDidDocument } = await import('../src/rp/server.js');
  const { ensureStatusList } = await import('../src/rp/statuslist.js');
  const { clearActiveCredential, nextDelegationIndex } = await import('../src/rp/issue.js');
  const { makeVcSigningFunction, loadRpIdentity } = await import('../src/lib/wiring.js');

  const identity = loadRpIdentity();
  const didDoc = ensureDidDocument(identity);
  await ensureStatusList({ identity, signingFunction: makeVcSigningFunction(identity.privateKeyBase64), url: STATUS_LIST_URL });
  clearActiveCredential();
  (await import('../src/agent/store.js')).clearAgentState();
  const { ConsentFlowStore } = await import('../src/rp/consent-store.js');
  new ConsentFlowStore().invalidatePending();
  const index = nextDelegationIndex();

  void rp;
  console.log(JSON.stringify({
    responsibleParty: { did: identity.did, kid: identity.kid, didDocument: 'var/rp/did.json', verificationMethods: didDoc.verificationMethod?.length ?? 0 },
    merchant: { did: merchantDid },
    agent: { did: agentDid },
    statusList: STATUS_LIST_URL,
    delegation: { active: false, reservedIndex: index, next: 'place_order returns a consent URL; the human approves the grant' },
    next: 'npm run demo  →  http://localhost:4949/',
  }, null, 2));
}

main().catch((err) => { console.error(err); process.exit(1); });
