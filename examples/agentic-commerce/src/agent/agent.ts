#!/usr/bin/env npx tsx
/**
 * THE AGENT — a real MCP client, the thing being governed.
 *
 * 1. DISCOVER: read the merchant's /.well-known/mcp and decide whether the
 *    merchant accepts the authority the agent holds (scheme, DID methods,
 *    algorithms, clock skew, audience) — BEFORE presenting anything.
 * 2. ACT: call `place_order` over Streamable HTTP, presenting
 *      - its Delegation Credential (`_kyaos_delegation`) from the Responsible
 *        Party, scoped to one GS1 Digital Link product class, and
 *      - a per-request holder proof (`_kyaos_proof`) signed by its OWN did:key
 *        (the shipped `generateRequestProof`). The merchant runs
 *        holderBinding: 'enforce', so a stolen credential without this key is
 *        refused before any handler runs.
 *
 * Runnable standalone:
 *   npm run agent -- discover
 *   npm run agent -- order --product risotto --quantity 2
 *   npm run agent -- order --product olive-oil          # outside the scope
 *   npm run agent -- order --product risotto --quantity 5   # over the cap
 *   npm run agent -- order --product risotto --forge    # stolen credential, wrong key
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { generateDidKeyFromBase64, generateRequestProof, type DelegationCredential } from '@kya-os/mcp';
import { cryptoProvider, loadAgentIdentity, merchantOrigin, requiredEnv, rpOrigin, SCOPE_PRODUCT_CLASS, type KeyedIdentity } from '../lib/wiring.js';
import { readAgentState, saveAgentState } from './store.js';
import { ConsentProtocol } from '../lib/consent-protocol.js';
import { verifyConsentEvidence, tokenReference } from '../lib/consent-evidence.js';
import type { ConsentChallenge } from '../lib/consent-contract.js';
import { responseBody, verifyMerchantOrderResponse, type MerchantToolResult } from './authorization.js';
import { isMainModule } from '../lib/main-module.js';
import type { DiscoveryDocument } from '../merchant/well-known.js';

export interface DiscoveryDecision {
  document: DiscoveryDocument;
  accepted: boolean;
  scheme: Record<string, unknown> | null;
  audience: string;
  clockSkewSeconds: number;
  reasons: string[];
  elapsedMs: number;
}

export const SCHEME_ID = 'org.kya-os/delegation';

/** Read the merchant's discovery document and decide whether to present. */
export async function discover(origin = merchantOrigin(), identity?: KeyedIdentity): Promise<DiscoveryDecision> {
  const started = Date.now();
  const res = await fetch(`${origin}/.well-known/mcp`, { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`discovery failed: HTTP ${res.status}`);
  const document = (await res.json()) as DiscoveryDocument;
  const reasons: string[] = [];
  const scheme = (document.acceptedTrustSchemes ?? []).find((s) => s['id'] === SCHEME_ID) ?? null;
  if (!scheme) reasons.push(`merchant does not list ${SCHEME_ID} in acceptedTrustSchemes`);
  const myDid = identity?.did ?? safeAgentDid();
  const myMethod = myDid ? myDid.split(':').slice(0, 2).join(':') : 'did:key';
  if (!(document.supportedDidMethods ?? []).includes(myMethod)) reasons.push(`merchant does not resolve ${myMethod}`);
  if (!(document.proofAlgorithms ?? []).includes('EdDSA')) reasons.push('merchant does not accept EdDSA proofs');
  if (!document.serverDid) reasons.push('merchant publishes no DID to bind the audience to');
  return {
    document,
    accepted: reasons.length === 0,
    scheme,
    audience: document.serverDid,
    clockSkewSeconds: document.clockSkewSeconds ?? 120,
    reasons,
    elapsedMs: Date.now() - started,
  };
}

function safeAgentDid(): string | null {
  try { return loadAgentIdentity().did; } catch { return null; }
}

export interface AgentOrderOutcome {
  checkoutId?: string;
  result: MerchantToolResult;
  elapsedMs: number;
  agentDid: string;
  presented: { product: string; quantity: number; credentialId: string | null; audience: string };
}

/**
 * One order attempt over MCP with a fresh holder proof. The approved grant
 * is read from agent-owned storage on every call.
 * Pending credentials are picked up from the RP over authenticated HTTP.
 */
export interface AgentOrderOptions {
  product: string;
  quantity?: number;
  serverUrl?: string;
  audience?: string;
  identity?: KeyedIdentity;
  /** Explicit null models an agent with no grant; omitted reloads the local store. */
  credential?: DelegationCredential | null;
  /** Theft simulation: present the REAL credential, sign the proof with a fresh key. */
  forge?: boolean;
  /** Gateway-owned checkout context; never supplied directly by the LLM. */
  checkout?: { id: string; protocol: 'x402' | 'ucp'; termsDigest?: string };
  /** Standard x402 MCP transport metadata, bound to the pinned checkout. */
  payment?: Record<string, unknown>;
}
// One single-user gateway owns this store. Serialize its application transitions
// across stateless MCP connections so overlapping challenge/pickup requests
// cannot overwrite each other's pending grant.
let orderTail: Promise<unknown> = Promise.resolve();
export function serializeAgentOperation<T>(operation: () => Promise<T>): Promise<T> {
  const next = orderTail.then(operation);
  orderTail = next.catch(() => {});
  return next;
}
export function runAgentOrder(options: AgentOrderOptions): Promise<AgentOrderOutcome> {
  if (options.credential !== undefined) return performAgentOrder(options);
  return serializeAgentOperation(() => performAgentOrder(options));
}

/** Shared pickup and proof preparation for MCP and UCP transports. */
export async function prepareAgentOrder(options: AgentOrderOptions) {
  let identity = options.identity ?? loadAgentIdentity();
  if (options.forge) {
    const stolen = await cryptoProvider.generateKeyPair();
    const thiefDid = generateDidKeyFromBase64(stolen.publicKey);
    identity = { did: thiefDid, kid: `${thiefDid}#${thiefDid.replace('did:key:', '')}`, privateKeyBase64: stolen.privateKey, publicKeyBase64: stolen.publicKey };
  }
  const local = options.credential === undefined;
  let state = readAgentState();
  let credential = local ? state.credential ?? null : options.credential;
  const quantity = options.quantity ?? 1;
  // The demo pins the merchant identity locally. Neither an unverified
  // credential nor network discovery may replace this trust anchor.
  const audience = options.audience ?? requiredEnv('MERCHANT_DID');
  if (local && !credential && state.pending && !options.forge) {
    const pickup = await new ConsentProtocol().request('/consent/pickup', 'consent.pickup', {
      resumeToken: state.pending.resumeToken, audience,
    }, identity);
    if (pickup['state'] === 'approved') {
      const received = pickup['credential'] as DelegationCredential;
      const consent = verifyConsentEvidence(received, requiredEnv('RP_DID'));
      if (received.credentialSubject.id !== identity.did || consent.audience !== audience
        || consent.consentRef !== tokenReference(state.pending.resumeToken)) throw new Error('CONSENT_BINDING_MISMATCH: credential pickup does not belong to this agent and consent request');
      state = { credential: received };
      saveAgentState(state);
      credential = received;
    } else if (pickup['state'] === 'pending' && state.challengeResult) {
      // This is the previously verified challenge, not a new merchant decision.
      // Keep its URL stable while the human is approving it.
      return { identity, audience, credential: null, quantity, args: null, pendingResult: state.challengeResult };
    } else if (['denied', 'expired', 'failed'].includes(String(pickup['state']))) {
      state = {};
      saveAgentState(state);
    } else throw new Error('CONSENT_PROTOCOL_INVALID: unexpected pickup state');
  }
  const args: Record<string, unknown> = { product: options.product, quantity,
    ...(options.checkout ? { checkout: options.checkout } : {}),
    ...(credential ? { _kyaos_delegation: credential } : {}),
  };
  args['_kyaos_proof'] = await generateRequestProof({
    identity: { did: identity.did, kid: identity.kid, privateKey: identity.privateKeyBase64, publicKey: identity.publicKeyBase64 },
    crypto: cryptoProvider,
    toolName: 'place_order',
    args,
    audience,
  });
  return { identity, audience, credential, quantity, args, pendingResult: null };
}

/** Validates signed merchant evidence before any payment or consent action. */
export async function acceptMerchantOrderResult(result: MerchantToolResult, args: Record<string, unknown>, identity: KeyedIdentity, audience: string, saveChallenge = true): Promise<void> {
  const consentOrigin = new URL(rpOrigin());
  if (consentOrigin.hostname === 'localhost') consentOrigin.hostname = '127.0.0.1';
  await verifyMerchantOrderResponse(result, { args, merchantDid: audience, agentDid: identity.did,
    consentOrigin: consentOrigin.origin, scope: SCOPE_PRODUCT_CLASS });
  if (saveChallenge && responseBody(result)['error'] === 'needs_authorization') {
    saveAgentState({ pending: responseBody(result) as unknown as ConsentChallenge, challengeResult: result });
  }
}

/** Caller must hold serializeAgentOperation when using the shared wallet. */
export async function performAgentOrder(options: AgentOrderOptions): Promise<AgentOrderOutcome> {
  const serverUrl = options.serverUrl ?? `${merchantOrigin()}/mcp`;
  const { identity, audience, credential, quantity, args, pendingResult } = await prepareAgentOrder(options);
  const presented = { product: options.product, quantity, credentialId: credential?.id ?? null, audience };
  if (pendingResult) return { result: pendingResult, elapsedMs: 0, agentDid: identity.did, presented };

  const client = new Client({ name: 'shopping-agent', version: '0.1.0' });
  const transport = new StreamableHTTPClientTransport(new URL(serverUrl));
  const started = Date.now();
  await client.connect(transport);
  try {
    const result = await client.callTool({ name: 'place_order', arguments: args!,
      ...(options.payment ? { _meta: { 'x402/payment': options.payment } } : {}) }) as MerchantToolResult;
    await acceptMerchantOrderResult(result, args!, identity, audience, options.credential === undefined && !options.forge);
    return {
      result: result as AgentOrderOutcome['result'],
      elapsedMs: Date.now() - started,
      agentDid: identity.did,
      presented,
    };
  } finally {
    await client.close();
  }
}

/** Unauthenticated read — the "agent-visible" half. */
export async function browseCatalog(serverUrl = `${merchantOrigin()}/mcp`): Promise<unknown> {
  const client = new Client({ name: 'shopping-agent', version: '0.1.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(serverUrl)));
  try {
    const r = await client.callTool({ name: 'get_catalog', arguments: {} });
    const text = (r as { content?: Array<{ text?: string }> }).content?.[0]?.text ?? '[]';
    return JSON.parse(text);
  } finally {
    await client.close();
  }
}

if (isMainModule(import.meta.url)) {
  const [, , cmd = 'order', ...rest] = process.argv;
  const arg = (name: string, fallback?: string) => { const i = rest.indexOf(`--${name}`); return i > -1 ? rest[i + 1] : fallback; };
  const run = async () => {
    if (cmd === 'discover') {
      const d = await discover();
      console.log(JSON.stringify({ accepted: d.accepted, reasons: d.reasons, audience: d.audience, clockSkewSeconds: d.clockSkewSeconds, scheme: d.scheme }, null, 2));
      return;
    }
    if (cmd === 'browse') { console.log(JSON.stringify(await browseCatalog(), null, 2)); return; }
    const outcome = await runAgentOrder({
      product: arg('product', 'risotto')!,
      quantity: Number(arg('quantity', '1')),
      forge: rest.includes('--forge'),
    });
    const text = outcome.result.content?.[0]?.text ?? '';
    let body: Record<string, unknown> = {};
    try { body = JSON.parse(text); } catch { body = { raw: text }; }
    const needsConsent = body['error'] === 'needs_authorization';
    const denied = Boolean(outcome.result.isError || body['error']);
    const verdict = needsConsent ? 'NEEDS_AUTHORIZATION' : denied ? 'DENIED' : 'ALLOWED';
    console.log(JSON.stringify({ agent: outcome.agentDid, tool: 'place_order', ...outcome.presented, elapsedMs: outcome.elapsedMs, verdict, ...body }, null, 2));
    process.exit(denied && !needsConsent ? 1 : 0);
  };
  run().catch((err) => { console.error('agent error:', err instanceof Error ? err.message : err); process.exit(2); });
}
