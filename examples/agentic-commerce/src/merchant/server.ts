#!/usr/bin/env npx tsx
/**
 * The MERCHANT EDGE — one process, four surfaces:
 *
 *   1. /.well-known/mcp   the discovery document an agent reads first: the
 *                         merchant's DID, algorithms, clock-skew tolerance and
 *                         the trust schemes it accepts (`acceptedTrustSchemes`).
 *   2. POST /mcp          a REAL MCP server (Streamable HTTP). `get_catalog` is
 *                         open (agent-visible); `place_order` is gated by the
 *                         SHIPPED withKyaOs delegation middleware: signature →
 *                         revocation (fetched from the Responsible Party's list
 *                         on every call) → holder key → scope; then the handler
 *                         reads the product class and the cap out of the same
 *                         credential. Point mcp-inspector at it — nothing
 *                         demo-specific in the gate.
 *   3. /api/*             act routes the console uses. "Agent orders" drives a
 *                         real MCP client against our own /mcp.
 *   4. /                  the verifier console (web/).
 *   5. /api/audit/*       the SHIPPED audit protocol: every gate decision above
 *                         is a signed, hash-chained ledger entry; `A` anchors an
 *                         RFC 9162 checkpoint (witnessed by the RP), `T` shows
 *                         an insider's edit failing, `E` exports the replay
 *                         bundle for `npx kya-audit verify`.
 *
 * Low-level SDK `Server` (not McpServer.registerTool): delegation-protected
 * tools receive `_kyaos_delegation` as a tool argument, and registerTool's zod
 * validation would strip it.
 */
import http from 'node:http';
import path from 'node:path';
import { isMainModule } from '../lib/main-module.js';
import { createHash } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { spawn } from 'node:child_process';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { Hono } from 'hono';
import { createMiddleware } from 'hono/factory';
import { streamSSE } from 'hono/streaming';
import { getRequestListener } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import {
  createKyaOsMiddleware,
  assertHolderBinding,
  toHolderBindingRequest,
  ProofVerifier,
  ProofGenerator,
  SystemClockProvider,
  MemoryNonceCacheProvider,
  type DetachedProof,
  didWebToUrl,
  KYA_OS_PROOF_META_KEY,
  type DelegationCredential,
  type KyaOsMiddleware,
} from '@kya-os/mcp';
import {
  EXAMPLE_ROOT,
  MERCHANT_PORT,
  RP_DID,
  RP_DID_MIRROR_URL,
  STATUS_LIST_URL,
  SCOPE_PRODUCT_CLASS,
  SPEND_CAP,
  SPEND_CURRENCY,
  VALID_HOURS,
  WEB_DIR,
  VAR_DIR,
  cryptoProvider,
  env,
  flag,
  gzipCompressor,
  gzipDecompressor,
  loadMerchantIdentity,
  rpOrigin,
  type KeyedIdentity,
  GATEWAY_TOKEN,
  ADMIN_TOKEN,
  adminTokenOk,
  publicHosts,
  merchantOrigin,
} from '../lib/wiring.js';
import { DemoFetchProvider } from '../lib/mirror-fetch.js';
import { HttpStatusListResolver, ed25519PublicKeyBase64 } from '../lib/http-statuslist-resolver.js';
import { requireCredentialStore } from './require-credential-store.js';
import { createMerchantAudit } from './audit.js';
import type { AuditInsiderEdit } from '../lib/party-audit.js';
import type { ConsentChallenge } from '../lib/consent-contract.js';
import { consentDigest, verifyConsentEvidence, tokenReference } from '../lib/consent-evidence.js';
import { ConsentProtocol, signMessage } from '../lib/consent-protocol.js';
import { clearAgentState } from '../agent/store.js';
import { CATALOG } from '../lib/product.js';
import { buildDiscoveryDocument } from './well-known.js';
import { evaluateOrder, allocateOrderId, summarizeMandate, type Mandate, type ApprovedOrderQuote } from './place-order.js';
import type { MerchantToolResult } from '../agent/authorization.js';
import { discover, runAgentOrder, serializeAgentOperation } from '../agent/agent.js';
import { createGatewayServer } from '../agent/gateway.js';
import { handleStatelessMcp } from '../lib/stateless-mcp.js';
import { ResponseProofContext } from '../lib/response-proof-context.js';
import { mountCommerce, x402McpResult } from '../commerce/mount.js';
import { RunBoundary } from '../lib/run-boundary.js';

export interface MerchantAppConfig {
  identity: KeyedIdentity;
  name: string;
  port: number;
  /** Listener address; loopback locally, 0.0.0.0 behind a deployment proxy. */
  bindHost?: string;
  rpDid: string;
  rpDidMirrorUrl: string;
  statusListUrl: string;
  rpOrigin: string;
  offline: boolean;
  allowInsecureLocalhost: boolean;
  statusCacheTtlMs: number;
  pythonVerifier: string | null;
  /** Ask the Responsible Party to witness each audit checkpoint (AUDIT_WITNESS=0 to disable). */
  witness: boolean;
  /** Where exported replay bundles land (default var/audit). */
  auditDir?: string;
  /** Public origin advertised by checkout discovery (including reverse proxies). */
  origin?: string;
}

/** Server-owned effect invoked only after the common KYA and business gates. */
export interface OrderExecutionResult {
  body: Record<string, unknown>;
  isError?: boolean;
  /** False for an idempotent replay of an already committed order. */
  committed?: boolean;
}
export type OrderExecution = (input: {
  outcome: ApprovedOrderQuote;
  vc: DelegationCredential;
  evidence: Record<string, unknown>;
}) => OrderExecutionResult | Promise<OrderExecutionResult>;

export function merchantConfigFromEnv(overrides: Partial<MerchantAppConfig> = {}): MerchantAppConfig {
  return {
    identity: loadMerchantIdentity(),
    name: env('MERCHANT_NAME', 'Dal Giardino Direct (demo merchant)'),
    port: MERCHANT_PORT,
    bindHost: env('BIND_HOST', '127.0.0.1'),
    rpDid: RP_DID,
    rpDidMirrorUrl: RP_DID_MIRROR_URL,
    statusListUrl: STATUS_LIST_URL,
    rpOrigin: rpOrigin(),
    offline: flag('OFFLINE'),
    allowInsecureLocalhost: env('ALLOW_INSECURE_LOCALHOST', '1') === '1',
    statusCacheTtlMs: Number(env('STATUS_CACHE_TTL_MS', '0')),
    pythonVerifier: path.join(EXAMPLE_ROOT, 'scripts', 'verify-receipt.py'),
    witness: env('AUDIT_WITNESS', '1') === '1',
    ...overrides,
  };
}

type GateState = 'pass' | 'fail' | 'skip' | 'pending';
export interface GateChecks {
  signature: GateState; revocation: GateState; holder: GateState;
  product: GateState; cap: GateState; consent: GateState; receipt: GateState;
}

/** Refresh the mutable authority evidence at the rail's final reversible step. */
export async function verifySettlementAuthority(vc: DelegationCredential, resolver: {
  invalidateCache(): void;
  checkStatus(status: NonNullable<DelegationCredential['credentialStatus']>): Promise<boolean>;
}, observed: Partial<GateChecks> = {}): Promise<void> {
  resolver.invalidateCache();
  const constraints = vc.credentialSubject.delegation.constraints;
  const checkWindow = () => {
    const now = Date.now();
    if ((constraints.notAfter !== undefined && now / 1000 >= constraints.notAfter)
      || (vc.expirationDate && now >= Date.parse(vc.expirationDate))) {
      observed.signature = 'fail';
      throw new Error('AUTHORITY_EXPIRED: The delegation expired before payment. No payment was submitted.');
    }
  };
  checkWindow();
  let revoked: boolean;
  try {
    if (!vc.credentialStatus) throw new Error('Missing credential status');
    revoked = await resolver.checkStatus(vc.credentialStatus);
  } catch {
    observed.revocation = 'fail';
    throw new Error('AUTHORITY_STATUS_UNAVAILABLE: Current revocation status could not be established. No payment was submitted.');
  }
  if (revoked) {
    observed.revocation = 'fail';
    throw new Error('AUTHORITY_REVOKED: The delegation was revoked before payment. No payment was submitted.');
  }
  checkWindow(); // Time may have advanced while the current status was fetched.
}

/**
 * Map an outcome to the seven gates, following the middleware's actual
 * order: basic+signature (window, audience) → status (revocation) → holder
 * binding → flat scope → [handler] product class → spend cap → signed receipt.
 */
export function checksFromOutcome(verdict: 'allowed' | 'denied', code: string | undefined, reason: string, observed: Partial<GateChecks> = {}): GateChecks {
  const skipped: GateChecks = { signature: 'skip', revocation: 'skip', holder: 'skip', product: 'skip', cap: 'skip', consent: 'skip', receipt: 'skip' };
  let inferred: Partial<GateChecks>;
  if (verdict === 'allowed') inferred = { signature: 'pass', revocation: 'pass', holder: 'pass', product: 'pass', cap: 'pass', consent: 'pass', receipt: 'pass' };
  else if (code === 'needs_authorization') inferred = { consent: 'pending' };
  else if (code?.startsWith('CONSENT_')) inferred = { consent: 'fail' };
  else if (code === 'AUTHORITY_EXPIRED') inferred = { signature: 'fail' };
  else if (code === 'AUTHORITY_REVOKED' || code === 'AUTHORITY_STATUS_UNAVAILABLE') inferred = { signature: 'pass', revocation: 'fail' };
  else if (code === 'holder_binding_failed') inferred = { signature: 'pass', revocation: 'pass', holder: 'fail' };
  else if (/revoked|status_unresolvable|status list/i.test(reason)) inferred = { signature: 'pass', revocation: 'fail' };
  else if (['PRODUCT_OUT_OF_SCOPE', 'UNKNOWN_PRODUCT', 'INVALID_PRODUCT_URI', 'INVALID_QUANTITY'].includes(code ?? '')) inferred = { signature: 'pass', revocation: 'pass', holder: 'pass', product: 'fail' };
  else if (['SPEND_CAP_EXCEEDED', 'CURRENCY_MISMATCH', 'NO_CAP_IN_CREDENTIAL'].includes(code ?? '')) inferred = { signature: 'pass', revocation: 'pass', holder: 'pass', product: 'pass', cap: 'fail' };
  else if (code?.startsWith('PAYMENT_') || code?.startsWith('CHECKOUT_') || code === 'SETTLEMENT_PENDING') inferred = { signature: 'pass', revocation: 'pass', holder: 'pass', product: 'pass', cap: 'pass', consent: 'pass' };
  else inferred = { signature: 'fail' };
  // Handler observations override guesses: a later consent/storage failure
  // cannot undo credential or holder checks that have already passed.
  return { ...skipped, ...inferred, ...observed };
}

export async function createMerchant(config: MerchantAppConfig) {
  const { identity } = config;
  const runBoundary = new RunBoundary();

  // ---- outbound trust: the RP's DID document + revocation list ----------------
  const rpDidUrl = didWebToUrl(config.rpDid);
  const fetchProvider = new DemoFetchProvider({
    allowInsecureLocalhost: config.allowInsecureLocalhost,
    mirrors: rpDidUrl ? { [rpDidUrl]: config.rpDidMirrorUrl } : {},
    offline: config.offline,
  });
  const didResolver = { resolve: (did: string) => fetchProvider.resolveDID(did) };
  const statusListResolver = new HttpStatusListResolver({
    fetchProvider,
    didResolver,
    cryptoProvider,
    expectedIssuerDid: config.rpDid,
    compressor: gzipCompressor,
    decompressor: gzipDecompressor,
    cacheTtlMs: config.statusCacheTtlMs,
    allowInsecureLocalhost: config.allowInsecureLocalhost,
  });

  // ---- the shipped audit trail ----------------------------------------------------
  // Every decision the gate makes below lands here as a signed, chained entry;
  // `delivery: 'required'` means a call that cannot be recorded is refused.
  const audit = await createMerchantAudit(identity, {
    witnessUrl: config.witness ? `${config.rpOrigin}/api/rp/audit/observe` : undefined,
    resolvePublicKeyBase64: async (signer) => {
      const doc = await didResolver.resolve(signer.did);
      const method = doc?.verificationMethod?.find((m) => m.id === signer.kid) ?? doc?.verificationMethod?.[0];
      return method ? ed25519PublicKeyBase64(method) : null;
    },
    ...(config.auditDir ? { auditDir: config.auditDir } : {}),
  });

  // ---- the shipped gate ---------------------------------------------------------
  const kyaos: KyaOsMiddleware = createKyaOsMiddleware(
    {
      identity: { did: identity.did, kid: identity.kid, privateKey: identity.privateKeyBase64, publicKey: identity.publicKeyBase64 },
      autoSession: false,
      grantStore: requireCredentialStore,
      delegation: {
        fetchProvider,
        didResolver,
        statusListResolver,
        // Subject-bound, not bearer: the caller must present a per-request
        // proof signed by the delegation SUBJECT's did:key.
        holderBinding: 'enforce',
      },
      audit: audit.middlewareAudit,
    },
    cryptoProvider,
  );
  // Private response-proof metadata, independent of MCP transport sessions and
  // caller authority. Explicit attribution survives concurrent HTTP clients.
  const responseProofContext = new ResponseProofContext(kyaos.sessionManager, identity.did);
  const receiptProofGenerator = new ProofGenerator({ did: identity.did, kid: identity.kid,
    privateKey: identity.privateKeyBase64, publicKey: identity.publicKeyBase64 }, cryptoProvider);

  // The gate strips the `_kyaos_*` control args before the handler runs, so the
  // verified credential reaches the handler through a per-call context: the
  // MCP dispatcher stashes the SAME object the gate verifies, and the handler
  // checks the gate's `authorization.delegationRef` names that credential.
  const callStore = new AsyncLocalStorage<{ vc?: DelegationCredential; args: Record<string, unknown>; agentDid: string; checks: Partial<GateChecks>; challenge?: ConsentChallenge; execution?: OrderExecution }>();
  const consentProtocol = new ConsentProtocol(config.rpDid, config.rpOrigin);
  const decisionAudit = {
    async record(input: Parameters<typeof audit.record>[0]) {
      const recorded = await audit.record(input);
      if (recorded.status !== 'recorded') throw new Error('AUDIT_UNAVAILABLE: merchant decision not recorded');
    },
  };
  const requestVerifier = new ProofVerifier({ cryptoProvider, clockProvider: new SystemClockProvider(), nonceCacheProvider: new MemoryNonceCacheProvider(), fetchProvider });
  let authorizationChallenge: Record<string, unknown> | null = null;
  const refusal = async (code: string, reason: string) => {
    await decisionAudit.record({ eventType: 'authorization.denied', action: { category: 'authorization', name: 'place_order' },
      outcome: 'denied', reason: { code }, evidence: [], details: { family: 'authorization', phase: 'denied' } });
    return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: code, reason }) }] };
  };
  const consentFailure = (code: string, reason: string) => refusal(`CONSENT_${code}`, reason);
  const consentErrorResponse = (error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    const code = /^(CONSENT_[A-Z_]+):/.exec(message)?.[1]?.slice('CONSENT_'.length) ?? 'UNAVAILABLE';
    return consentFailure(code, message);
  };

  // Demo memory: what the merchant has SEEN (for the console), never for trust.
  let lastMandate: Mandate | null = null;
  let lastReceipt: { body: Record<string, unknown>; proof: unknown; at: string; request: { method: string; params: Record<string, unknown> }; content: unknown } | null = null;
  let orders = 0;

  // Invoke this wrapper inside callStore.run: formatChallenge needs the bound
  // request, and the handler must use the same VC the delegation gate verified.
  const placeOrderHandler = kyaos.wrapWithDelegation(
    'place_order',
    {
      scopeId: 'commerce.order', consentUrl: `${config.rpOrigin}/consent`,
      formatChallenge: () => {
        const call = callStore.getStore();
        if (!call?.challenge) throw new Error('No authenticated RP consent challenge in this request');
        return [{ type: 'text', text: JSON.stringify(call.challenge) }];
      },
    },
    kyaos.wrapWithProof('place_order', async (args: Record<string, unknown>, _sessionId?: string, context?: { authorization?: { delegationRef?: string } }) => {
      // The gate has verified signature, window, audience, revocation (fresh),
      // holder key and the flat scope of THIS credential by the time we are here.
      const call = callStore.getStore();
      const vc = call?.vc;
      if (call) Object.assign(call.checks, { signature: 'pass', revocation: 'pass', holder: 'pass' });
      const ref = context?.authorization?.delegationRef;
      if (!vc || (ref && ref !== (vc.id ?? vc.credentialSubject.delegation.id))) {
        return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: 'CREDENTIAL_CONTEXT_MISMATCH', message: 'Fail-closed: the verified credential is not the one in the call context' }) }] };
      }
      // The RP attests to human consent inside this verified credential. The
      // merchant verifies that assertion; it never reads the RP's private files.
      let consent;
      try { consent = verifyConsentEvidence(vc, config.rpDid); }
      catch (error) { return consentErrorResponse(error); }
      if (call) call.checks.consent = 'pass';
      authorizationChallenge = null;
      lastMandate = summarizeMandate(vc);
      const outcome = evaluateOrder({ product: String(args['product'] ?? ''), quantity: Number(args['quantity'] ?? 1) }, vc);
      if (call) Object.assign(call.checks, {
        product: outcome.ok || ['SPEND_CAP_EXCEEDED', 'CURRENCY_MISMATCH', 'NO_CAP_IN_CREDENTIAL'].includes(outcome.error) ? 'pass' : 'fail',
        cap: outcome.ok ? 'pass' : ['SPEND_CAP_EXCEEDED', 'CURRENCY_MISMATCH', 'NO_CAP_IN_CREDENTIAL'].includes(outcome.error) ? 'fail' : 'skip',
      });

      await decisionAudit.record({
        eventType: 'credential.verified', actor: { kind: 'pairwise_did', did: identity.did },
        responsibleParty: { kind: 'public_did', did: config.rpDid },
        correlationId: consent.consentRef, action: { category: 'consent', name: 'verify_rp_consent_attestation' },
        outcome: 'succeeded', resource: { kind: 'keyed_commitment', value: consentDigest(vc), keyId: 'verified-delegation' },
        evidence: [], details: { family: 'consent', phase: 'credential_verified', consentRef: consent.consentRef },
      });

      // The handler's own two gates (product class, cap) go on the same ledger
      // as the middleware's, with the merchant's reason codes. delivery is
      // 'required': a decision the merchant cannot record is a sale it refuses.
      const issuer = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id;
      const recorded = await audit.record({
        eventType: outcome.ok ? 'authorization.approved' : 'authorization.denied',
        correlationId: consent.consentRef,
        action: { category: 'authorization', name: 'place_order' },
        actor: { kind: 'pairwise_did', did: vc.credentialSubject.id },
        responsibleParty: { kind: 'public_did', did: issuer },
        resource: { kind: 'keyed_commitment', value: `sha256:${createHash('sha256').update(outcome.ok ? outcome.item.uri : String(args['product'] ?? '')).digest('hex')}`, keyId: 'gs1-digital-link' },
        outcome: outcome.ok ? 'succeeded' : 'denied',
        ...(outcome.ok ? {} : { reason: { code: outcome.error } }),
        authorization: { source: 'delegation', decision: outcome.ok ? 'allowed' : 'denied', scopeId: 'commerce.order', ...(ref ? { delegationRef: ref } : {}) },
        evidence: [],
        details: { family: 'authorization', phase: outcome.ok ? 'approved' : 'denied' },
      }).catch((err: unknown) => ({ status: 'failed' as const, error: err }));
      if (recorded.status !== 'recorded') {
        return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: 'AUDIT_UNAVAILABLE', message: 'Fail-closed: the merchant could not record this decision, so it will not act on it' }) }] };
      }

      if (!outcome.ok) {
        return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: outcome.error, message: outcome.message, detail: outcome.detail ?? null, mandate: outcome.mandate }) }] };
      }
      const evidence = {
        merchant: { did: identity.did, name: config.name },
        order: { product: outcome.item.uri, gtin: outcome.item.gtin, name: outcome.item.name, quantity: outcome.quantity, unitPrice: `${outcome.currency} ${outcome.item.unitPrice}`, total: outcome.total },
        mandate: outcome.mandate,
        consent: { consentRef: consent.consentRef, attestedBy: config.rpDid, observedBy: identity.did },
        checks: outcome.checks,
      };
      // The trusted adapter receives the exact verified VC and approved quote.
      // No caller-controlled field can select or serialize this function.
      const execution: OrderExecutionResult = call?.execution
        ? await call.execution({ outcome, vc, evidence })
        : { body: { ...evidence, ok: true, orderId: allocateOrderId(),
          payment: { status: 'not-initiated', note: 'Order only. No money moved; payment rails are outside this demonstration.' },
          verifiedAt: new Date().toISOString() } };
      if (execution.committed !== false && !execution.isError && execution.body['ok'] === true && typeof execution.body['orderId'] === 'string' && execution.body['orderId']) orders += 1;
      return { ...(execution.isError ? { isError: true } : {}), content: [{ type: 'text', text: JSON.stringify(execution.body) }] };
    }),
  );

  const catalogHandler = kyaos.wrapWithProof('get_catalog', async () => ({
    content: [{ type: 'text', text: JSON.stringify(CATALOG) }],
  }));

  // ---- event bus: the console is a VERIFIER VIEW that observes this server -----
  type Subscriber = (data: string) => void;
  const subscribers = new Set<Subscriber>();
  function broadcast(event: Record<string, unknown>): void {
    const data = JSON.stringify({ ...event, at: new Date().toISOString() });
    for (const sub of subscribers) { try { sub(data); } catch { /* dead subscriber must not break the others */ } }
  }

  /** All transports share these authority checks before invoking a server-owned effect. */
  function executeOrder(a: Record<string, unknown>, execution?: OrderExecution): Promise<MerchantToolResult> {
    return runBoundary.operation(() => executeOrderInRun(a, execution));
  }
  async function executeOrderInRun(a: Record<string, unknown>, execution?: OrderExecution): Promise<MerchantToolResult> {
    const sessionId = await responseProofContext.getSessionId();
    const started = Date.now();
    broadcast({ type: 'request', tool: 'place_order', product: String(a['product'] ?? ''), quantity: Number(a['quantity'] ?? 1), agentDid: (a['_kyaos_delegation'] as DelegationCredential | undefined)?.credentialSubject?.id ?? null });

    const vc = a['_kyaos_delegation'] as DelegationCredential | undefined;
    const agentDid = vc?.credentialSubject?.id ?? env('AGENT_DID', '');
    const call = { vc, args: a, agentDid, execution, checks: {} as Partial<GateChecks>, challenge: undefined as ConsentChallenge | undefined };
    const invoke = async () => {
      if (!vc) {
        call.checks.signature = 'skip';
        call.checks.revocation = 'skip';
        const holder = await assertHolderBinding({ proof: a['_kyaos_proof'] as DetachedProof, subjectDid: agentDid, request: toHolderBindingRequest('place_order', a), expectedAudience: identity.did, proofVerifier: requestVerifier });
        call.checks.holder = holder.status === 'bound' ? 'pass' : 'fail';
        if (holder.status !== 'bound') return refusal('holder_binding_failed', 'A fresh holder proof bound to this request, agent, and merchant is required before consent.');
      }
      if (!vc) {
        try {
          const response = await consentProtocol.request('/consent/requests', 'consent.create', {
            bindings: { agentDid, audience: identity.did, product: String(a['product'] ?? ''), quantity: Number(a['quantity'] ?? 1),
              productClass: SCOPE_PRODUCT_CLASS, cap: SPEND_CAP, currency: SPEND_CURRENCY, validHours: VALID_HOURS,
              requestHash: consentDigest({ method: 'place_order', params: a }) },
            agentRequest: a,
          }, identity);
          call.challenge = response['challenge'] as ConsentChallenge;
          if (!call.challenge?.authorizationUrl || call.challenge.error !== 'needs_authorization') throw new Error('RP returned an invalid challenge');
          authorizationChallenge = { ...call.challenge };
        } catch (error) { return consentErrorResponse(error); }
      }
      return callStore.run(call, () => placeOrderHandler(a, sessionId));
    };
    const result = await invoke();

    const r = result as { isError?: boolean; content?: Array<{ text?: string }>; _meta?: Record<string, unknown> };
    const text = r.content?.[0]?.text ?? '{}';
    let body: Record<string, unknown> = {};
    try { body = JSON.parse(text); } catch { body = {}; }
    const verdict: 'allowed' | 'denied' = r.isError || body['error'] ? 'denied' : 'allowed';
    const code = body['error'] as string | undefined;
    const reason = String(body['reason'] ?? body['message'] ?? '');
    const proof = r._meta?.[KYA_OS_PROOF_META_KEY] ?? r._meta?.['proof'] ?? null;
    if (code === 'needs_authorization') {
      await decisionAudit.record({
        eventType: 'consent.requested', actor: { kind: 'pairwise_did', did: agentDid },
        responsibleParty: { kind: 'public_did', did: config.rpDid },
        action: { category: 'consent', name: 'place_order' }, outcome: 'challenged',
        correlationId: tokenReference(String(body['resumeToken'])),
        resource: { kind: 'keyed_commitment', value: consentDigest(body['authorizationUrl']), keyId: 'authorization-url' },
        authorization: { source: 'anonymous', decision: 'needs_authorization', scopeId: SCOPE_PRODUCT_CLASS },
        evidence: [], details: { family: 'consent', phase: 'requested', consentRef: tokenReference(String(body['resumeToken'])) },
      });
      broadcast({ type: 'needs_authorization', ...body });
    }
    if (verdict === 'allowed' && body['ok'] === true && typeof body['orderId'] === 'string' && body['orderId']) {
      authorizationChallenge = null;
      // Exactly what the proof binds: the request minus the `_kyaos_*` control
      // args (the gate strips them before the proof wrapper hashes the call)
      // and the response content array (body profile).
      const params: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(a)) if (!k.startsWith('_kyaos')) params[k] = v;
      lastReceipt = { body, proof, at: new Date().toISOString(), request: { method: 'place_order', params }, content: r.content ?? null };
    }

    broadcast({
      type: 'verdict',
      verdict,
      code: code ?? null,
      reason: reason || null,
      elapsedMs: Date.now() - started,
      checks: checksFromOutcome(verdict, code, reason, call.checks),
      body,
      receipt: proof,
      statusList: statusListResolver.lastObservation,
      rpResolvedFrom: rpDidUrl ? (fetchProvider.resolvedFrom.get(rpDidUrl) ?? null) : null,
    });
    return result as MerchantToolResult;
  }

  // ---- MCP surface ---------------------------------------------------------------
  function createMcpServer(): Server {
    const server = new Server({ name: 'agentic-commerce-merchant', version: '0.1.0' }, { capabilities: { tools: {} } });

    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        kyaos.kyaOsTool,
        {
          name: 'get_catalog',
          description: 'List the merchant catalog (GS1 Digital Link product URIs and prices). Open to any agent; the response is signed.',
          inputSchema: { type: 'object' as const, properties: {} },
        },
        {
          name: 'place_order',
          description:
            'Place an order for a catalog product. Requires a KYA-OS delegation (scope commerce.order) whose crisp scope covers the product\'s GS1 Digital Link class and whose cap covers the total; revocation is checked against the Responsible Party\'s status list on every call.',
          inputSchema: {
            type: 'object' as const,
            properties: {
              product: { type: 'string', description: 'Catalog sku or GS1 Digital Link URI (https://id.gs1.org/01/<gtin>[/10/<lot>][/21/<serial>])' },
              quantity: { type: 'integer', description: 'Units to order (default 1)' },
            },
            required: ['product'],
          },
        },
      ],
    }));

    server.setRequestHandler(CallToolRequestSchema, (request) => runBoundary.operation(async () => {
      const { name, arguments: args = {} } = request.params;
      if (name === '_kyaos') return kyaos.handleKyaOs(args as Record<string, unknown>);
      if (name === 'get_catalog') return catalogHandler({}, await responseProofContext.getSessionId());
      if (name === 'place_order') {
        const a = args as Record<string, unknown>;
        const checkout = a['checkout'] as Record<string, unknown> | undefined;
        const payment = request.params._meta?.['x402/payment'];
        const gatewayPaymentArguments = ['payment_protocol', 'payment_method', 'checkout_id'].some(name => a[name] !== undefined);
        const paymentIntent = gatewayPaymentArguments || a['checkout'] !== undefined || payment !== undefined;
        if (!commerce && paymentIntent) return { isError: true, content: [{ type: 'text', text: JSON.stringify({
          error: 'PAYMENTS_DISABLED', message: 'Optional payment demonstrations are disabled. The operator must enable COMMERCE_PAYMENTS before selecting a payment protocol.',
        }) }] };
        if (gatewayPaymentArguments || (paymentIntent && checkout?.['protocol'] !== 'x402')) return { isError: true, content: [{ type: 'text', text: JSON.stringify({
          error: 'CHECKOUT_PROTOCOL_UNSUPPORTED', message: 'Use /agent/mcp for payment options, or the discovered checkout transport. Payment intent cannot fall back to an unpaid order.',
        }) }] };
        if (commerce && checkout?.['protocol'] === 'x402') {
          const result = payment === undefined
            ? await commerce.coordinator.requestPayment(a)
            : await commerce.coordinator.complete(a, payment);
          return x402McpResult(result);
        }
        return executeOrder(a);
      }
      return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
    }));
    return server;
  }

  // ---- discovery + act API + static console (Hono) -------------------------------
  const app = new Hono();
  // Keep every merchant operation and its audit responses inside one run.
  // Gateway requests acquire the shared wallet queue before calling /mcp, so
  // never hold this boundary around /agent/mcp or /api/act/order themselves.
  app.use('*', async (c, next) => {
    const route = c.req.path;
    const observesRun = route === '/api/state' || route.startsWith('/api/audit/')
      || route.startsWith('/api/receipt/') || route.startsWith('/payments/')
      || route.startsWith('/ucp/') || route.startsWith('/checkout/')
      || ['/api/act/audit', '/api/act/tamper', '/api/act/export', '/api/act/verify-receipt'].includes(route);
    return observesRun ? runBoundary.operation(next) : next();
  });
  // The presenter's destructive controls. On a laptop the loopback binding is the
  // boundary; once the console is public, ADMIN_TOKEN becomes that boundary.
  const requireAdmin = createMiddleware(async (c, next) => {
    if (!adminTokenOk(c.req.header('x-admin-token')))
      return c.json({ error: 'admin_required', message: 'This control is reserved for the presenter.' }, 403);
    await next();
  });
  app.use('/api/act/reset', requireAdmin);
  app.use('/api/act/tamper', requireAdmin);
  const discovery = buildDiscoveryDocument({ serverDid: identity.did, name: config.name, currency: 'CHF' });
  const commerceOrigin = config.origin ?? env('MERCHANT_ORIGIN', `http://localhost:${config.port}`);
  const commerce = flag('COMMERCE_PAYMENTS') ? mountCommerce(app, {
    origin: commerceOrigin, merchantDid: identity.did, file: path.join(VAR_DIR, 'merchant', 'commerce.json'), authorize: executeOrder, broadcast,
    signStatus: (body, audience) => signMessage('payment.status.result', body, identity, audience),
    signResult: async (args, body) => {
      const session = await kyaos.sessionManager.getSession(await responseProofContext.getSessionId());
      if (!session) throw new Error('Historical receipt proof context unavailable');
      const content = [{ type: 'text', text: JSON.stringify(body) }];
      const { _kyaos_delegation: ignored, ...challengeArgs } = args;
      const challenge = body['error'] === 'needs_authorization';
      const proof = await receiptProofGenerator.generateProof(challenge ? { method: 'place_order', params: challengeArgs } : toHolderBindingRequest('place_order', args),
        { data: content }, session, { outcome: challenge ? 'needs_authorization' : 'allowed' });
      return { content, _meta: { [KYA_OS_PROOF_META_KEY]: proof } };
    },
    beforeSettlement: (vc) => verifySettlementAuthority(vc, statusListResolver, callStore.getStore()?.checks),
    onPayment: async (event) => {
      await decisionAudit.record({ eventType: event['phase'] === 'authorized' ? 'authorization.approved' : 'tool.call.completed',
        actor: { kind: 'public_did', did: identity.did }, action: { category: 'commerce', name: `payment.${String(event['rail'])}` },
        outcome: 'succeeded', correlationId: String(event['checkoutId']),
        resource: { kind: 'keyed_commitment', value: consentDigest(event), keyId: 'checkout-payment-evidence' }, evidence: [],
        details: event['phase'] === 'authorized' ? { family: 'authorization', phase: 'approved' }
          // The SDK attempt is a decimal counter, not a checkout identifier.
          // One committed payment is correlated by checkoutId above.
          : { family: 'tool', phase: 'completed', attempt: '1', idempotencyRef: String(event['termsDigest']) },
      });
      broadcast({ type: 'payment', ...event });
    },
  }) : null;
  if (commerce) Object.assign(discovery, { commerce: { ...discovery.commerce, ucp: `${commerceOrigin}/.well-known/ucp`, x402: { version: 2, httpEndpoint: `${commerceOrigin}/payments/x402`, mode: commerce.rail.mode },
    rails: ['x402', 'sandbox-token'], authorization: 'org.kya-os/delegation' } });

  app.get('/connect', (c) => c.redirect('/connect.html'));
  app.get('/.well-known/mcp', (c) => { c.header('Cache-Control', 'no-store'); return c.json(discovery); });
  app.get('/api/catalog', (c) => c.json(CATALOG));

  app.get('/api/events', (c) =>
    streamSSE(c, async (stream) => {
      const sub: Subscriber = (data) => { void stream.writeSSE({ data }); };
      subscribers.add(sub);
      await stream.writeSSE({ data: JSON.stringify({ type: 'hello', role: 'merchant', at: new Date().toISOString() }) });
      await new Promise<void>((resolve) => {
        const ping = setInterval(() => { void stream.writeSSE({ data: JSON.stringify({ type: 'ping' }) }).catch(() => {}); }, 15000);
        stream.onAbort(() => { clearInterval(ping); subscribers.delete(sub); resolve(); });
      });
    }),
  );

  app.get('/api/state', async (c) => {
    let rpDocument: { resolved: boolean; from: string | null; kid: string | null } = { resolved: false, from: null, kid: null };
    try {
      const doc = await didResolver.resolve(config.rpDid);
      rpDocument = { resolved: !!doc, from: rpDidUrl ? (fetchProvider.resolvedFrom.get(rpDidUrl) ?? null) : null, kid: doc?.verificationMethod?.[0]?.id ?? null };
    } catch { /* unresolved → fail-closed at verification time */ }
    // UI observation across HTTP; this is never an authorization input.
    if (authorizationChallenge) {
      try {
        const url = new URL('/consent/status', config.rpOrigin);
        url.searchParams.set('resume_token', String(authorizationChallenge['resumeToken']));
        const response = await fetch(url, { signal: AbortSignal.timeout(2000), redirect: 'error' });
        if (response.ok && (await response.json() as { state: string }).state !== 'pending') authorizationChallenge = null;
      } catch { /* Leave the last observed challenge visible while RP is unavailable. */ }
    }
    return c.json({
      merchant: { did: identity.did, kid: identity.kid, name: config.name, port: config.port },
      discovery,
      responsibleParty: { did: config.rpDid, hubOrigin: config.rpOrigin, didDocumentUrl: rpDidUrl, mirror: config.rpDidMirrorUrl, offline: config.offline, ...rpDocument },
      statusList: { url: config.statusListUrl, checkedAt: 'every-call', onUnresolvable: 'fail-closed', last: statusListResolver.lastObservation },
      policy: { holderBinding: 'enforce', revocationCheck: 'fail-closed', spendEnforcement: 'merchant, from credential cap' },
      authorizationChallenge: authorizationChallenge && Number(authorizationChallenge['expiresAt']) > Date.now() / 1000 ? authorizationChallenge : null,
      lastMandate,
      lastReceipt: lastReceipt ? { at: lastReceipt.at, orderId: lastReceipt.body['orderId'] ?? null } : null,
      orders,
      commerce: commerce ? { enabled: true, mode: commerce.rail.mode, ucp: `${commerceOrigin}/.well-known/ucp`, rails: ['x402', 'sandbox-token'] } : { enabled: false },
      catalog: CATALOG,
      audit: { ledger: audit.ledger, recorder: audit.recorder, profile: audit.capabilities.profile, delivery: audit.capabilities.delivery, entries: (await audit.entries()).length, witness: config.witness ? `${config.rpOrigin}/api/rp/audit/observe` : null },
    });
  });

  // ---- the audit finale: ledger → checkpoint → witness → tamper → export ----------
  app.get('/api/audit/ledger', async (c) => { return c.json(await audit.report()); });

  app.post('/api/act/audit', async (c) => {
    const started = Date.now();
    try {
      // A fresh run has no checkpoint to sign. Show its honest empty report.
      if ((await audit.entries()).length === 0) return c.json(await audit.report());
      const a = await audit.anchor();
      const report = await audit.report();
      broadcast({ type: 'audit', created: a.created, treeSize: a.checkpoint.core.treeSize, rootDigest: a.checkpoint.core.rootDigest, checkpointDigest: a.checkpoint.checkpointDigest, witnessed: !!a.witness, witnessError: a.witnessError, entries: report.entries.length, allIncluded: report.allIncluded, chainIntact: report.chainIntact, elapsedMs: Date.now() - started });
      return c.json(report);
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : String(err) }, 409);
    }
  });

  app.post('/api/act/tamper', async (c) => {
    const started = Date.now();
    try {
      // An absent body keeps the scripted demo compatible. Malformed or
      // partial selections must fail rather than editing an unrelated row.
      const body = await c.req.text();
      const edit = body.trim() === '' ? undefined : JSON.parse(body) as AuditInsiderEdit;
      const t = await audit.tamper(edit);
      broadcast({ type: 'tamper', target: t.target, rootsMatch: t.rootsMatch, chainBreaksAt: t.chainBreaksAt, forgedInclusion: t.forgedInclusion, forgedReceiptVerifies: t.forgedReceiptVerifies, verdicts: verdictsOf(t.reports.tampered), elapsedMs: Date.now() - started });
      return c.json(t);
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : String(err) }, 409);
    }
  });

  app.post('/api/act/export', async (c) => {
    const started = Date.now();
    try {
      const e = await audit.exportBundle();
      broadcast({ type: 'export', bundleId: e.bundleId, manifestDigest: e.manifestDigest, files: e.files, command: e.command, verdicts: { honest: verdictsOf(e.reports.honest), tampered: verdictsOf(e.reports.tampered) }, elapsedMs: Date.now() - started });
      return c.json(e);
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : String(err) }, 409);
    }
  });

  app.get('/api/audit/bundle', async (c) => {
    try {
      const b = await audit.bundle();
      c.header('Content-Disposition', `attachment; filename="kya-audit-bundle-${audit.ledger.ledgerEpochId}.json"`);
      return c.json(b);
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : String(err) }, 409);
    }
  });

  // The console is only a control plane: these drive THE AGENT — a real MCP
  // client that connects to our own /mcp and presents credential + holder proof.
  app.post('/api/act/discover', async (c) => {
    try {
      const d = await discover(`http://localhost:${config.port}`);
      broadcast({ type: 'discovered', accepted: d.accepted, reasons: d.reasons, audience: d.audience, clockSkewSeconds: d.clockSkewSeconds, scheme: d.scheme, elapsedMs: d.elapsedMs });
      return c.json(d);
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : String(err) }, 500);
    }
  });

  app.post('/api/act/order', async (c) => {
    const body = await c.req.json().catch(() => ({} as Record<string, unknown>));
    const product = String((body as Record<string, unknown>)['product'] ?? 'risotto');
    const quantity = Number((body as Record<string, unknown>)['quantity'] ?? 1);
    const forge = Boolean((body as Record<string, unknown>)['forge']);
    try {
      const outcome = await runAgentOrder({ product, quantity, forge, serverUrl: `http://localhost:${config.port}/mcp`, audience: identity.did });
      return c.json({ elapsedMs: outcome.elapsedMs, result: outcome.result, agentDid: outcome.agentDid, presented: outcome.presented, via: 'mcp/streamable-http' });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      broadcast({ type: 'agent_error', message });
      return c.json({ error: message }, 500);
    }
  });

  app.post('/api/act/reset', (c) => serializeAgentOperation(() => runBoundary.exclusive(async () => {
    // Drain gateway pickup first, then merchant effects/audit actions. Reversing
    // this lock order would deadlock a gateway waiting for its own /mcp call.
    // Archive before resetting authority; failure leaves the current run intact.
    let nextRun: Awaited<ReturnType<typeof audit.prepareNewRun>>;
    try {
      nextRun = await audit.prepareNewRun();
    } catch {
      return c.json({ error: 'AUDIT_ARCHIVE_FAILED', message: 'The previous signed audit could not be archived. Start over was not applied; the current grant and audit remain unchanged.' }, 503);
    }
    let res: Response;
    let issued: Record<string, unknown>;
    try {
      // Server-to-server, but the hub's guard applies to it too: without the
      // presenter's token the hub refuses and the console's reset half-completes.
      res = await fetch(`${config.rpOrigin}/api/rp/reset`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(ADMIN_TOKEN ? { 'x-admin-token': ADMIN_TOKEN } : {}) }, body: '{}',
        redirect: 'error', signal: AbortSignal.timeout(8000) });
      const body: unknown = await res.json().catch(() => null);
      issued = body && typeof body === 'object' && !Array.isArray(body) ? body as Record<string, unknown> : {};
    } catch {
      return c.json({ error: 'RP_RESET_UNAVAILABLE', message: 'The authorization host could not confirm reset. The local grant remains unchanged.' }, 502);
    }
    if (!res.ok || issued['success'] !== true) return c.json({
      error: typeof issued['error'] === 'string' ? issued['error'] : 'RP_RESET_REFUSED',
      message: typeof issued['message'] === 'string' ? issued['message'] : `The authorization host did not confirm reset (HTTP ${res.status}). The local grant remains unchanged.`,
      upstreamStatus: res.status,
    }, 502);
    try { clearAgentState(); }
    catch {
      return c.json({ error: 'RESET_WALLET_FAILED', authorityReset: true,
        message: 'The authorization host reset the grant, but the demo wallet could not be cleared. The merchant audit is retained. Retry Start over after fixing wallet storage.' }, 503);
    }
    nextRun.commit();
    statusListResolver.invalidateCache();
    lastMandate = null;
    lastReceipt = null;
    orders = 0;
    authorizationChallenge = null;
    const freshAudit = { auditRunId: nextRun.ledger.ledgerEpochId, archivedAudit: nextRun.archive };
    broadcast({ type: 'reset', index: issued['index'] ?? null, ...freshAudit });
    return c.json({ ...issued, ...freshAudit });
  })));

  app.get('/api/receipt/last', (c) => (lastReceipt ? c.json(lastReceipt) : c.json({ error: 'no receipt yet — place an order first' }, 404)));

  /** Cross-language re-verification of the last receipt with the stdlib Python verifier. */
  app.post('/api/act/verify-receipt', async (c) => {
    if (!lastReceipt) return c.json({ error: 'no receipt yet — place an order first' }, 404);
    if (!config.pythonVerifier) return c.json({ error: 'python verifier not configured' }, 501);
    const input = JSON.stringify({ receipt: lastReceipt, merchant: { did: identity.did, kid: identity.kid, publicKeyBase64: identity.publicKeyBase64 } });
    const started = Date.now();
    const out = await new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
      const child = spawn(env('PYTHON', 'python3'), [config.pythonVerifier!], { stdio: ['pipe', 'pipe', 'pipe'] });
      let stdout = '', stderr = '';
      child.stdout.on('data', (d) => { stdout += String(d); });
      child.stderr.on('data', (d) => { stderr += String(d); });
      child.on('error', (e) => resolve({ code: null, stdout, stderr: stderr + String(e) }));
      child.on('close', (code) => resolve({ code, stdout, stderr }));
      child.stdin.end(input);
    });
    let parsed: unknown = null;
    try { parsed = JSON.parse(out.stdout); } catch { parsed = null; }
    const result = { ok: out.code === 0, exitCode: out.code, elapsedMs: Date.now() - started, report: parsed, stdout: parsed ? undefined : out.stdout, stderr: out.stderr || undefined };
    broadcast({ type: 'crosscheck', ...result });
    return c.json(result);
  });

  // A passkey binds to the hub's RP ID, so enrolment must happen on the hub's
  // hostname. Serving this page from the console works only while the two share
  // a hostname, as they do on a laptop.
  const setupUrl = new URL('/setup-key.html', config.rpOrigin);
  if (setupUrl.hostname === '127.0.0.1') setupUrl.hostname = 'localhost';
  if (env('GOOGLE_CLIENT_ID', '') || setupUrl.hostname !== new URL(merchantOrigin()).hostname) {
    app.get('/setup-key.html', (c) => c.redirect(setupUrl.toString()));
  }
  app.use('/*', serveStatic({ root: path.relative(process.cwd(), WEB_DIR) || './web' }));

  // Both agent and merchant use stateless Streamable HTTP on the same listener.
  const honoListener = getRequestListener(app.fetch);
  const httpServer = http.createServer({ maxHeaderSize: 64 * 1024 }, async (req, res) => {
    const url = new URL(req.url ?? '/', `http://localhost:${config.port}`);
    if (url.pathname === '/agent/mcp') {
      await handleStatelessMcp(req, res, () => createGatewayServer({
        merchantOrigin: `http://127.0.0.1:${req.socket.localPort}`,
        audience: identity.did,
      }), {
        loopbackOnly: true,
        allowedHosts: publicHosts(merchantOrigin()),
        token: GATEWAY_TOKEN,
      });
      return;
    }
    if (url.pathname === '/mcp') {
      await handleStatelessMcp(req, res, createMcpServer);
      return;
    }
    await honoListener(req, res);
  });

  return { app, httpServer, kyaos, statusListResolver, fetchProvider, discovery, broadcast, audit, executeOrder, commerce };
}

/** The seven verdicts of an SDK verification report, compact for the event bus. */
function verdictsOf(report: object): Record<string, { verdict: string; reasonCodes: string[] }> {
  const out: Record<string, { verdict: string; reasonCodes: string[] }> = {};
  for (const [k, v] of Object.entries(report as Record<string, unknown>)) {
    if (v && typeof v === 'object' && 'verdict' in v) out[k] = v as { verdict: string; reasonCodes: string[] };
  }
  return out;
}

export async function startMerchantServer(overrides: Partial<MerchantAppConfig> = {}) {
  const config = merchantConfigFromEnv(overrides);
  const merchant = await createMerchant(config);
  await new Promise<void>((resolve) => merchant.httpServer.listen(config.port, config.bindHost ?? '127.0.0.1', () => {
    console.log(`Merchant edge: http://localhost:${config.port}`);
    console.log(`  console:    http://localhost:${config.port}/`);
    console.log(`  connect:    http://localhost:${config.port}/connect`);
    console.log(`  Claude MCP: http://localhost:${config.port}/agent/mcp (stateless Streamable HTTP)`);
    console.log(`  discovery:  http://localhost:${config.port}/.well-known/mcp`);
    console.log(`  merchant:   http://localhost:${config.port}/mcp (delegation + holder proof required)`);
    console.log(`  did:        ${config.identity.did}`);
    console.log(`  trusts RP:  ${config.rpDid} (list: ${config.statusListUrl}${config.offline ? ', OFFLINE mirror' : ''})`);
    console.log(`  audit:      ${merchant.audit.ledger.ledgerId} · ${merchant.audit.capabilities.profile} · delivery ${merchant.audit.capabilities.delivery}${config.witness ? ` · witness ${config.rpOrigin}` : ''}`);
    resolve();
  }));
  return { ...merchant, config };
}

if (isMainModule(import.meta.url)) void startMerchantServer();
