#!/usr/bin/env npx tsx
/**
 * The Responsible Party's hub — the shopper's own identity host. Three jobs:
 *
 *   1. Publish the RP's DID document (did:web → /.well-known/did.json).
 *   2. Host the signed StatusList2021 credential the merchant verifies on
 *      every call (GET /status-list, Cache-Control: no-store).
 *   3. Issue and revoke the agent's delegation, the latter behind an
 *      authenticator touch when KEY_WEBAUTHN=1.
 *   4. Witness the merchant's audit ledger: countersign each RFC 9162
 *      checkpoint the merchant publishes (POST /api/rp/audit/observe), so the
 *      merchant's history is pinned by a party it does not control.
 *
 * It is a SEPARATE process/origin from the merchant on purpose: the merchant
 * trusts the RP's signature, resolved through the RP's DID, not this server.
 */
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { createMiddleware } from 'hono/factory';
import { cors } from 'hono/cors';
import { streamSSE } from 'hono/streaming';
import { buildDidWebDocument, type DIDDocument, type VerificationMethod } from '@kya-os/mcp';
import {
  RP_PORT,
  STATUS_LIST_URL,
  env,
  flag,
  loadRpIdentity,
  makeVcSigningFunction,
  merchantOrigin,
  rpOrigin,
  readJson,
  writeJson,
  type KeyedIdentity,
  adminTokenOk,
} from '../lib/wiring.js';
import path from 'node:path';
import { isMainModule } from '../lib/main-module.js';
import { publicOrigin } from '../lib/public-origin.js';
import fs from 'node:fs';
import { WEB_DIR } from '../lib/wiring.js';
import { GoogleIdentity } from './google-identity.js';
import type { HumanIdentityAuth } from './human-identity.js';
import { ensureStatusList, loadStatusList, loadStatusListMeta, readBit, RP_DIR } from './statuslist.js';
import { activeIndex, activeCredentialOrNull, clearActiveCredential } from './issue.js';
import { createConsentRoutes } from './consent.js';
import { ConsentFlowStore } from './consent-store.js';
import { ConsentProtocol, signMessage, type SignedMessage } from '../lib/consent-protocol.js';
import { createRpAudit } from './audit.js';
import type { ConsentBindings } from './consent-store.js';
import { consentDigest } from '../lib/consent-evidence.js';
import { revokeIndex, type RevokePhase } from './revoke.js';
import { createKeyRoutes } from './key/webauthn-routes.js';
import { hasAuthenticator, listAuthenticators } from './key/credential-store.js';
import { createWitness, type Witness } from './witness.js';

export const DID_DOCUMENT_FILE = path.join(RP_DIR, 'did.json');

export interface RpAppConfig {
  identity: KeyedIdentity;
  statusListUrl: string;
  /** DIDs allowed to be issued to / for. Read from env at request time by default. */
  agentDid: () => string;
  merchantDid: () => string;
  corsOrigins: string[];
  keySetup: boolean;
  keyWebauthn: boolean;
  consentWebauthn?: boolean;
  bypassWebauthn: boolean;
  rpID: string;
  origin: string;
  googleClientId?: string;
  googleOrigin?: string;
  /** Public browser origin for consent, independent of the status-list host. */
  authorizationOrigin?: string;
  /** Listener address; loopback locally, 0.0.0.0 behind a deployment proxy. */
  bindHost?: string;
  identityAuth?: HumanIdentityAuth & { routes?: Hono };
}

export function buildRpDidDocument(identity: KeyedIdentity): DIDDocument {
  return buildDidWebDocument({
    did: identity.did,
    kid: identity.kid,
    publicKey: identity.publicKeyBase64,
    createdAt: new Date().toISOString(),
  });
}

/** Keep published verification material aligned with the deployed signing identity. */
export function ensureDidDocument(identity: KeyedIdentity): DIDDocument {
  const existing = readJson<DIDDocument>(DID_DOCUMENT_FILE);
  const doc = buildRpDidDocument(identity);
  const expected = doc.verificationMethod![0]!;
  const expectedJwk = expected.publicKeyJwk as JsonWebKey;
  const matchesKey = (method: VerificationMethod): boolean => {
    if (!method || method.id !== expected.id || method.controller !== expected.controller || method.type !== expected.type) return false;
    const jwk = method.publicKeyJwk as JsonWebKey | undefined;
    const multibase = method.publicKeyMultibase;
    // Check every advertised representation: different resolvers may prefer
    // JWK or multibase. Neither may retain the previous deployment's key.
    return (jwk !== undefined || multibase !== undefined)
      && (jwk === undefined || Boolean(jwk && jwk.kty === expectedJwk.kty
        && jwk.crv === expectedJwk.crv && jwk.x === expectedJwk.x && jwk.d === undefined))
      && (multibase === undefined || multibase === expected.publicKeyMultibase);
  };
  const authorizesKey = (methods: DIDDocument['assertionMethod']): boolean => Array.isArray(methods)
    && methods.some(method => typeof method === 'string' ? method === identity.kid : matchesKey(method));
  const activeMethods = Array.isArray(existing?.verificationMethod)
    ? existing.verificationMethod.filter(method => method?.id === identity.kid) : [];
  if (existing?.id === identity.did && activeMethods.length === 1 && matchesKey(activeMethods[0]!)
    && authorizesKey(existing.authentication) && authorizesKey(existing.assertionMethod)) return existing;
  writeJson(DID_DOCUMENT_FILE, doc);
  return doc;
}

export function createRpApp(config: RpAppConfig): Hono {
  const app = new Hono();
  const { identity } = config;
  const signingFunction = makeVcSigningFunction(identity.privateKeyBase64);
  const googleOrigin = config.googleOrigin ?? new URL(config.statusListUrl).origin.replace('127.0.0.1', 'localhost');
  const identityAuth = config.identityAuth ?? new GoogleIdentity({ clientId: config.googleClientId, origin: googleOrigin });
  const authorizationOrigin = publicOrigin(config.authorizationOrigin
    ?? ((identityAuth.enabled || config.consentWebauthn) ? googleOrigin : new URL(config.statusListUrl).origin));
  // A missing key must not silently downgrade an explicitly gated deployment.
  const keyRequired = () => config.keyWebauthn && !config.bypassWebauthn;
  const revocableIndex = () => activeCredentialOrNull() ? activeIndex() : null;
  const consentStore = new ConsentFlowStore({ authorizationOrigin });
  const consentAudit = createRpAudit(identity, consentStore);
  const protocol = new ConsentProtocol(identity.did, new URL(config.statusListUrl).origin);

  app.use('/api/*', cors({ origin: config.corsOrigins, credentials: identityAuth.enabled }));
  // The presenter's destructive controls. On a laptop the loopback binding is the
  // boundary; once the hub is public, ADMIN_TOKEN becomes that boundary.
  const requireAdmin = createMiddleware(async (c, next) => {
    if (!adminTokenOk(c.req.header('x-admin-token')))
      return c.json({ error: 'admin_required', message: 'This control is reserved for the presenter.' }, 403);
    await next();
  });
  app.use('/api/rp/reset', requireAdmin);
  app.use('/api/rp/revoke', requireAdmin);
  // The merchant monitor reconciles pending human consent across RP origins.
  // Consent actions remain same-origin; only this read endpoint is exposed.
  app.use('/consent/status', cors({
    origin: config.corsOrigins,
    credentials: identityAuth.enabled,
    allowMethods: ['GET'],
    allowHeaders: ['Content-Type'],
  }));
  app.use('/status-list', cors({ origin: '*' }));
  app.use('/.well-known/*', cors({ origin: '*' }));

  // ---- SSE: revocation phases, for the console's RP pane ----------------------
  type Subscriber = (data: string) => void;
  const subscribers = new Set<Subscriber>();
  const broadcast = (event: Record<string, unknown>) => {
    const data = JSON.stringify({ ...event, at: new Date().toISOString() });
    for (const sub of subscribers) { try { sub(data); } catch { /* dead subscriber */ } }
  };
  app.get('/api/rp/events', (c) =>
    streamSSE(c, async (stream) => {
      const sub: Subscriber = (data) => { void stream.writeSSE({ data }); };
      subscribers.add(sub);
      await stream.writeSSE({ data: JSON.stringify({ type: 'hello', role: 'rp', at: new Date().toISOString() }) });
      await new Promise<void>((resolve) => {
        const ping = setInterval(() => { void stream.writeSSE({ data: JSON.stringify({ type: 'ping' }) }).catch(() => {}); }, 15000);
        stream.onAbort(() => { clearInterval(ping); subscribers.delete(sub); resolve(); });
      });
    }),
  );

  if (identityAuth.routes) app.route('/', identityAuth.routes);
  // The revocation ceremony is served here, not on the console, because a passkey
  // is scoped to the RP ID it was registered against.
  app.get('/revoke', (c) => {
    c.header('Cache-Control', 'no-store');
    return c.html(fs.readFileSync(path.join(WEB_DIR, 'revoke.html'), 'utf8').replace('__MERCHANT_ORIGIN__', merchantOrigin()));
  });
  app.get('/setup-key.html', (c) => {
    c.header('Cache-Control', 'no-store');
    return c.html(fs.readFileSync(path.join(WEB_DIR, 'setup-key.html'), 'utf8'));
  });
  // Each party authenticates protocol messages using its own verifier and key.
  // The merchant never creates or opens this RP's private flow store.
  async function readMessage(c: import('hono').Context): Promise<SignedMessage> {
    const raw = await c.req.text();
    if (Buffer.byteLength(raw) > 65_536) throw new Error('Consent protocol request too large');
    return JSON.parse(raw) as SignedMessage;
  }
  app.post('/consent/requests', async (c) => {
    try {
      const message = await readMessage(c);
      const body = await protocol.verify('consent.create', message, config.merchantDid(), identity.did);
      const bindings = body['bindings'] as ConsentBindings;
      const agentRequest = body['agentRequest'] as Record<string, unknown>;
      if (!bindings || bindings.agentDid !== config.agentDid() || bindings.audience !== config.merchantDid()
        || typeof bindings.productClass !== 'string' || typeof bindings.cap !== 'string' || typeof bindings.currency !== 'string'
        || !Number.isFinite(bindings.validHours) || bindings.validHours <= 0 || !agentRequest
        || bindings.product !== agentRequest['product'] || bindings.quantity !== (agentRequest['quantity'] ?? 1)) throw new Error('Consent request bindings differ');
      await protocol.verify('place_order', { body: agentRequest, proof: agentRequest['_kyaos_proof'] as SignedMessage['proof'] }, config.agentDid(), config.merchantDid());
      const challenge = consentStore.create({ ...bindings, authorizationOrigin });
      return c.json(await signMessage('consent.create.result', { requestNonce: message.proof.meta.nonce, challenge }, identity, config.merchantDid()));
    } catch { return c.json({ error: 'CONSENT_REQUEST_INVALID', message: 'A fresh merchant request and bound agent proof are required.' }, 400); }
  });
  app.post('/consent/pickup', async (c) => {
    try {
      const message = await readMessage(c);
      const body = await protocol.verify('consent.pickup', message, config.agentDid(), identity.did);
      const token = String(body['resumeToken'] ?? '');
      const flow = consentStore.get(token);
      if (!flow || flow.bindings.agentDid !== config.agentDid() || flow.bindings.audience !== body['audience']) throw new Error('Pickup binding differs');
      let result: Record<string, unknown> = { state: flow.state };
      // The challenge deadline limits the human decision, not delivery of an
      // already issued grant. Credential lifetime and revocation are separate.
      if (flow.state === 'pending' && flow.challenge.expiresAt <= Math.floor(Date.now() / 1000)) result = { state: 'expired' };
      else if (flow.state === 'approved' || flow.state === 'consumed') {
        // Required RP recording precedes delivery. Repeated pickup with a fresh
        // holder proof is idempotent, so a lost HTTP response cannot lose a grant.
        await consentAudit.flush();
        const vc = flow.file ? readJson<import('@kya-os/mcp').DelegationCredential>(flow.file) : null;
        if (!vc || flow.credentialDigest !== consentDigest(vc)) throw new Error('Issued credential unavailable');
        if (consentStore.get(token)?.state === 'approved') consentStore.consume(token, {
          agentDid: flow.bindings.agentDid, audience: flow.bindings.audience,
          credentialId: flow.credentialId!, credentialDigest: flow.credentialDigest!,
        });
        result = { state: 'approved', credential: vc };
      }
      return c.json(await signMessage('consent.pickup.result', { requestNonce: message.proof.meta.nonce, ...result }, identity, config.agentDid()));
    } catch { return c.json({ error: 'CONSENT_PICKUP_INVALID', message: 'Credential pickup requires its bound agent and a fresh proof.' }, 400); }
  });
  app.route('/', createConsentRoutes({ identity, statusListUrl: config.statusListUrl, authorizationOrigin, rpID: config.rpID, agentDid: config.agentDid, merchantDid: config.merchantDid, broadcast, consentWebauthn: config.consentWebauthn, identityAuth, store: consentStore, recordDecision: () => consentAudit.export() }));

  // ---- 1. identity ----------------------------------------------------------
  app.get('/.well-known/did.json', (c) => {
    c.header('Cache-Control', 'no-store');
    return c.json(ensureDidDocument(identity));
  });

  // ---- 2. the revocation list ----------------------------------------------
  app.get('/status-list', async (c) => {
    const list = await ensureStatusList({ identity, signingFunction, url: config.statusListUrl });
    c.header('Cache-Control', 'no-store');
    c.header('Content-Type', 'application/json');
    return c.body(JSON.stringify(list));
  });

  // ---- state for the console ------------------------------------------------
  app.get('/api/rp/state', async (c) => {
    const list = loadStatusList();
    const meta = loadStatusListMeta();
    const index = revocableIndex();
    const bit = list && index !== null ? await readBit(list, index) : null;
    let authenticators: ReturnType<typeof listAuthenticators> = [];
    let authenticatorStoreError: string | null = null;
    try { authenticators = listAuthenticators(); } catch (error) { authenticatorStoreError = error instanceof Error ? error.message : 'Authenticator store unavailable'; }
    return c.json({
      did: identity.did,
      kid: identity.kid,
      didDocumentUrl: new URL('/.well-known/did.json', c.req.url).toString(),
      statusListUrl: config.statusListUrl,
      statusList: { version: meta.version, updatedAt: meta.updatedAt, lastAction: meta.lastAction ?? null, issuanceDate: list?.issuanceDate ?? null },
      activeIndex: index,
      grantIssued: activeCredentialOrNull() !== null,
      consentRequired: true,
      consentWebauthn: config.consentWebauthn ?? false,
      googleIdentityEnabled: identityAuth.enabled,
      revoked: bit,
      keyRequired: keyRequired(),
      authenticatorStoreError,
      keySetup: config.keySetup,
      authenticators: authenticators.map((a) => ({ label: a.label, idTail: a.id.slice(-6) })),
    });
  });

  // ---- 3a. issue -------------------------------------------------------------
  app.post('/api/rp/issue', (c) => c.json({ error: 'consent_required', message: 'Place an order and approve the signed authorization URL. Direct issuance is disabled.' }, 403));
  app.post('/api/rp/reset', async (c) => {
    if (activeCredentialOrNull()) await revokeIndex(activeIndex(), { identity, statusListUrl: config.statusListUrl });
    await consentAudit.flush();
    clearActiveCredential(); consentStore.invalidatePending();
    broadcast({ type: 'grant.reset' });
    return c.json({ success: true, grantIssued: false, message: 'The agent starts with no grant. Place an order to request fresh human consent.' });
  });
  app.get('/api/rp/delegation', (c) => {
    const vc = activeCredentialOrNull();
    if (!vc) return c.json({ error: 'no active delegation' }, 404);
    return c.json({ index: activeIndex(), credential: vc });
  });

  // ---- 3b. revoke --------------------------------------------------------------
  async function performRevoke(index: number) {
    broadcast({ type: 'revoke_start', index });
    let result;
    try {
      result = await revokeIndex(index, {
        identity,
        statusListUrl: config.statusListUrl,
        onPhase: (p: RevokePhase) => broadcast({ type: 'revoke_phase', index, ...p }),
      });
    } catch (error) {
      broadcast({ type: 'revoke_failed', index, message: 'Revocation could not be confirmed. Check the current status list.' });
      throw error;
    }
    try {
      await consentAudit.export();
      result.audit = 'recorded';
    } catch (error) {
      // Publication is already verified. Export failure cannot undo revocation.
      // Retained RP source events remain available for the next export attempt.
      console.error('Revocation published; RP audit export unavailable:', error);
      result.audit = 'unavailable';
    }
    broadcast({ type: 'revoke_done', ...result });
    return result;
  }

  // Software path — used when the key feature is off or bypassed. When a key IS
  // required, the console runs the two-phase /api/rp/revoke/* flow instead.
  app.post('/api/rp/revoke', async (c) => {
    if (keyRequired()) {
      return c.json({ error: 'key_required', message: 'Revocation requires an authenticator assertion (/api/rp/revoke/challenge).' }, 403);
    }
    const body = await c.req.json().catch(() => ({} as Record<string, unknown>));
    const requested = Number((body as Record<string, unknown>)['index']);
    const index = Number.isInteger(requested) && requested >= 0 ? requested : revocableIndex();
    if (index === null) return c.json({ error: 'no_active_grant', message: 'There is no active grant to revoke. Approve a grant first.' }, 409);
    const restore = Boolean((body as Record<string, unknown>)['restore']);
    if (restore) {
      const result = await revokeIndex(index, { restore: true, identity, statusListUrl: config.statusListUrl });
      broadcast({ type: 'restored', ...result });
      return c.json(result);
    }
    return c.json(await performRevoke(index));
  });

  app.route('/', createKeyRoutes({
    rpID: config.rpID,
    origin: config.origin,
    rpName: 'KYA-OS Responsible Party',
    setupEnabled: config.keySetup,
    identityAuth,
    ...(identityAuth.enabled ? { registrationOrigin: googleOrigin } : {}),
    additionalRegistrationOrigins: [merchantOrigin(), rpOrigin()],
    statusListUrl: () => config.statusListUrl,
    currentIndex: revocableIndex,
    performRevoke,
  }));

  // ---- 4. witness the merchant's audit ledger ----------------------------------
  // The SDK observer, keyed with the RP's did:web key; created on first use.
  let witnessPromise: Promise<Witness> | null = null;
  const witness = () => (witnessPromise ??= createWitness(identity, { acceptIssuer: () => config.merchantDid() }));

  app.post('/api/rp/audit/observe', async (c) => {
    const body = (await c.req.json().catch(() => null)) as { checkpoint?: unknown; consistency?: unknown } | null;
    if (!body || typeof body !== 'object' || !body.checkpoint) return c.json({ error: 'expected { checkpoint, consistency? }' }, 400);
    try {
      const w = await witness();
      const receipt = await w.observe(body as never);
      const cp = (body.checkpoint as { core: { treeSize: string; rootDigest: string; ledgerId: string }; checkpointDigest: string });
      broadcast({ type: 'witnessed', ledgerId: cp.core.ledgerId, treeSize: cp.core.treeSize, rootDigest: cp.core.rootDigest, checkpointDigest: cp.checkpointDigest, observationDigest: receipt.observationDigest, observations: w.observations });
      return c.json({ receipt, observer: w.observer });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      broadcast({ type: 'witness_refused', message });
      return c.json({ error: message }, 409);
    }
  });

  app.get('/api/rp/audit/latest', async (c) => {
    const ledgerId = c.req.query('ledgerId') ?? '';
    const ledgerEpochId = c.req.query('ledgerEpochId') ?? '';
    const w = await witness();
    const latest = await w.latest(ledgerId, ledgerEpochId);
    return c.json({ observer: w.observer, observations: w.observations, latest });
  });
  app.get('/api/rp/audit/ledger', async (c) => c.json(await (await consentAudit.flush()).report()));
  app.get('/api/rp/audit/bundle', async (c) => c.json(await (await consentAudit.flush()).bundle()));
  app.post('/api/rp/audit/export', async (c) => c.json(await consentAudit.export()));

  app.get('/', (c) => c.json({
    role: 'responsible-party-hub',
    did: identity.did,
    didDocument: '/.well-known/did.json',
    statusList: '/status-list',
    api: ['/consent/requests', '/consent/pickup', '/api/rp/audit/ledger', '/api/rp/audit/bundle', '/api/rp/audit/export', '/api/rp/state', '/api/rp/issue', '/api/rp/revoke', '/api/rp/revoke/challenge', '/api/rp/revoke/execute', '/api/rp/key/list', '/api/rp/events', '/api/rp/audit/observe', '/api/rp/audit/latest'],
  }));

  return app;
}

export function rpConfigFromEnv(overrides: Partial<RpAppConfig> = {}): RpAppConfig {
  const authorizationOrigin = publicOrigin(rpOrigin());
  return {
    identity: loadRpIdentity(),
    statusListUrl: STATUS_LIST_URL,
    agentDid: () => env('AGENT_DID', ''),
    merchantDid: () => env('MERCHANT_DID', ''),
    corsOrigins: [...new Set([merchantOrigin(), authorizationOrigin, `http://localhost:${RP_PORT}`, `http://127.0.0.1:${RP_PORT}`])],
    keySetup: flag('KEY_SETUP'),
    keyWebauthn: flag('KEY_WEBAUTHN'),
    consentWebauthn: flag('CONSENT_WEBAUTHN'),
    bypassWebauthn: flag('DEMO_BYPASS_WEBAUTHN'),
    rpID: env('WEBAUTHN_RP_ID', 'localhost'),
    origin: env('WEBAUTHN_ORIGIN', merchantOrigin()),
    googleClientId: env('GOOGLE_CLIENT_ID', ''),
    googleOrigin: authorizationOrigin,
    authorizationOrigin,
    bindHost: env('BIND_HOST', '127.0.0.1'),
    ...overrides,
  };
}

export function startRpServer(port = RP_PORT, overrides: Partial<RpAppConfig> = {}) {
  const config = rpConfigFromEnv(overrides);
  const app = createRpApp(config);
  const server = serve({ fetch: app.fetch, port, hostname: config.bindHost ?? '127.0.0.1' }, () => {
    console.log(`Responsible Party hub: http://localhost:${port}`);
    console.log(`  did:          ${config.identity.did}`);
    console.log(`  did.json:     http://localhost:${port}/.well-known/did.json`);
    console.log(`  status list:  ${config.statusListUrl}`);
    console.log(`  revocation:   ${config.keyWebauthn && !config.bypassWebauthn ? (hasAuthenticator() ? 'authenticator touch REQUIRED' : 'BLOCKED: register an authenticator with KEY_SETUP=1') : 'software-confirmed'}`);
  });
  return { app, server, config };
}

if (isMainModule(import.meta.url)) startRpServer();
