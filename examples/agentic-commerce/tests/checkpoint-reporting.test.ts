/**
 * The demo reports to Checkpoint, end to end and in-process: a Responsible
 * Party hub and a merchant edge configured ONLY through KYA_OS_EVENTS_URL and
 * KYA_OS_EVENTS_TOKEN, a real agent placing real orders, and a local stub of
 * `POST /api/v1/kya-os/events` in place of Checkpoint.
 *
 * It checks what reaches the stub (batches, auth header, the event for each
 * beat), and that a slow or refusing endpoint never changes or delays an order.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';
import type { CheckpointReporter } from '../src/lib/checkpoint-reporter.js';

const crypto = new NodeCryptoProvider();
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agentic-commerce-checkpoint-'));
const RP_PORT = 16950 + Math.floor(Math.random() * 1000);
const MERCHANT_PORT = RP_PORT + 1;
const TOKEN = 'kya_test_events_token_not_a_real_key';

type Event = { type: string; verdict?: string; error?: { excerpt: string }; delegation?: { jti: string }; session?: { agent?: { did: string } }; source: { serverDid: string } };
interface Received { method: string; url: string; apiKey: string | undefined; contentType: string | undefined; events: Event[]; answered: typeof mode }

// ---- the stub of Checkpoint's events endpoint ---------------------------------
let mode: 'accept' | 'refuse' | 'hang' = 'accept';
const received: Received[] = [];
const stub = http.createServer((req, res) => {
  let raw = '';
  req.on('data', (chunk) => { raw += chunk; });
  req.on('end', () => {
    const events = (JSON.parse(raw || '{}') as { events?: Event[] }).events ?? [];
    received.push({ method: req.method ?? '', url: req.url ?? '', apiKey: req.headers['x-api-key'] as string | undefined, contentType: req.headers['content-type'], events, answered: mode });
    if (mode === 'hang') return; // never answers; the reporter's timeout must cut it off
    if (mode === 'refuse') { res.writeHead(503).end(); return; }
    res.writeHead(202, { 'content-type': 'application/json' }).end(JSON.stringify({ accepted: events.length, skipped: 0, skipped_details: [] }));
  });
});

let rp: { server: { close: (cb?: () => void) => void }; config: { checkpoint?: CheckpointReporter | null } };
let merchant: { httpServer: { close: (cb?: () => void) => void }; checkpoint: CheckpointReporter | null };
let agent: typeof import('../src/agent/agent.js');
let merchantDid: string;

async function order(product: string, quantity = 1) {
  const started = Date.now();
  const outcome = await agent.runAgentOrder({ product, quantity, serverUrl: `http://localhost:${MERCHANT_PORT}/mcp`, audience: merchantDid });
  const body = JSON.parse(outcome.result.content?.[0]?.text ?? '{}') as Record<string, unknown>;
  return { denied: !!outcome.result.isError || !!body['error'], code: body['error'] as string | undefined, body, elapsedMs: Date.now() - started };
}

async function flushBoth(): Promise<void> {
  await Promise.all([merchant.checkpoint?.flush(), rp.config.checkpoint?.flush()]);
}

const allEvents = () => received.flatMap((request) => request.events);

async function until(condition: () => boolean, timeoutMs = 3_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error('timed out waiting for the stub');
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
const orderEvents = () => allEvents().filter((event) => event.type === 'tool.invoked');

beforeAll(async () => {
  await new Promise<void>((resolve) => stub.listen(0, '127.0.0.1', resolve));
  const stubPort = (stub.address() as AddressInfo).port;
  const rpKp = await crypto.generateKeyPair();
  const mKp = await crypto.generateKeyPair();
  const aKp = await crypto.generateKeyPair();
  merchantDid = generateDidKeyFromBase64(mKp.publicKey);
  // Environment BEFORE any example module is imported (wiring reads it at import).
  Object.assign(process.env, {
    DEMO_VAR_DIR: path.join(tmp, 'var'),
    DEMO_DATA_DIR: path.join(tmp, 'data'),
    RP_PORT: String(RP_PORT),
    MERCHANT_PORT: String(MERCHANT_PORT),
    RP_DID: `did:web:localhost%3A${RP_PORT}`,
    RP_KID: `did:web:localhost%3A${RP_PORT}#key-1`,
    RP_PRIVATE_KEY_BASE64: rpKp.privateKey,
    RP_PUBLIC_KEY_BASE64: rpKp.publicKey,
    MERCHANT_DID: merchantDid,
    MERCHANT_PRIVATE_KEY_BASE64: mKp.privateKey,
    MERCHANT_PUBLIC_KEY_BASE64: mKp.publicKey,
    AGENT_DID: generateDidKeyFromBase64(aKp.publicKey),
    AGENT_ED25519_PRIVATE_KEY_BASE64: aKp.privateKey,
    AGENT_ED25519_PUBLIC_KEY_BASE64: aKp.publicKey,
    KEY_WEBAUTHN: '0', KEY_SETUP: '0', OFFLINE: '0',
    // The bare origin: the reporter adds /api/v1/kya-os/events.
    KYA_OS_EVENTS_URL: `http://127.0.0.1:${stubPort}`,
    KYA_OS_EVENTS_TOKEN: TOKEN,
  });
  const rpMod = await import('../src/rp/server.js');
  const merchantMod = await import('../src/merchant/server.js');
  agent = await import('../src/agent/agent.js');
  const { ensureStatusList } = await import('../src/rp/statuslist.js');
  const { loadRpIdentity, makeVcSigningFunction, STATUS_LIST_URL } = await import('../src/lib/wiring.js');
  const identity = loadRpIdentity();
  rpMod.ensureDidDocument(identity);
  await ensureStatusList({ identity, signingFunction: makeVcSigningFunction(identity.privateKeyBase64), url: STATUS_LIST_URL });
  rp = rpMod.startRpServer(RP_PORT);
  merchant = await merchantMod.startMerchantServer({ port: MERCHANT_PORT, auditDir: path.join(tmp, 'audit') });
  await new Promise((resolve) => setTimeout(resolve, 300));
});

afterAll(async () => {
  if (merchant) await new Promise<void>((resolve) => merchant.httpServer.close(() => resolve()));
  if (rp) await new Promise<void>((resolve) => rp.server.close(() => resolve()));
  stub.closeAllConnections();
  await new Promise<void>((resolve) => stub.close(() => resolve()));
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('the demo reports every decision to Checkpoint', () => {
  it('both services pick the reporter up from the two settings', () => {
    expect(merchant.checkpoint).not.toBeNull();
    expect(rp.config.checkpoint).not.toBeNull();
  });

  it('runs the beats and sends one event per decision, approval and revocation', async () => {
    // Before any grant: refused, the shopper is asked.
    const first = await order('risotto', 2);
    expect(first.code).toBe('needs_authorization');
    const challenge = first.body as { authorizationUrl: string; resumeToken: string; scopes: string[] };
    const approved = await fetch(new URL('/consent/approve', challenge.authorizationUrl), {
      method: 'POST',
      body: new URLSearchParams({ tool: 'place_order', scopes: JSON.stringify(challenge.scopes), selected_scopes: JSON.stringify(challenge.scopes), agent_did: process.env['AGENT_DID']!, session_id: challenge.resumeToken }),
    });
    expect(approved.ok).toBe(true);

    expect((await order('risotto', 1)).denied).toBe(false);
    expect((await order('risotto', 3)).code).toBe('SPEND_CAP_EXCEEDED');
    expect((await order('olive-oil', 1)).code).toBe('PRODUCT_OUT_OF_SCOPE');
    const revoked = await fetch(`http://localhost:${RP_PORT}/api/rp/revoke`, { method: 'POST', body: '{}' });
    expect((await revoked.json()).revoked).toBe(true);
    const afterRevoke = await order('risotto', 1);
    expect(afterRevoke.denied).toBe(true);

    await flushBoth();

    // Every request: the events path, JSON, the project key in X-API-Key, 1 to 100 events.
    expect(received.length).toBeGreaterThan(0);
    for (const request of received) {
      expect(request.method).toBe('POST');
      expect(request.url).toBe('/api/v1/kya-os/events');
      expect(request.contentType).toBe('application/json');
      expect(request.apiKey).toBe(TOKEN);
      expect(request.events.length).toBeGreaterThanOrEqual(1);
      expect(request.events.length).toBeLessThanOrEqual(100);
    }

    const orders = orderEvents();
    expect(orders.map((event) => [event.verdict, event.error?.excerpt.split(':')[0] ?? 'permit'])).toEqual([
      ['fail', 'needs_authorization'],
      ['pass', 'permit'],
      ['fail', 'SPEND_CAP_EXCEEDED'],
      ['fail', 'PRODUCT_OUT_OF_SCOPE'],
      ['fail', 'delegation_revoked'],
    ]);
    expect(orders[2]!.error!.excerpt).toBe('SPEND_CAP_EXCEEDED: Over the spending limit. 3 x risotto = CHF 59.70, the limit is CHF 50.00 per order. Nothing was ordered.');
    expect(orders.every((event) => event.source.serverDid === merchantDid)).toBe(true);
    expect(orders[1]!.session?.agent?.did).toBe(process.env['AGENT_DID']);

    // The approval and the revocation come from the hub, for the grant the orders used.
    const observed = allEvents().filter((event) => event.type === 'delegation.observed');
    const revokes = allEvents().filter((event) => event.type === 'delegation.revoked');
    expect(observed).toHaveLength(1);
    expect(revokes).toHaveLength(1);
    const jti = observed[0]!.delegation!.jti;
    expect(orders[1]!.delegation?.jti).toBe(jti);
    expect(revokes[0]!.delegation?.jti).toBe(jti);
    expect(observed[0]!.source.serverDid).toBe(process.env['RP_DID']);
    // Checkpoint revokes only a grant it already knows: the approval is sent first.
    const position = (type: string) => allEvents().findIndex((event) => event.type === type);
    expect(position('delegation.observed')).toBeLessThan(position('delegation.revoked'));
  });

  it('a slow or refusing Checkpoint neither delays nor changes an order', async () => {
    // A fresh grant: Start over, then approve again.
    const reset = await fetch(`http://localhost:${MERCHANT_PORT}/api/act/reset`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    expect(reset.ok, await reset.text()).toBe(true);
    const ask = await order('risotto', 1);
    expect(ask.code).toBe('needs_authorization');
    const challenge = ask.body as { authorizationUrl: string; resumeToken: string; scopes: string[] };
    const approved = await fetch(new URL('/consent/approve', challenge.authorizationUrl), {
      method: 'POST',
      body: new URLSearchParams({ tool: 'place_order', scopes: JSON.stringify(challenge.scopes), selected_scopes: JSON.stringify(challenge.scopes), agent_did: process.env['AGENT_DID']!, session_id: challenge.resumeToken }),
    });
    expect(approved.ok).toBe(true);
    await flushBoth();
    const before = received.length;

    // Checkpoint refuses with 503.
    mode = 'refuse';
    const refused = await order('risotto', 2);
    expect(refused.denied).toBe(false);
    expect(refused.body['ok']).toBe(true);
    expect(refused.elapsedMs).toBeLessThan(2_500);
    await until(() => received.slice(before).some((request) => request.answered === 'refuse'));

    // Checkpoint takes the request and never answers (the retry of the refused batch hangs too).
    mode = 'hang';
    const slow = await order('risotto', 1);
    expect(slow.denied).toBe(false);
    expect(slow.body['ok']).toBe(true);
    // Reporting waits up to 3 s per attempt; the order never does.
    expect(slow.elapsedMs).toBeLessThan(2_500);
    await until(() => received.slice(before).some((request) => request.answered === 'hang'));

    // Once Checkpoint recovers, the timeout and retries deliver both decisions.
    mode = 'accept';
    await flushBoth();
    expect(merchant.checkpoint!.stats()).toMatchObject({ queued: 0, failed: 0 });
    const delivered = received.slice(before).filter((request) => request.answered === 'accept').flatMap((request) => request.events);
    expect(delivered.filter((event) => event.type === 'tool.invoked' && event.verdict === 'pass')).toHaveLength(2);
  }, 30_000);
});
