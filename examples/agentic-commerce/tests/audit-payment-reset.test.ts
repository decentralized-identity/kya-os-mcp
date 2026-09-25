import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'commerce-audit-payment-reset-'));
const crypto = new NodeCryptoProvider();
let rpPort: number, merchantPort: number, origin: string;
let rp: ReturnType<typeof import('../src/rp/server.js').startRpServer>;
let merchant: Awaited<ReturnType<typeof import('../src/merchant/server.js').startMerchantServer>>;
let runtime: NonNullable<typeof merchant.commerce>;
let commerce: typeof import('../src/agent/commerce.js');
let wallet: typeof import('../src/agent/store.js');
let wiring: typeof import('../src/lib/wiring.js');
let protocol: typeof import('../src/lib/consent-protocol.js');
const auditDir = path.join(tmp, 'audit');
const bodyOf = (result: { content?: Array<{ text?: string }> }) => JSON.parse(result.content?.[0]?.text ?? '{}');
const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
};

beforeAll(async () => {
  const reserve = async () => {
    const listener = net.createServer();
    await new Promise<void>(resolve => listener.listen(0, '127.0.0.1', resolve));
    return { listener, port: (listener.address() as net.AddressInfo).port };
  };
  const reservations = await Promise.all([reserve(), reserve()]);
  [rpPort, merchantPort] = reservations.map(value => value.port) as [number, number];
  await Promise.all(reservations.map(({ listener }) => new Promise<void>(resolve => listener.close(() => resolve()))));
  origin = `http://127.0.0.1:${merchantPort}`;
  const rpOrigin = `http://127.0.0.1:${rpPort}`;
  const [r, m, a] = await Promise.all([crypto.generateKeyPair(), crypto.generateKeyPair(), crypto.generateKeyPair()]);
  for (const [key, value] of Object.entries({
    DEMO_ENV_FILE: path.join(tmp, 'missing.env'), DEMO_VAR_DIR: path.join(tmp, 'var'), DEMO_DATA_DIR: path.join(tmp, 'data'),
    RP_PORT: String(rpPort), MERCHANT_PORT: String(merchantPort), RP_ORIGIN: rpOrigin, MERCHANT_ORIGIN: origin,
    RP_DID: `did:web:localhost%3A${rpPort}`, RP_KID: `did:web:localhost%3A${rpPort}#key-1`,
    STATUS_LIST_URL: `${rpOrigin}/status-list`, RP_DID_MIRROR_URL: `${rpOrigin}/.well-known/did.json`,
    RP_PRIVATE_KEY_BASE64: r.privateKey, RP_PUBLIC_KEY_BASE64: r.publicKey,
    MERCHANT_DID: generateDidKeyFromBase64(m.publicKey), MERCHANT_PRIVATE_KEY_BASE64: m.privateKey, MERCHANT_PUBLIC_KEY_BASE64: m.publicKey,
    AGENT_DID: generateDidKeyFromBase64(a.publicKey), AGENT_ED25519_PRIVATE_KEY_BASE64: a.privateKey, AGENT_ED25519_PUBLIC_KEY_BASE64: a.publicKey,
    KEY_WEBAUTHN: '0', CONSENT_WEBAUTHN: '0', KEY_SETUP: '0', OFFLINE: '0', GOOGLE_CLIENT_ID: '',
    COMMERCE_PAYMENTS: '1', PAYMENT_MODE: 'sandbox', X402_ATOMIC_UNITS_PER_CHF_CENT: '10000',
    X402_PAY_TO: '0x000000000000000000000000000000000000dEaD',
  })) vi.stubEnv(key, value);
  wiring = await import('../src/lib/wiring.js');
  wallet = await import('../src/agent/store.js');
  commerce = await import('../src/agent/commerce.js');
  protocol = await import('../src/lib/consent-protocol.js');
  const rpModule = await import('../src/rp/server.js');
  rpModule.ensureDidDocument(wiring.loadRpIdentity());
  rp = rpModule.startRpServer(rpPort);
  merchant = await (await import('../src/merchant/server.js')).startMerchantServer({ port: merchantPort, origin, witness: true, auditDir });
  if (!merchant.commerce) throw new Error('Payment concurrency fixture requires explicit commerce opt-in');
  runtime = merchant.commerce;
});
afterEach(() => vi.restoreAllMocks());
afterAll(async () => {
  if (merchant) {
    merchant.httpServer.closeAllConnections();
    await new Promise<void>(resolve => merchant.httpServer.close(() => resolve()));
  }
  if (rp) await new Promise<void>(resolve => rp.server.close(() => resolve()));
  vi.unstubAllEnvs(); fs.rmSync(tmp, { recursive: true, force: true });
});

const run = (checkoutId?: string) => commerce.runAgentCommerce({ product: 'risotto', quantity: 2, paymentProtocol: 'x402',
  paymentMethod: 'x402', checkoutId, serverUrl: `${origin}/mcp`, audience: wiring.loadMerchantIdentity().did });
const reset = () => fetch(`${origin}/api/act/reset`, { method: 'POST' });
async function approveGrant() {
  const request = bodyOf((await run()).result);
  expect(request.error).toBe('needs_authorization');
  const response = await fetch(new URL('/consent/approve', request.authorizationUrl), { method: 'POST', body: new URLSearchParams({
    tool: 'place_order', scopes: JSON.stringify(request.scopes), selected_scopes: JSON.stringify(request.scopes),
    agent_did: wiring.loadAgentIdentity().did, session_id: request.resumeToken,
  }) });
  expect(response.ok, await response.text()).toBe(true);
}
function observeResetFiles() {
  const original = globalThis.fetch;
  const snapshots = new Map<string, string>();
  vi.spyOn(globalThis, 'fetch').mockImplementation((url, init) => {
    if (String(url).endsWith('/api/rp/reset')) {
      for (const file of [runtime.coordinator.journal.file, wallet.AGENT_COMMERCE_FILE, wallet.AGENT_PAYMENT_WALLET_FILE]) {
        snapshots.set(file, fs.readFileSync(file, 'utf8'));
      }
    }
    return original(url, init);
  });
  return snapshots;
}
function expectRecoveryFilesUnchanged(snapshots: Map<string, string>) {
  expect(snapshots.size).toBe(3);
  for (const [file, contents] of snapshots) expect(fs.readFileSync(file, 'utf8')).toBe(contents);
  expect(wallet.readAgentState()).toEqual({});
}
function archivedEntries(epoch: string) {
  const files = fs.readdirSync(path.join(auditDir, 'archives'), { recursive: true }).map(String).filter(file => file.endsWith('bundle.json'));
  const bundle = files.map(file => JSON.parse(fs.readFileSync(path.join(auditDir, 'archives', file), 'utf8')))
    .find(value => JSON.stringify(value).includes(epoch));
  expect(bundle).toBeDefined();
  return bundle.components.find((part: { path: string }) => part.path === 'entries.json').content as Array<{
    core: { event: { eventType: string; correlationId?: string; action: { name: string } } };
  }>;
}

describe('Start over with optional sandbox payment in flight', () => {
  it('finishes a signed payment before reset and preserves its nonce reservation, checkout and wallet for later recovery', async () => {
    await approveGrant();
    const entered = deferred(), release = deferred();
    const settle = runtime.rail.settle.bind(runtime.rail);
    const settling = vi.spyOn(runtime.rail, 'settle').mockImplementationOnce(async (...args) => {
      entered.resolve(); await release.promise; return settle(...args);
    });
    const snapshots = observeResetFiles(), epoch = merchant.audit.ledger.ledgerEpochId;
    const buying = run();
    let resetting: Promise<Response> | undefined;
    try {
      await entered.promise;
      let resetFinished = false;
      resetting = reset().then(response => { resetFinished = true; return response; });
      await new Promise(resolve => setTimeout(resolve, 30));
      expect(resetFinished).toBe(false); expect(snapshots.size).toBe(0);
      expect(merchant.audit.ledger.ledgerEpochId).toBe(epoch);
      release.resolve();
      const purchased = bodyOf((await buying).result), response = await resetting;
      expect(purchased).toMatchObject({ ok: true, payment: { status: 'simulated', simulated: true } });
      expect(response.status).toBe(200);
      expectRecoveryFilesUnchanged(snapshots);
      const record = runtime.coordinator.get(purchased.checkoutId)!;
      expect(record.state).toBe('settled');
      expect(runtime.coordinator.journal.read().payments[record.paymentIdentity!]).toBe(record.id);
      expect(wallet.readAgentCheckout(record.id)?.payload).toBeTruthy();
      expect(await merchant.audit.entries()).toEqual([]);
      const completed = archivedEntries(epoch).filter(entry => entry.core.event.correlationId === record.id
        && entry.core.event.action.name === 'payment.x402' && entry.core.event.eventType === 'tool.call.completed');
      expect(completed).toHaveLength(1);
      // Model a lost client response: recover the existing result after the
      // grant was reset, without creating another authorization or transfer.
      const saved = wallet.readAgentCheckout(record.id)!;
      wallet.saveAgentCheckout({ ...saved, state: 'pending', lastResult: undefined });
      const recovered = bodyOf((await run(record.id)).result);
      expect(recovered.orderId).toBe(purchased.orderId);
      expect(settling).toHaveBeenCalledTimes(1);
      expect(await merchant.audit.entries()).toEqual([]);
    } finally {
      release.resolve(); await Promise.allSettled([buying, ...(resetting ? [resetting] : [])]);
    }
  });

  it('waits for authenticated HTTP completion-evidence recovery outside the agent queue before archiving', async () => {
    await approveGrant();
    const record = merchant.audit.record.bind(merchant.audit);
    const failedEvidence = vi.spyOn(merchant.audit, 'record').mockImplementation(async (input, options) => {
      if (input.eventType === 'tool.call.completed' && input.action.name === 'payment.x402') throw new Error('temporary audit delivery outage');
      return record(input, options);
    });
    const purchased = bodyOf((await run()).result);
    expect(purchased.ok).toBe(true);
    expect(runtime.coordinator.get(purchased.checkoutId)?.completionEvidence?.deliveredAt).toBeUndefined();
    failedEvidence.mockRestore();
    const entered = deferred(), release = deferred();
    vi.spyOn(merchant.audit, 'record').mockImplementation(async (input, options) => {
      if (input.eventType === 'tool.call.completed' && input.action.name === 'payment.x402') { entered.resolve(); await release.promise; }
      return record(input, options);
    });
    const settling = vi.spyOn(runtime.rail, 'settle');
    const snapshots = observeResetFiles(), epoch = merchant.audit.ledger.ledgerEpochId;
    const signed = await protocol.signMessage('payment.status', { id: purchased.checkoutId }, wiring.loadAgentIdentity(), wiring.loadMerchantIdentity().did);
    const recovering = fetch(`${origin}/payments/checkouts/${purchased.checkoutId}`, {
      headers: { 'X-KYA-Request': Buffer.from(JSON.stringify(signed)).toString('base64') },
    });
    let resetting: Promise<Response> | undefined;
    try {
      await entered.promise;
      let resetFinished = false;
      resetting = reset().then(response => { resetFinished = true; return response; });
      await new Promise(resolve => setTimeout(resolve, 30));
      expect(resetFinished).toBe(false); expect(snapshots.size).toBe(0);
      release.resolve();
      const recovered = await recovering, restarted = await resetting;
      expect(recovered.status).toBe(200); expect(restarted.status).toBe(200);
      const message = await recovered.json();
      const status = await new protocol.ConsentProtocol().verify('payment.status.result', message, wiring.loadMerchantIdentity().did, wiring.loadAgentIdentity().did);
      expect(status).toMatchObject({ state: 'settled', requestNonce: signed.proof.meta.nonce, result: { orderId: purchased.orderId } });
      expectRecoveryFilesUnchanged(snapshots);
      expect(runtime.coordinator.get(purchased.checkoutId)?.completionEvidence?.deliveredAt).toBeTruthy();
      expect(archivedEntries(epoch).filter(entry => entry.core.event.correlationId === purchased.checkoutId
        && entry.core.event.action.name === 'payment.x402' && entry.core.event.eventType === 'tool.call.completed')).toHaveLength(1);
      expect(await merchant.audit.entries()).toEqual([]);
      expect(settling).not.toHaveBeenCalled();
    } finally {
      release.resolve(); await Promise.allSettled([recovering, ...(resetting ? [resetting] : [])]);
    }
  });
});
