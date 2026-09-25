import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { NodeCryptoProvider, generateDidKeyFromBase64, generateRequestProof, type DelegationCredential } from '@kya-os/mcp';

const crypto = new NodeCryptoProvider();
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rail-authorization-'));
const rpPort = 25000 + Math.floor(Math.random() * 1000);
let rp: ReturnType<typeof import('../src/rp/server.js')['startRpServer']>;
let merchant: Awaited<ReturnType<typeof import('../src/merchant/server.js')['createMerchant']>>;
let vc: DelegationCredential;
let merchantDid: string;
let agentIdentity: import('../src/lib/wiring.js').KeyedIdentity;

beforeAll(async () => {
  const [rpKeys, merchantKeys, agentKeys] = await Promise.all([crypto.generateKeyPair(), crypto.generateKeyPair(), crypto.generateKeyPair()]);
  merchantDid = generateDidKeyFromBase64(merchantKeys.publicKey);
  const agentDid = generateDidKeyFromBase64(agentKeys.publicKey);
  Object.assign(process.env, {
    DEMO_VAR_DIR: path.join(tmp, 'var'), DEMO_DATA_DIR: path.join(tmp, 'data'),
    RP_PORT: String(rpPort), MERCHANT_PORT: String(rpPort + 1),
    RP_ORIGIN: `http://127.0.0.1:${rpPort}`,
    RP_DID: `did:web:localhost%3A${rpPort}`, RP_KID: `did:web:localhost%3A${rpPort}#key-1`,
    RP_PRIVATE_KEY_BASE64: rpKeys.privateKey, RP_PUBLIC_KEY_BASE64: rpKeys.publicKey,
    MERCHANT_DID: merchantDid, MERCHANT_PRIVATE_KEY_BASE64: merchantKeys.privateKey, MERCHANT_PUBLIC_KEY_BASE64: merchantKeys.publicKey,
    AGENT_DID: agentDid, AGENT_ED25519_PRIVATE_KEY_BASE64: agentKeys.privateKey, AGENT_ED25519_PUBLIC_KEY_BASE64: agentKeys.publicKey,
    KEY_WEBAUTHN: '0', CONSENT_WEBAUTHN: '0', KEY_SETUP: '0', OFFLINE: '0',
  });
  const rpModule = await import('../src/rp/server.js');
  const { createMerchant, merchantConfigFromEnv } = await import('../src/merchant/server.js');
  const { ensureStatusList } = await import('../src/rp/statuslist.js');
  const wiring = await import('../src/lib/wiring.js');
  const { ConsentFlowStore } = await import('../src/rp/consent-store.js');
  const identity = wiring.loadRpIdentity();
  agentIdentity = wiring.loadAgentIdentity();
  rpModule.ensureDidDocument(identity);
  await ensureStatusList({ identity, signingFunction: wiring.makeVcSigningFunction(identity.privateKeyBase64), url: wiring.STATUS_LIST_URL });
  rp = rpModule.startRpServer(rpPort);
  merchant = await createMerchant(merchantConfigFromEnv({ witness: false, auditDir: path.join(tmp, 'audit') }));
  const scope = 'https://id.gs1.org/01/09506000134352';
  const challenge = new ConsentFlowStore().create({ agentDid, audience: merchantDid, product: 'risotto', quantity: 2,
    productClass: scope, cap: '50.00', currency: 'CHF', validHours: 48, authorizationOrigin: `http://127.0.0.1:${rpPort}` });
  const approval = await fetch(`http://127.0.0.1:${rpPort}/consent/approve`, { method: 'POST',
    body: new URLSearchParams({ tool: 'place_order', scopes: JSON.stringify([scope]), selected_scopes: JSON.stringify([scope]), agent_did: agentDid, session_id: challenge.resumeToken }) });
  expect(approval.ok, await approval.text()).toBe(true);
  vc = (await import('../src/rp/issue.js')).activeCredential();
});

afterAll(async () => {
  if (rp) await new Promise<void>(resolve => rp.server.close(() => resolve()));
  fs.rmSync(tmp, { recursive: true, force: true });
});

async function signedArgs(overrides: Record<string, unknown> = {}) {
  const args: Record<string, unknown> = { product: 'risotto', quantity: 2, checkoutId: 'checkout-1', _kyaos_delegation: vc, ...overrides };
  if (args['_kyaos_delegation'] === undefined) delete args['_kyaos_delegation'];
  args['_kyaos_proof'] = await generateRequestProof({ identity: {
    did: agentIdentity.did, kid: agentIdentity.kid, privateKey: agentIdentity.privateKeyBase64, publicKey: agentIdentity.publicKeyBase64,
  }, crypto, toolName: 'place_order', args, audience: merchantDid });
  return args;
}
const bodyOf = (result: { content?: Array<{ text?: string }> }) => JSON.parse(result.content?.[0]?.text ?? '{}');
const state = async () => (await merchant.app.request('/api/state')).json();

describe('every execution rail runs behind the same merchant authorization', () => {
  it.each([
    ['missing grant', { _kyaos_delegation: undefined }, 'needs_authorization'],
    ['outside product class', { product: 'olive-oil' }, 'PRODUCT_OUT_OF_SCOPE'],
    ['over the cap', { quantity: 5 }, 'SPEND_CAP_EXCEEDED'],
  ])('does not invoke a rail for %s', async (_case, overrides, code) => {
    const execute = vi.fn(() => ({ body: { ok: true, orderId: 'must-not-happen' } }));
    const before = (await state()).orders;
    const result = await merchant.executeOrder(await signedArgs(overrides as Record<string, unknown>), execute);
    expect(bodyOf(result).error, JSON.stringify(bodyOf(result))).toBe(code);
    expect(execute).not.toHaveBeenCalled();
    expect((await state()).orders).toBe(before);
  });

  it('rejects a forged credential before invoking a rail', async () => {
    const altered = structuredClone(vc);
    altered.credentialSubject.delegation.constraints.crisp!.scopes[0]!.constraints!['maxAmount'] = '999.00';
    const execute = vi.fn(() => ({ body: { ok: true, orderId: 'must-not-happen' } }));
    const result = await merchant.executeOrder(await signedArgs({ _kyaos_delegation: altered }), execute);
    expect(bodyOf(result).error).toBe('delegation_invalid');
    expect(execute).not.toHaveBeenCalled();
  });

  it('binds the immutable checkout intent to the holder proof', async () => {
    const args = await signedArgs();
    args.checkoutId = 'substituted-checkout';
    const execute = vi.fn(() => ({ body: { ok: true, orderId: 'must-not-happen' } }));
    const result = await merchant.executeOrder(args, execute);
    expect(bodyOf(result).error).toBe('holder_binding_failed');
    expect(execute).not.toHaveBeenCalled();
  });

  it('signs a quote after authorization without allocating an order or incrementing the counter', async () => {
    const before = await state();
    const execute = vi.fn(({ outcome, evidence }) => ({ body: { ...evidence, ok: false, error: 'PAYMENT_REQUIRED', quote: outcome.total } }));
    const result = await merchant.executeOrder(await signedArgs(), execute);
    expect(execute).toHaveBeenCalledTimes(1);
    expect(execute.mock.calls[0]![0].outcome).toMatchObject({ total: 'CHF 39.80', quantity: 2 });
    expect(execute.mock.calls[0]![0].outcome).not.toHaveProperty('orderId');
    expect(bodyOf(result)).toMatchObject({ error: 'PAYMENT_REQUIRED', quote: 'CHF 39.80' });
    expect(result._meta?.['org.kya-os/response-proof']).toBeTruthy();
    const after = await state();
    expect(after.orders).toBe(before.orders);
    expect(after.lastReceipt).toEqual(before.lastReceipt);
  });

  it('counts only a committed business order', async () => {
    const before = (await state()).orders;
    const execute = vi.fn(({ evidence }) => ({ body: { ...evidence, ok: true, orderId: 'RAIL-ORDER-1', payment: { status: 'settled' } } }));
    const result = await merchant.executeOrder(await signedArgs(), execute);
    expect(bodyOf(result).orderId).toBe('RAIL-ORDER-1');
    expect((await state()).orders).toBe(before + 1);
  });

  it('does not count an idempotent replay as another order', async () => {
    const before = (await state()).orders;
    const result = await merchant.executeOrder(await signedArgs(), ({ evidence }) => ({
      body: { ...evidence, ok: true, orderId: 'RAIL-ORDER-1' }, committed: false,
    }));
    expect(bodyOf(result).orderId).toBe('RAIL-ORDER-1');
    expect((await state()).orders).toBe(before);
  });

  it('preserves authority gates when payment is required or settlement is pending', async () => {
    const { checksFromOutcome } = await import('../src/merchant/server.js');
    for (const code of ['PAYMENT_REQUIRED', 'SETTLEMENT_PENDING']) {
      expect(checksFromOutcome('denied', code, '')).toEqual({
        signature: 'pass', revocation: 'pass', holder: 'pass', consent: 'pass',
        product: 'pass', cap: 'pass', receipt: 'skip',
      });
    }
  });

  it('does not invoke a rail when required merchant decision audit fails', async () => {
    const execute = vi.fn(() => ({ body: { ok: true, orderId: 'must-not-happen' } }));
    const record = vi.spyOn(merchant.audit, 'record').mockResolvedValue({ status: 'failed' } as never);
    try {
      await expect(merchant.executeOrder(await signedArgs(), execute)).rejects.toThrow(/AUDIT_UNAVAILABLE/);
      expect(execute).not.toHaveBeenCalled();
    } finally { record.mockRestore(); }
  });

  it('does not invoke a rail when the final business authorization cannot be recorded', async () => {
    const execute = vi.fn(() => ({ body: { ok: true, orderId: 'must-not-happen' } }));
    const original = merchant.audit.record.bind(merchant.audit);
    const record = vi.spyOn(merchant.audit, 'record').mockImplementation(async input => input.eventType === 'authorization.approved'
      ? { status: 'failed' } as never : original(input));
    try {
      const result = await merchant.executeOrder(await signedArgs(), execute);
      expect(bodyOf(result).error).toBe('AUDIT_UNAVAILABLE');
      expect(execute).not.toHaveBeenCalled();
    } finally { record.mockRestore(); }
  });

  it('preserves the wallet, displayed grant, cache, and event stream when the RP refuses reset', async () => {
    await merchant.executeOrder(await signedArgs(), ({ evidence }) => ({ body: { ...evidence, error: 'REVIEW_ONLY' } }));
    const { saveAgentState, AGENT_STATE_FILE } = await import('../src/agent/store.js');
    saveAgentState({ credential: vc });
    const wallet = fs.readFileSync(AGENT_STATE_FILE, 'utf8');
    const before = await state();
    expect(before.lastMandate).not.toBeNull();
    const stream = await merchant.app.request('/api/events');
    const reader = stream.body!.getReader();
    await reader.read(); // Initial hello event.
    const fetchOriginal = globalThis.fetch;
    const mockedFetch = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => String(input).endsWith('/api/rp/reset')
      ? Promise.resolve(Response.json({ error: 'ADMIN_AUTH_REQUIRED', message: 'Sign into the owner account.' }, { status: 403 }))
      : fetchOriginal(input, init));
    const invalidate = vi.spyOn(merchant.statusListResolver, 'invalidateCache');
    try {
      const response = await merchant.app.request('/api/act/reset', { method: 'POST' });
      expect(response.status).toBe(502);
      expect(await response.json()).toMatchObject({ error: 'ADMIN_AUTH_REQUIRED' });
      expect(fs.readFileSync(AGENT_STATE_FILE, 'utf8')).toBe(wallet);
      expect(invalidate).not.toHaveBeenCalled();
      expect((await state()).lastMandate).toEqual(before.lastMandate);
      merchant.broadcast({ type: 'reset-test-complete' });
      let events = '';
      while (!events.includes('reset-test-complete')) events += new TextDecoder().decode((await reader.read()).value);
      expect(events).not.toContain('"type":"reset"');
    } finally { mockedFetch.mockRestore(); invalidate.mockRestore(); await reader.cancel(); }
  });

  it('does not invoke a rail after revocation even with a fresh holder proof', async () => {
    const revoked = await fetch(`http://127.0.0.1:${rpPort}/api/rp/revoke`, { method: 'POST', body: '{}' });
    expect(revoked.ok, await revoked.text()).toBe(true);
    const execute = vi.fn(() => ({ body: { ok: true, orderId: 'must-not-happen' } }));
    const result = await merchant.executeOrder(await signedArgs(), execute);
    expect(bodyOf(result).reason).toMatch(/revoked/i);
    expect(execute).not.toHaveBeenCalled();
  });
});
