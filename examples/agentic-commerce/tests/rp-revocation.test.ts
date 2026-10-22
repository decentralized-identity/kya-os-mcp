import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';

const { exportAudit } = vi.hoisted(() => ({ exportAudit: vi.fn() }));
vi.mock('../src/rp/audit.js', () => ({ createRpAudit: () => ({ export: exportAudit }) }));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rp-revocation-'));
let server: typeof import('../src/rp/server.js');
let issue: typeof import('../src/rp/issue.js');
let status: typeof import('../src/rp/statuslist.js');
let identity: import('../src/lib/wiring.js').KeyedIdentity;
const statusListUrl = 'http://localhost:4950/status-list';
beforeAll(async () => {
  process.env['DEMO_VAR_DIR'] = path.join(tmp, 'var');
  process.env['DEMO_DATA_DIR'] = path.join(tmp, 'data');
  process.env['DEMO_ENV_FILE'] = path.join(tmp, 'no-local-env');
  const key = await new NodeCryptoProvider().generateKeyPair();
  identity = { did: 'did:web:localhost%3A4950', kid: 'did:web:localhost%3A4950#key-1', privateKeyBase64: key.privateKey, publicKeyBase64: key.publicKey };
  process.env['AGENT_DID'] = generateDidKeyFromBase64(key.publicKey);
  server = await import('../src/rp/server.js');
  issue = await import('../src/rp/issue.js');
  status = await import('../src/rp/statuslist.js');
});
afterAll(() => { fs.rmSync(tmp, { recursive: true, force: true }); vi.restoreAllMocks(); });
const post = { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' };
const app = (keyWebauthn: boolean) => server.createRpApp({
  identity, statusListUrl, keyWebauthn, bypassWebauthn: false, googleClientId: '', keySetup: false,
  agentDid: () => process.env['AGENT_DID']!, merchantDid: () => 'did:key:merchant',
  corsOrigins: ['http://localhost:4949'], rpID: 'localhost', origin: 'http://localhost:4949',
});

describe('RP revocation failure boundaries', () => {
  it('never downgrades passkey enforcement when the key store is empty', async () => {
    const rp = app(true);
    expect((await rp.request('/api/rp/state')).status).toBe(200);
    expect(await (await rp.request('/api/rp/state')).json()).toMatchObject({ keyRequired: true, grantIssued: false, activeIndex: null });
    expect((await rp.request('/api/rp/revoke', post)).status).toBe(403);
    const challenge = await rp.request('/api/rp/revoke/challenge', post);
    expect(challenge.status).toBe(409);
    expect(await challenge.json()).toMatchObject({ error: 'no_active_grant' });
    expect(status.loadStatusListMeta().version).toBe(0);
  });

  it('reports a verified revocation even if the subsequent audit export fails', async () => {
    await issue.issueAndActivate({ index: 96, agentDid: process.env['AGENT_DID']!, audience: 'did:key:merchant', identity, statusListUrl });
    exportAudit.mockRejectedValueOnce(new Error('Simulated audit disk failure'));
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const rp = app(false);
    const response = await rp.request('/api/rp/revoke', post);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ index: 96, revoked: true, audit: 'unavailable' });
    expect(await status.readBit(status.loadStatusList()!, 96)).toBe(true);
    expect(log).toHaveBeenCalled();
    log.mockRestore();
  });
});
