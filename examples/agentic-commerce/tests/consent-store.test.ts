import { afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ConsentFlowStore } from '../src/rp/consent-store.js';

const dirs: string[] = [];
const bindings = {
  agentDid: 'did:key:agent',
  audience: 'did:key:merchant',
  product: 'risotto',
  quantity: 2,
  productClass: 'https://id.gs1.org/01/09506000134352',
  cap: '50.00',
  currency: 'CHF',
  validHours: 48,
  authorizationOrigin: 'http://127.0.0.1:4950',
};
function store(now = () => Date.now()) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'consent-store-'));
  dirs.push(dir);
  return new ConsentFlowStore({ dir, now });
}
function form(token: string) {
  return {
    tool: 'place_order',
    agent_did: bindings.agentDid,
    scopes: JSON.stringify([bindings.productClass]),
    selected_scopes: JSON.stringify([bindings.productClass]),
    session_id: token,
  };
}
const issued = () =>
  Promise.resolve({
    file: '/tmp/grant.json',
    vc: {
      id: 'urn:grant:94',
      credentialStatus: { statusListIndex: '94' },
    } as never,
  });
afterEach(() => {
  for (const dir of dirs.splice(0))
    fs.rmSync(dir, { recursive: true, force: true });
});

describe('persistent bound consent decisions', () => {
  it('binds the authorization URL to the stored agent, scope and session', () => {
    const s = store();
    const c = s.create(bindings);
    const url = new URL(c.authorizationUrl);
    expect(c.error).toBe('needs_authorization');
    expect(c.scopes).toEqual([bindings.productClass]);
    expect(url.searchParams.get('resume_token')).toBe(c.resumeToken);
    expect(url.searchParams.get('agent_did')).toBe(bindings.agentDid);
    expect(
      new ConsentFlowStore({ dir: dirs[0]! }).get(c.resumeToken)?.bindings,
    ).toMatchObject(bindings);
  });
  it.each(['tool', 'agent_did', 'scopes', 'session_id', 'cap', 'audience'])(
    'rejects tampered %s before issuing',
    async (key) => {
      const s = store();
      const c = s.create(bindings);
      const issue = vi.fn(issued);
      await expect(
        s.approve(
          c.resumeToken,
          { ...form(c.resumeToken), [key]: 'tampered' },
          issue,
        ),
      ).rejects.toMatchObject({ code: 'consent_binding_mismatch' });
      expect(issue).not.toHaveBeenCalled();
      expect(s.get(c.resumeToken)?.state).toBe('pending');
    },
  );
  it('records the exact human selection before calling the issuer and preserves it in the consent audit commitment', async () => {
    const s = store();
    const c = s.create(bindings);
    const issue = vi.fn(async (flow) => {
      expect(flow.approvedScopes).toEqual([bindings.productClass]);
      expect(s.get(c.resumeToken)?.approvedScopes).toEqual([bindings.productClass]);
      return issued();
    });
    const approved = await s.approve(c.resumeToken, form(c.resumeToken), issue);
    expect(approved.approvedScopes).toEqual([bindings.productClass]);
    expect(approved.auditPayload?.['approvedScopes']).toEqual(approved.approvedScopes);
  });
  it('commits passkey evidence to consent approval without mislabelling it as a credential verification', async () => {
    const s = store();
    const c = s.create(bindings);
    const authentication = { method: 'webauthn', credentialId: 'registered-key', aaguid: 'fixture-aaguid' };
    await s.approve(c.resumeToken, form(c.resumeToken), async () => ({ ...await issued(), authentication }));
    expect(s.pendingEvents().map(event => event.type)).toEqual(['consent.approved', 'delegation.issued']);
    expect(s.pendingEvents()[0]?.payload).toMatchObject({ authentication, approvedScopes: [bindings.productClass] });
  });
  it('denial is persistent and cannot later approve or resume', async () => {
    const s = store();
    const c = s.create(bindings);
    s.deny(c.resumeToken, form(c.resumeToken));
    await expect(
      s.approve(c.resumeToken, form(c.resumeToken), issued),
    ).rejects.toMatchObject({ code: 'consent_denied' });
    expect(() =>
      s.consume(c.resumeToken, { agentDid: bindings.agentDid, audience: bindings.audience, credentialId: 'urn:grant:94', credentialDigest: s.get(c.resumeToken)?.credentialDigest ?? 'missing' }),
    ).toThrow();
    expect(s.pendingEvents().map((e) => e.type)).toEqual(['consent.denied']);
  });
  it('expires an undecided challenge while preserving delivery of an approved grant', async () => {
    let time = 1_000_000;
    const s = store(() => time);
    const c = s.create({ ...bindings, expiresAt: 1100 });
    await s.approve(c.resumeToken, form(c.resumeToken), issued);
    time = 1_100_000;
    expect(s.consume(c.resumeToken, { agentDid: bindings.agentDid, audience: bindings.audience, credentialId: 'urn:grant:94', credentialDigest: s.get(c.resumeToken)?.credentialDigest ?? 'missing' }).state).toBe('consumed');
    const d = s.create({ ...bindings, expiresAt: 1101 });
    time = 1_102_000;
    await expect(
      s.approve(d.resumeToken, form(d.resumeToken), issued),
    ).rejects.toMatchObject({ code: 'consent_expired' });
  });
  it('issues once under concurrent approval and consumes once for the approved grant', async () => {
    const s = store();
    const c = s.create(bindings);
    let release!: () => void;
    const issue = vi.fn(async () => {
      await new Promise<void>((r) => {
        release = r;
      });
      return issued();
    });
    const first = s.approve(c.resumeToken, form(c.resumeToken), issue);
    await expect(
      s.approve(c.resumeToken, form(c.resumeToken), issue),
    ).rejects.toMatchObject({ code: 'consent_busy' });
    release();
    const approved = await first;
    expect(issue).toHaveBeenCalledTimes(1);
    const redemption = { agentDid: bindings.agentDid, audience: bindings.audience,
      credentialId: approved.credentialId!, credentialDigest: approved.credentialDigest! };
    for (const key of ['agentDid', 'audience', 'credentialId', 'credentialDigest']) {
      expect(() => s.consume(c.resumeToken, { ...redemption, [key]: 'different' })).toThrow(/binding/);
      expect(s.get(c.resumeToken)?.state).toBe('approved');
    }
    // Product and quantity are order-policy inputs, not grant redemption inputs.
    expect(s.consume(c.resumeToken, redemption).state).toBe('consumed');
    expect(() => s.consume(c.resumeToken, redemption)).toThrow(/consumed/);
    expect(s.findByCredential('urn:grant:94')?.state).toBe('consumed');
    const events = s.pendingEvents();
    expect(events.map((e) => e.type)).toEqual([
      'consent.approved',
      'delegation.issued',
    ]);
    s.acknowledgeEvents(events.map((e) => e.id));
    expect(s.pendingEvents()).toEqual([]);
  });
  it('recovers a dead issuer process lock before resetting pending consent', () => {
    const s = store();
    const c = s.create(bindings);
    fs.mkdirSync(path.join(s.dir, '.lock'));
    fs.writeFileSync(
      path.join(s.dir, '.lock', 'owner.json'),
      JSON.stringify({ pid: 2147483647 }),
    );
    s.invalidatePending();
    expect(s.get(c.resumeToken)?.state).toBe('failed');
    expect(fs.existsSync(path.join(s.dir, '.lock'))).toBe(false);
  });
  it('fails closed after issuance failure and rejects path-like tokens', async () => {
    const s = store();
    const c = s.create(bindings);
    await expect(
      s.approve(c.resumeToken, form(c.resumeToken), async () => {
        throw new Error('issuer unavailable');
      }),
    ).rejects.toThrow('issuer unavailable');
    expect(s.get(c.resumeToken)?.state).toBe('failed');
    expect(s.get('../../active-index')).toBeUndefined();
  });
});
