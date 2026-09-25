import { describe, expect, it, vi } from 'vitest';
import { createConsentAuditBridge } from '../src/rp/consent-audit.js';
import { consentDigest } from '../src/lib/consent-evidence.js';
import type { MerchantAudit } from '../src/merchant/audit.js';
import type { ConsentFlowStore } from '../src/rp/consent-store.js';

const event = { id: 'consent-1', type: 'delegation.issued', actor: 'did:web:rp.example', payload: { credentialId: 'grant-94', index: 94, scope: 'https://id.gs1.org/01/09506000134352', cap: '50.00', currency: 'CHF', resumeTokenHash: 'a'.repeat(64) } };
function setup(events = [event]) {
  let pending = events;
  const record = vi.fn().mockResolvedValue({ status: 'recorded' });
  const acknowledgeEvents = vi.fn((ids: string[]) => { pending = pending.filter(e => !ids.includes(e.id)); });
  const store = { pendingEvents: () => pending, acknowledgeEvents } as unknown as ConsentFlowStore;
  return { bridge: createConsentAuditBridge({ record } as unknown as MerchantAudit, store, 'did:web:rp.example'), record, acknowledgeEvents };
}

describe('the RP records its own consent audit trail', () => {
  it('replays a legacy revocation without inventing an unavailable scope or cap', async () => {
    const { bridge, record } = setup([{ ...event, type: 'delegation.revoked', payload: { ...event.payload, scope: '', cap: '', currency: '' } }]);
    await bridge.flush();
    const input = record.mock.calls[0]![0];
    expect(input.authorization.scopeId).toBeUndefined();
    expect(input.action.name).toBe('revoke status-list index=94');
    expect(input.resource.value).toBe(consentDigest({ ...event.payload, scope: '', cap: '', currency: '' }));
  });

  it('records each RP event once when multiple requests flush concurrently', async () => {
    const { bridge, record, acknowledgeEvents } = setup();
    await Promise.all([bridge.flush(), bridge.flush(), bridge.flush()]);
    expect(record).toHaveBeenCalledTimes(1);
    expect(acknowledgeEvents).not.toHaveBeenCalled();
    expect(record.mock.calls[0]![0]).toMatchObject({ eventType: 'delegation.issued', details: { family: 'delegation', phase: 'issued', delegationRef: 'grant-94' }, authorization: { scopeId: event.payload.scope }, action: { name: 'place_order; index=94; MaxAmount=CHF 50.00' } });
  });
  it('identifies the public RP correctly and commits authentication within the human consent event', async () => {
    const payload = { ...event.payload, approvedScopes: [event.payload.scope], authentication: { credentialId: 'auth-key', aaguid: 'test-aaguid' } };
    const { bridge, record } = setup([{ ...event, type: 'consent.approved', payload }]);
    await bridge.flush();
    expect(record).toHaveBeenCalledOnce();
    expect(record.mock.calls[0]![0]).toMatchObject({
      eventType: 'consent.approved',
      actor: { kind: 'public_did', did: 'did:web:rp.example' },
      details: { family: 'consent', phase: 'approved', consentRef: consentDigest(payload.resumeTokenHash) },
      resource: { kind: 'keyed_commitment', value: consentDigest(payload) },
      action: { name: 'place_order' },
    });
  });
  it('replays older queued authenticator events as proof verification, not credential verification', async () => {
    const payload = { ...event.payload, authentication: { credentialId: 'legacy-key', userVerified: true } };
    const { bridge, record } = setup([{ ...event, type: 'credential.verified', payload }]);
    await bridge.flush();
    expect(record.mock.calls[0]![0]).toMatchObject({
      eventType: 'proof.verified', actor: { kind: 'public_did' },
      details: { family: 'proof', phase: 'verified', verificationCode: 'WEBAUTHN_ASSERTION_VERIFIED' },
      resource: { value: consentDigest(payload) },
    });
  });
  it('keeps undelivered events for retry and fails the call when required recording fails', async () => {
    const { bridge, record, acknowledgeEvents } = setup();
    record.mockResolvedValueOnce({ status: 'failed' });
    await expect(bridge.flush()).rejects.toThrow('AUDIT_UNAVAILABLE');
    expect(acknowledgeEvents).not.toHaveBeenCalled();
    await bridge.flush();
    expect(record).toHaveBeenCalledTimes(2);
    expect(acknowledgeEvents).not.toHaveBeenCalled();
  });
});
