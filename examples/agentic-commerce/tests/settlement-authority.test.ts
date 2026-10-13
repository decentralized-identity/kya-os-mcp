import { afterEach, describe, expect, it, vi } from 'vitest';
import type { DelegationCredential } from '@kya-os/mcp';
import { checksFromOutcome, verifySettlementAuthority, type GateChecks } from '../src/merchant/server.js';

afterEach(() => vi.restoreAllMocks());
const passed = (): Partial<GateChecks> => ({ signature: 'pass', revocation: 'pass', holder: 'pass', product: 'pass', cap: 'pass', consent: 'pass' });
const credential = (expiresAt: number): DelegationCredential => ({
  credentialSubject: { delegation: { constraints: { notAfter: expiresAt / 1000 } } },
  credentialStatus: { id: 'https://rp.example/status#1', type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '1', statusListCredential: 'https://rp.example/status' },
} as unknown as DelegationCredential);

describe('final authority evidence controls the displayed refusal gate', () => {
  it.each([
    ['AUTHORITY_REVOKED', async () => true],
    ['AUTHORITY_STATUS_UNAVAILABLE', async () => { throw new Error('network unavailable'); }],
  ])('overwrites the earlier revocation pass when the final check returns %s', async (code, check) => {
    const observed = passed();
    const resolver = { invalidateCache: vi.fn(), checkStatus: vi.fn(check) };
    await expect(verifySettlementAuthority(credential(Date.now() + 60_000), resolver, observed)).rejects.toThrow(code);
    expect(resolver.invalidateCache).toHaveBeenCalledOnce();
    expect(checksFromOutcome('denied', code, '', observed)).toMatchObject({ signature: 'pass', revocation: 'fail', holder: 'pass', product: 'pass', cap: 'pass' });
  });

  it('shows the validity-window gate when the grant expires during status retrieval', async () => {
    let now = Date.now();
    const expiresAt = now + 500;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const observed = passed();
    const resolver = { invalidateCache: vi.fn(), checkStatus: vi.fn(async () => { now = expiresAt; return false; }) };
    await expect(verifySettlementAuthority(credential(expiresAt), resolver, observed)).rejects.toThrow('AUTHORITY_EXPIRED');
    expect(checksFromOutcome('denied', 'AUTHORITY_EXPIRED', '', observed)).toMatchObject({ signature: 'fail', revocation: 'pass', holder: 'pass' });
  });

  it('keeps all actual authority passes for ordinary payment and checkout failures', () => {
    for (const code of ['PAYMENT_REQUIRED', 'PAYMENT_INVALID', 'PAYMENT_FAILED', 'PAYMENT_REPLAY', 'CHECKOUT_EXPIRED', 'SETTLEMENT_PENDING']) {
      expect(checksFromOutcome('denied', code, '')).toMatchObject({ ...passed(), receipt: 'skip' });
    }
  });
});
