import { describe, it, expect } from 'vitest';
import { verifyApprovalQuorum, type ApprovalGrant } from '../approval.js';

const grant = (over: Partial<ApprovalGrant> = {}): ApprovalGrant => ({
  approvalRequestId: 'r1',
  approverDid: 'did:example:a',
  requestHash: 'sha256:abc',
  decision: 'approve',
  ts: 1,
  signature: 'sig',
  ...over,
});

const validSig = async () => true;

describe('verifyApprovalQuorum', () => {
  it('is satisfied by N distinct approvers over the same requestHash', async () => {
    const grants = [grant({ approverDid: 'did:a' }), grant({ approverDid: 'did:b' })];
    const r = await verifyApprovalQuorum(grants, 'sha256:abc', { n: 2, approvers: [] }, validSig);
    expect(r.satisfied).toBe(true);
  });

  it('is not satisfied with too few approvers', async () => {
    const r = await verifyApprovalQuorum([grant({ approverDid: 'did:a' })], 'sha256:abc', { n: 2, approvers: [] }, validSig);
    expect(r.satisfied).toBe(false);
  });

  it('rejects grants bound to a different requestHash (TOCTOU guard)', async () => {
    const grants = [grant({ approverDid: 'did:a', requestHash: 'sha256:OTHER' }), grant({ approverDid: 'did:b', requestHash: 'sha256:OTHER' })];
    const r = await verifyApprovalQuorum(grants, 'sha256:abc', { n: 2, approvers: [] }, validSig);
    expect(r.satisfied).toBe(false);
  });

  it('counts duplicate approver DIDs once', async () => {
    const grants = [grant({ approverDid: 'did:a' }), grant({ approverDid: 'did:a' })];
    const r = await verifyApprovalQuorum(grants, 'sha256:abc', { n: 2, approvers: [] }, validSig);
    expect(r.satisfied).toBe(false);
  });

  it('ignores deny grants and invalid signatures', async () => {
    const grants = [grant({ approverDid: 'did:a', decision: 'deny' }), grant({ approverDid: 'did:b' })];
    const denyCounted = await verifyApprovalQuorum(grants, 'sha256:abc', { n: 2, approvers: [] }, validSig);
    expect(denyCounted.satisfied).toBe(false);

    const badSig = await verifyApprovalQuorum([grant({ approverDid: 'did:a' })], 'sha256:abc', { n: 1, approvers: [] }, async () => false);
    expect(badSig.satisfied).toBe(false);
  });

  it('treats a non-positive quorum as never-satisfiable (misconfiguration guard)', async () => {
    const zero = await verifyApprovalQuorum([], 'sha256:abc', { n: 0, approvers: [] }, validSig);
    expect(zero.satisfied).toBe(false);
    const neg = await verifyApprovalQuorum(
      [grant()],
      'sha256:abc',
      { n: -1, approvers: [] },
      validSig,
    );
    expect(neg.satisfied).toBe(false);
  });

  it('enforces the allowed-approver allowlist', async () => {
    const grants = [grant({ approverDid: 'did:outsider' })];
    const r = await verifyApprovalQuorum(grants, 'sha256:abc', { n: 1, approvers: ['did:insider'] }, validSig);
    expect(r.satisfied).toBe(false);
  });
});
