/**
 * An outcome proof (a denial, a step-up or a consent challenge) binds the
 * request a client or auditor can recompute from the call as sent: SPEC §7.3's
 * request with every `_kyaos*` control argument removed, whichever control
 * arguments the call carried and whichever gate decided the outcome.
 */
import { describe, it, expect, vi } from 'vitest';
import type { KyaOsMiddleware, KyaOsToolHandler } from '../with-kya-os.js';
import { DelegationCredentialIssuer } from '../../delegation/vc-issuer.js';
import { generateRequestProof } from '../../delegation/holder-binding.js';
import { generateDidKeyFromBase64, didKeyFragment } from '../../utils/did-helpers.js';
import { base64urlEncodeFromBytes } from '../../utils/base64.js';
import type { CredentialStatus, DelegationCredential, Proof } from '../../types/protocol.js';
import { logger } from '../../logging/index.js';
import { createMiddleware, crypto, handshake, proofOf, served, verifyReceived } from './helpers/received-proof.js';

const SCOPE = 'vault:read';
const CONSENT = { scopeId: SCOPE, consentUrl: 'https://example.com/consent' };
const ran: KyaOsToolHandler = async () => ({ content: [{ type: 'text', text: 'ran' }] });

/** A did:key identity whose secret key the test holds as base64. */
interface TestIdentity {
  did: string;
  kid: string;
  privateKey: string;
  publicKey: string;
}

async function identity(): Promise<TestIdentity> {
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  return { did, kid: `${did}#${didKeyFragment(did)}`, ...keyPair };
}

/** A delegation to `subjectDid`, signed by a fresh issuer. */
async function delegation(
  subjectDid: string,
  options: { scopes?: string[]; credentialStatus?: CredentialStatus } = {},
): Promise<DelegationCredential> {
  const issuer = await identity();
  const sign = async (canonical: string, _did: string, kid: string): Promise<Proof> => ({
    type: 'Ed25519Signature2020',
    created: new Date().toISOString(),
    verificationMethod: kid,
    proofPurpose: 'assertionMethod',
    proofValue: base64urlEncodeFromBytes(await crypto.sign(new TextEncoder().encode(canonical), issuer.privateKey)),
  });
  return new DelegationCredentialIssuer(
    { getDid: () => issuer.did, getKeyId: () => issuer.kid, getPrivateKey: () => issuer.privateKey },
    sign,
  ).createAndIssueDelegation(
    {
      id: `del-${Math.random().toString(16).slice(2)}`,
      issuerDid: issuer.did,
      subjectDid,
      constraints: { scopes: options.scopes ?? [SCOPE], notAfter: Math.floor(Date.now() / 1000) + 3600 },
    },
    options.credentialStatus ? { credentialStatus: options.credentialStatus } : {},
  );
}

const grant = { approvalRequestId: 'r1', approverDid: 'did:example:approver', requestHash: 'sha256:x', decision: 'approve', ts: 1, signature: 'sig' };

/** The proof verifies against every argument as sent, in both request shapes a client may hold. */
async function expectVerifiesAsSent(
  kyaos: KyaOsMiddleware,
  result: Record<string, unknown>,
  toolName: string,
  sent: Record<string, unknown>,
  binds: 'content' | 'nothing',
): Promise<void> {
  for (const shape of ['legacy', 'tools/call'] as const) {
    const verified = await verifyReceived(result, { signer: kyaos.identity.did, toolName, params: sent, binds, shape });
    expect(verified.valid, `${shape}: ${verified.reason ?? ''}`).toBe(true);
  }
}

const errorOf = (result: Record<string, unknown>): string =>
  JSON.parse((result.content as Array<{ text: string }>)[0]!.text).error as string;

describe('delegation-gate outcome proofs bind the call as sent', () => {
  it.each([
    ['_kyaos_proof', { path: '/secret', _kyaos_proof: { jws: 'x', meta: {} } }],
    ['a null _kyaos_delegation and _kyaos_proof', { path: '/secret', _kyaos_delegation: null, _kyaos_proof: { jws: 'x', meta: {} } }],
  ])('needs_authorization, on a call carrying %s (and the client can check the challenge body)', async (_label, sent) => {
    const kyaos = await served(await createMiddleware());
    const sessionId = await handshake(kyaos);

    const result = await kyaos.wrapWithDelegation('vault', CONSENT, ran)(sent, sessionId) as Record<string, unknown>;

    expect(proofOf(result)?.meta.outcome).toBe('needs_authorization');
    await expectVerifiesAsSent(kyaos, result, 'vault', sent, 'content');
  });

  it('an invalid delegation, on a call carrying _kyaos_approvals', async () => {
    const kyaos = await served(await createMiddleware());
    const sessionId = await handshake(kyaos);
    const agent = await identity();
    const forged = await delegation(agent.did);
    forged.credentialSubject.delegation.constraints.scopes = [SCOPE, 'vault:write'];
    const sent = { path: '/secret', _kyaos_delegation: forged, _kyaos_approvals: [grant] };

    const result = await kyaos.wrapWithDelegation('vault', CONSENT, ran)(sent, sessionId) as Record<string, unknown>;

    expect(errorOf(result)).toBe('delegation_invalid');
    await expectVerifiesAsSent(kyaos, result, 'vault', sent, 'nothing');
  });

  it('a revoked delegation, on a call carrying _kyaos_proof', async () => {
    const kyaos = await served(await createMiddleware({
      delegation: { statusListResolver: { checkStatus: async () => true } },
    }));
    const sessionId = await handshake(kyaos);
    const agent = await identity();
    const revoked = await delegation(agent.did, {
      credentialStatus: {
        id: 'https://status.example/revocation/v1#0',
        type: 'StatusList2021Entry',
        statusPurpose: 'revocation',
        statusListIndex: '0',
        statusListCredential: 'https://status.example/revocation/v1',
      },
    });
    const sent = { path: '/secret', _kyaos_delegation: revoked, _kyaos_proof: { jws: 'x', meta: {} } };

    const result = await kyaos.wrapWithDelegation('vault', CONSENT, ran)(sent, sessionId) as Record<string, unknown>;

    expect(errorOf(result)).toBe('delegation_invalid');
    await expectVerifiesAsSent(kyaos, result, 'vault', sent, 'nothing');
  });

  it('a holder binding with no request proof, on a call carrying _kyaos_approvals', async () => {
    const kyaos = await served(await createMiddleware({ delegation: { holderBinding: 'enforce' } }));
    const sessionId = await handshake(kyaos);
    const agent = await identity();
    const sent = { path: '/secret', _kyaos_delegation: await delegation(agent.did), _kyaos_approvals: [grant] };

    const result = await kyaos.wrapWithDelegation('vault', CONSENT, ran)(sent, sessionId) as Record<string, unknown>;

    expect(errorOf(result)).toBe('holder_binding_failed');
    await expectVerifiesAsSent(kyaos, result, 'vault', sent, 'nothing');
  });

  it('a holder binding whose request proof another key signed', async () => {
    const kyaos = await served(await createMiddleware({ delegation: { holderBinding: 'enforce' } }));
    const sessionId = await handshake(kyaos);
    const agent = await identity();
    const base = { path: '/secret', _kyaos_delegation: await delegation(agent.did) };
    const stolen = await generateRequestProof({
      identity: await identity(), crypto, toolName: 'vault', args: base, audience: kyaos.identity.did, sessionId,
    });
    const sent = { ...base, _kyaos_proof: stolen };

    const result = await kyaos.wrapWithDelegation('vault', CONSENT, ran)(sent, sessionId) as Record<string, unknown>;

    expect(errorOf(result)).toBe('holder_binding_failed');
    await expectVerifiesAsSent(kyaos, result, 'vault', sent, 'nothing');
  });

  it('an insufficient scope, on a call carrying _kyaos_proof and _kyaos_approvals', async () => {
    const kyaos = await served(await createMiddleware());
    const sessionId = await handshake(kyaos);
    const agent = await identity();
    const sent = {
      path: '/secret',
      _kyaos_delegation: await delegation(agent.did, { scopes: ['files:read'] }),
      _kyaos_proof: { jws: 'x', meta: {} },
      _kyaos_approvals: [grant],
    };

    const result = await kyaos.wrapWithDelegation('vault', CONSENT, ran)(sent, sessionId) as Record<string, unknown>;

    expect(errorOf(result)).toBe('insufficient_scope');
    await expectVerifiesAsSent(kyaos, result, 'vault', sent, 'nothing');
  });
});

describe('proveOutcome proofs bind the call as sent', () => {
  it('a denial proved with the call\'s control arguments still in its args', async () => {
    const kyaos = await served(await createMiddleware());
    const sessionId = await handshake(kyaos);
    const sent = { report_id: 'r_1', _kyaos_delegation: 'vc', _kyaos_proof: { jws: 'x', meta: {} }, _kyaos_approvals: [grant] };

    const result = await kyaos.proveOutcome!({
      toolName: 'get_report',
      args: sent,
      outcome: 'denied',
      reason: 'insufficient_scope',
      result: { content: [{ type: 'text', text: 'no' }], isError: true },
      sessionId,
    }) as Record<string, unknown>;

    await expectVerifiesAsSent(kyaos, result, 'get_report', sent, 'nothing');
  });
});

describe('policy-gate outcome proofs bind the call as sent', () => {
  const stepUp = (approvalsArgKey?: string, approve = false) => ({
    resolveNamespace: () => 'prod',
    scopeMatched: true,
    isValidApprovalSignature: async () => approve,
    ...(approvalsArgKey === undefined ? {} : { approvalsArgKey }),
  });
  const requestHashIn = (result: Record<string, unknown>): string =>
    JSON.parse((result.content as Array<{ text: string }>)[0]!.text).requestHash as string;

  it('with a custom approvals key: the challenge and the re-challenge on resume both verify', async () => {
    const kyaos = await served(await createMiddleware());
    const sessionId = await handshake(kyaos);
    const handler = kyaos.withPolicyGate!('db.drop', ran, stepUp('approvals'));

    const first = await handler({ table: 'users' }, sessionId) as Record<string, unknown>;
    await expectVerifiesAsSent(kyaos, first, 'db.drop', { table: 'users' }, 'nothing');

    const resumed = { table: 'users', approvals: [grant] };
    const again = await handler(resumed, sessionId) as Record<string, unknown>;
    expect(errorOf(again)).toBe('needs_approval');
    await expectVerifiesAsSent(kyaos, again, 'db.drop', resumed, 'nothing');

    // The approval still binds the action without its grants, so a grant over the
    // first challenge still matches; the proof binds the call as sent, grants included.
    expect(requestHashIn(again)).toBe(requestHashIn(first));
    expect(proofOf(again)?.meta.requestHash).not.toBe(requestHashIn(again));
  });

  it('with the default approvals key: the re-challenge proof and the approval bind the same hash', async () => {
    const kyaos = await served(await createMiddleware());
    const sessionId = await handshake(kyaos);
    const handler = kyaos.withPolicyGate!('db.drop', ran, stepUp());

    const resumed = { table: 'users', _kyaos_approvals: [grant] };
    const again = await handler(resumed, sessionId) as Record<string, unknown>;

    await expectVerifiesAsSent(kyaos, again, 'db.drop', resumed, 'nothing');
    expect(proofOf(again)?.meta.requestHash).toBe(requestHashIn(again));
  });

  it('composed inside the delegation gate with a custom approvals key, the re-challenge verifies against the outer call', async () => {
    const kyaos = await served(await createMiddleware());
    const sessionId = await handshake(kyaos);
    const agent = await identity();
    const handler = kyaos.wrapWithDelegation('db.drop', CONSENT, kyaos.withPolicyGate!('db.drop', ran, stepUp('approvals')));
    const sent = { table: 'users', _kyaos_delegation: await delegation(agent.did), approvals: [grant] };

    const result = await handler(sent, sessionId) as Record<string, unknown>;

    expect(errorOf(result)).toBe('needs_approval');
    await expectVerifiesAsSent(kyaos, result, 'db.drop', sent, 'nothing');
  });

  /** A handler that records the arguments it ran with. */
  function recording(): { handler: KyaOsToolHandler; received: Array<Record<string, unknown>> } {
    const received: Array<Record<string, unknown>> = [];
    return { received, handler: async (args) => { received.push(args); return { content: [{ type: 'text', text: 'dropped' }] }; } };
  }

  it('with a custom key outside _kyaos: an approved resume runs with the key, and its proof verifies', async () => {
    const kyaos = await served(await createMiddleware());
    const sessionId = await handshake(kyaos);
    const { handler, received } = recording();
    const gate = kyaos.withPolicyGate!('db.drop', kyaos.wrapWithProof('db.drop', handler), stepUp('approvals', true));

    const challenge = await gate({ table: 'users' }, sessionId) as Record<string, unknown>;
    const resumed = { table: 'users', approvals: [{ ...grant, requestHash: requestHashIn(challenge) }] };
    const approved = await gate(resumed, sessionId) as Record<string, unknown>;

    expect(approved.isError).toBeUndefined();
    expect(received).toEqual([resumed]);
    await expectVerifiesAsSent(kyaos, approved, 'db.drop', resumed, 'content');
  });

  it('with a custom key outside _kyaos, composed inside the delegation gate: the approved resume verifies against the outer call', async () => {
    const kyaos = await served(await createMiddleware());
    const sessionId = await handshake(kyaos);
    const agent = await identity();
    const { handler, received } = recording();
    const gate = kyaos.wrapWithDelegation(
      'db.drop',
      CONSENT,
      kyaos.withPolicyGate!('db.drop', kyaos.wrapWithProof('db.drop', handler), stepUp('approvals', true)),
    );
    const vc = await delegation(agent.did);

    const challenge = await gate({ table: 'users', _kyaos_delegation: vc }, sessionId) as Record<string, unknown>;
    const sent = { table: 'users', _kyaos_delegation: vc, approvals: [{ ...grant, requestHash: requestHashIn(challenge) }] };
    const approved = await gate(sent, sessionId) as Record<string, unknown>;

    expect(approved.isError).toBeUndefined();
    expect(received).toEqual([{ table: 'users', approvals: sent.approvals }]);
    await expectVerifiesAsSent(kyaos, approved, 'db.drop', sent, 'content');
  });

  it('with a custom key, composed inside the delegation gate: grants sent under _kyaos_approvals are not bound as the custom key', async () => {
    const kyaos = await served(await createMiddleware());
    const sessionId = await handshake(kyaos);
    const agent = await identity();
    const { handler, received } = recording();
    const gate = kyaos.wrapWithDelegation(
      'db.drop',
      CONSENT,
      kyaos.withPolicyGate!('db.drop', kyaos.wrapWithProof('db.drop', handler), stepUp('approvals', true)),
    );
    const vc = await delegation(agent.did);

    const challenge = await gate({ table: 'users', _kyaos_delegation: vc }, sessionId) as Record<string, unknown>;
    const invalid = { table: 'users', _kyaos_delegation: vc, _kyaos_approvals: [grant] };
    const again = await gate(invalid, sessionId) as Record<string, unknown>;
    expect(errorOf(again)).toBe('needs_approval');
    await expectVerifiesAsSent(kyaos, again, 'db.drop', invalid, 'nothing');

    const sent = { table: 'users', _kyaos_delegation: vc, _kyaos_approvals: [{ ...grant, requestHash: requestHashIn(challenge) }] };
    const approved = await gate(sent, sessionId) as Record<string, unknown>;
    expect(approved.isError).toBeUndefined();
    expect(received).toEqual([{ table: 'users' }]);
    await expectVerifiesAsSent(kyaos, approved, 'db.drop', sent, 'content');
  });

  it('with the default key: an approved resume runs without the grants, and its proof verifies', async () => {
    const kyaos = await served(await createMiddleware());
    const sessionId = await handshake(kyaos);
    const { handler, received } = recording();
    const gate = kyaos.withPolicyGate!('db.drop', kyaos.wrapWithProof('db.drop', handler), stepUp(undefined, true));

    const challenge = await gate({ table: 'users' }, sessionId) as Record<string, unknown>;
    const resumed = { table: 'users', _kyaos_approvals: [{ ...grant, requestHash: requestHashIn(challenge) }] };
    const approved = await gate(resumed, sessionId) as Record<string, unknown>;

    expect(received).toEqual([{ table: 'users' }]);
    await expectVerifiesAsSent(kyaos, approved, 'db.drop', resumed, 'content');
  });

  it('warns once for each gate built with a custom approvals key, and never for the default key', async () => {
    const kyaos = await createMiddleware();
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    try {
      kyaos.withPolicyGate!('db.drop', ran, stepUp());
      expect(warn).not.toHaveBeenCalled();

      kyaos.withPolicyGate!('db.drop', ran, stepUp('approvals'));
      expect(warn).toHaveBeenCalledOnce();
      const message = String(warn.mock.calls[0]![0]);
      expect(message).toContain('"approvals"');
      expect(message).toMatch(/ordinary tool argument/);
      expect(message).toMatch(/wrapWithDelegation/);

      kyaos.withPolicyGate!('db.drop', ran, stepUp('_kyaos_grants'));
      expect(warn).toHaveBeenCalledTimes(2);
    } finally {
      warn.mockRestore();
    }
  });
});
