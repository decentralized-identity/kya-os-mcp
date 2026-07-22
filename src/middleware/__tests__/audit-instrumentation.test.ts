import { describe, expect, it, vi } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { generateDidKeyFromBase64 } from '../../utils/did-helpers.js';
import { MemoryAuditLogProvider } from '../../providers/audit-log.js';
import type { AuditTrailService } from '../../audit/service.js';
import { createKyaOsMiddleware } from '../with-kya-os.js';
import { KYA_OS_PROOF_META_KEY, LEGACY_PROOF_META_KEY } from '../../proof/index.js';

type AuditEventInput = Parameters<AuditTrailService['record']>[0];

async function setup(
  record: Pick<AuditTrailService, 'record'>['record'],
  options: { includeToolNames?: boolean; autoSession?: boolean } = {},
) {
  const crypto = new NodeCryptoProvider();
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  const middleware = createKyaOsMiddleware({
    identity: {
      did,
      kid: `${did}#${did.replace('did:key:', '')}`,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
    },
    autoSession: options.autoSession ?? true,
    audit: {
      record,
      ...(options.includeToolNames === undefined
        ? {}
        : { includeToolNames: options.includeToolNames }),
    },
  }, crypto);
  return middleware;
}

describe('MCP audit instrumentation', () => {
  it('emits intent, proof, and terminal events for each successful call', async () => {
    const events: Array<{ eventType: string }> = [];
    const record: Pick<AuditTrailService, 'record'>['record'] = vi.fn(async (event) => {
      events.push(event);
      return { status: 'pending', event: event as never };
    });
    const middleware = await setup(record);
    const handler = middleware.wrapWithProof('secret.tool.name', async () => ({
      content: [{ type: 'text', text: 'ok' }],
    }));

    await handler({ secret: 'never-audit-raw-args' });
    expect(events.map((event) => event.eventType)).toEqual([
      'tool.call.started',
      'proof.generated',
      'tool.call.completed',
    ]);
    expect(JSON.stringify(events)).not.toContain('secret.tool.name');
    expect(JSON.stringify(events)).not.toContain('never-audit-raw-args');
  });

  it('records bounded tool names only when the operator explicitly opts in', async () => {
    const events: AuditEventInput[] = [];
    const middleware = await setup(async (event) => {
      events.push(event);
      return { status: 'pending', event: event as never };
    }, { includeToolNames: true });
    const handler = middleware.wrapWithProof('orders.create', async () => ({
      content: [{ type: 'text', text: 'ok' }],
    }));

    await handler({});

    expect(events[0]?.action).toEqual({ category: 'tool.call', name: 'orders.create' });
  });

  it('records thrown and error-result terminal paths', async () => {
    const events: Array<{ eventType: string }> = [];
    const record: Pick<AuditTrailService, 'record'>['record'] = async (event) => {
      events.push(event);
      return { status: 'pending', event: event as never };
    };
    const middleware = await setup(record);
    await expect(middleware.wrapWithProof('throws', async () => {
      throw new Error('boom');
    })({})).rejects.toThrow('boom');
    await middleware.wrapWithProof('error-result', async () => ({
      content: [{ type: 'text', text: 'failed' }], isError: true,
    }))({});
    expect(events.map((event) => event.eventType)).toEqual([
      'tool.call.started', 'tool.call.failed',
      'tool.call.started', 'tool.call.failed',
    ]);
  });

  it('returns a structured failure and prevents execution when required intent delivery throws', async () => {
    const handler = vi.fn(async () => ({ content: [{ type: 'text', text: 'ran' }] }));
    const middleware = await setup(async () => { throw new Error('audit unavailable'); });
    const result = await middleware.wrapWithProof('write', handler)({});
    expect(result).toMatchObject({
      isError: true,
      _meta: { 'org.kya-os/audit': { status: 'degraded' } },
    });
    expect(JSON.parse(result.content[0]!.text)).toMatchObject({
      error: { code: 'audit_delivery_failed' },
    });
    expect(handler).not.toHaveBeenCalled();
  });

  it('preserves the handler exception when recording its failure also throws', async () => {
    const middleware = await setup(async (event) => {
      if (event.eventType === 'tool.call.failed') throw new Error('audit unavailable');
      return { status: 'pending', event: event as never };
    });
    const handler = middleware.wrapWithProof('write', async () => {
      throw new Error('original handler failure');
    });

    await expect(handler({})).rejects.toThrow('original handler failure');
  });

  it('preserves an error result and marks it degraded when its terminal audit fails', async () => {
    const middleware = await setup(async (event) => {
      if (event.eventType === 'tool.call.failed') throw new Error('audit unavailable');
      return { status: 'pending', event: event as never };
    });
    const handler = middleware.wrapWithProof('write', async () => ({
      content: [{ type: 'text', text: 'domain failure' }], isError: true,
    }));

    const result = await handler({});

    expect(result.content[0]?.text).toBe('domain failure');
    expect(result).toMatchObject({
      isError: true,
      _meta: { 'org.kya-os/audit': { status: 'degraded' } },
    });
  });

  it('never lets rejected-handshake audit failure displace the handshake denial', async () => {
    const middleware = await setup(async () => { throw new Error('audit unavailable'); });
    const result = await middleware.handleHandshake({ nonce: 123 });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0]!.text)).toMatchObject({
      success: false,
      error: { code: 'handshake_failed' },
    });
  });

  it('rejects simultaneous legacy and verifiable audit configuration', async () => {
    const crypto = new NodeCryptoProvider();
    const keyPair = await crypto.generateKeyPair();
    const did = generateDidKeyFromBase64(keyPair.publicKey);
    expect(() => createKyaOsMiddleware({
      identity: {
        did, kid: `${did}#key`, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey,
      },
      audit: { record: async (event) => ({ status: 'pending', event: event as never }) },
      auditLog: new MemoryAuditLogProvider(),
    }, crypto)).toThrow(/either audit or legacy auditLog/i);
  });

  it('records rejected handshakes and step-up outcomes as typed negative-path events', async () => {
    const events: Array<{ eventType: string }> = [];
    const middleware = await setup(async (event) => {
      events.push(event);
      return { status: 'pending', event: event as never };
    });
    await middleware.handleKyaOs({ action: 'handshake', nonce: 123 });
    const handler = middleware.withPolicyGate!(
      'db.drop',
      async () => ({ content: [{ type: 'text', text: 'must-not-run' }] }),
      { resolveNamespace: () => 'prod', scopeMatched: true },
    );
    const result = await handler({ table: 'users' });
    expect(result.isError).toBe(true);
    expect(events.map((event) => event.eventType)).toEqual([
      'session.rejected',
      'authorization.evaluated',
      'authorization.step_up_required',
      'tool.call.challenged',
      'proof.generated',
    ]);
  });

  it('records needs-authorization challenges without executing the protected handler', async () => {
    const events: Array<{ eventType: string }> = [];
    const middleware = await setup(async (event) => {
      events.push(event);
      return { status: 'pending', event: event as never };
    });
    const protectedHandler = vi.fn(async () => ({ content: [{ type: 'text', text: 'ran' }] }));
    const handler = middleware.wrapWithDelegation(
      'payments.create',
      { scopeId: 'payments:write', consentUrl: 'https://consent.example/authorize' },
      protectedHandler,
    );
    const result = await handler({ amount: 10 });
    expect(result.isError).toBeUndefined();
    expect(protectedHandler).not.toHaveBeenCalled();
    expect(events.map((event) => event.eventType)).toEqual([
      'authorization.step_up_required',
      'tool.call.challenged',
      'proof.generated',
    ]);
  });

  it('distinguishes nonce replay rejection from an ordinary handshake rejection', async () => {
    const events: Array<{ eventType: string }> = [];
    const middleware = await setup(async (event) => {
      events.push(event);
      return { status: 'pending', event: event as never };
    });
    const request = {
      action: 'handshake', nonce: 'A'.repeat(22), audience: middleware.identity.did,
      timestamp: Math.floor(Date.now() / 1000),
    };
    await middleware.handleKyaOs(request);
    await middleware.handleKyaOs(request);
    expect(events.map((event) => event.eventType)).toEqual([
      'session.established', 'session.replay_rejected',
    ]);
  });

  it('threads complete call attribution into proof and tool audit events', async () => {
    const events: AuditEventInput[] = [];
    const middleware = await setup(async (event) => {
      events.push(event);
      return { status: 'pending', event: event as never };
    });
    const context = {
      actor: { kind: 'public_did' as const, did: 'did:example:actor' },
      responsibleParty: { kind: 'public_did' as const, did: 'did:example:owner' },
      authorization: { source: 'policy' as const, decision: 'allowed' as const },
      correlationId: 'correlation-1',
      causationId: 'causation-1',
    };
    const handler = middleware.wrapWithProof('read', async () => ({
      content: [{ type: 'text', text: 'ok' }],
    }));

    await handler({}, undefined, context);

    expect(events[0]).toMatchObject(context);
    expect(events.find((event) => event.eventType === 'proof.generated'))
      .toMatchObject(context);
  });

  it('audits an explicit unknown session without misattributing a proof', async () => {
    const events: AuditEventInput[] = [];
    const middleware = await setup(async (event) => {
      events.push(event);
      return { status: 'pending', event: event as never };
    });
    const handler = middleware.wrapWithProof('read', async () => ({
      content: [{ type: 'text', text: 'ok' }],
    }));

    const result = await handler({}, 'kyaos_missing');

    expect(result._meta).toBeUndefined();
    expect(events.map((event) => event.eventType)).toEqual([
      'tool.call.started', 'proof.rejected', 'tool.call.completed',
    ]);
    expect(events[1]).toMatchObject({
      details: { verificationCode: 'PROOF_SESSION_NOT_FOUND' },
    });
  });

  it('returns an unproven result when automatic session establishment fails', async () => {
    const events: AuditEventInput[] = [];
    const middleware = await setup(async (event) => {
      events.push(event);
      return { status: 'pending', event: event as never };
    });
    vi.spyOn(middleware.sessionManager, 'validateHandshake').mockResolvedValueOnce({
      success: false,
      error: { code: 'handshake_failed', message: 'session unavailable' },
    });
    const handler = middleware.wrapWithProof('read', async () => ({
      content: [{ type: 'text', text: 'ok' }],
    }));

    const result = await handler({});

    expect(result._meta).toBeUndefined();
    expect(events[1]).toMatchObject({
      eventType: 'proof.rejected',
      details: { verificationCode: 'PROOF_SESSION_UNAVAILABLE' },
    });
  });

  it('degrades a completed response when proof-session rejection cannot be audited', async () => {
    const middleware = await setup(async (event) => {
      if (event.eventType === 'proof.rejected') throw new Error('audit unavailable');
      return { status: 'pending', event: event as never };
    }, { autoSession: false });
    const handler = middleware.wrapWithProof('read', async () => ({
      content: [{ type: 'text', text: 'ok' }],
    }));

    const result = await handler({});

    expect(result).toMatchObject({
      isError: true,
      _meta: { 'org.kya-os/audit': { status: 'degraded' } },
    });
  });

  it('degrades a completed response when a missing explicit session cannot be audited', async () => {
    const middleware = await setup(async (event) => {
      if (event.eventType === 'proof.rejected') throw new Error('audit unavailable');
      return { status: 'pending', event: event as never };
    });
    const result = await middleware.wrapWithProof('read', async () => ({
      content: [{ type: 'text', text: 'ok' }],
    }))({}, 'kyaos_missing');

    expect(result).toMatchObject({
      isError: true,
      _meta: { 'org.kya-os/audit': { status: 'degraded' } },
    });
  });

  it('marks a completed response degraded when required terminal audit delivery fails', async () => {
    const middleware = await setup(async (event) => {
      if (event.eventType === 'proof.generated') throw 'required recorder unavailable';
      return { status: 'pending', event: event as never };
    });
    const handler = middleware.wrapWithProof('write', async () => ({
      content: [{ type: 'text', text: 'completed' }],
    }));

    const result = await handler({});

    expect(result.isError).toBe(true);
    expect(result._meta).toMatchObject({
      'org.kya-os/audit': {
        status: 'degraded',
        reason: 'Required terminal audit delivery failed after tool completion',
      },
    });
    expect(result._meta?.[KYA_OS_PROOF_META_KEY]).toBeUndefined();
    expect(result._meta?.[LEGACY_PROOF_META_KEY]).toBeUndefined();
  });

  it('audits proof-generation failures while preserving the tool response', async () => {
    const events: AuditEventInput[] = [];
    const middleware = await setup(async (event) => {
      events.push(event);
      return { status: 'pending', event: event as never };
    });
    vi.spyOn(middleware.proofGenerator, 'generateProof')
      .mockRejectedValueOnce('signer unavailable');
    const handler = middleware.wrapWithProof('read', async () => ({
      content: [{ type: 'text', text: 'ok' }],
    }));

    const result = await handler({});

    expect(result.isError).toBeUndefined();
    expect(result._meta).toEqual({
      proofError: 'Proof generation failed — response is unproven',
    });
    expect(events.at(-1)).toMatchObject({
      eventType: 'proof.rejected',
      details: { verificationCode: 'PROOF_GENERATION_FAILED' },
    });
  });

  it('degrades when both proof generation and its required failure audit fail', async () => {
    const middleware = await setup(async (event) => {
      if (event.eventType === 'proof.rejected') throw new Error('audit unavailable');
      return { status: 'pending', event: event as never };
    });
    vi.spyOn(middleware.proofGenerator, 'generateProof')
      .mockRejectedValueOnce(new Error('signer unavailable'));

    const result = await middleware.wrapWithProof('read', async () => ({
      content: [{ type: 'text', text: 'ok' }],
    }))({});

    expect(result).toMatchObject({
      isError: true,
      _meta: { 'org.kya-os/audit': { status: 'degraded' } },
    });
  });

  it('audits allow decisions with the complete authorization context', async () => {
    const events: AuditEventInput[] = [];
    const middleware = await setup(async (event) => {
      events.push(event);
      return { status: 'pending', event: event as never };
    });
    const context = {
      actor: { kind: 'public_did' as const, did: 'did:example:actor' },
      responsibleParty: { kind: 'public_did' as const, did: 'did:example:owner' },
      authorization: { source: 'delegation' as const, decision: 'allowed' as const },
    };
    const handler = middleware.withPolicyGate!(
      'repo.read',
      async (args) => ({ content: [{ type: 'text', text: JSON.stringify(args) }] }),
      { scopeMatched: true },
    );

    const result = await handler({
      _kyaos_delegation: {
        credentialSubject: {
          id: 'did:example:actor',
          delegation: {
            subjectDid: 'did:example:actor',
            controller: 'did:example:owner',
          },
        },
      },
    }, undefined, context);

    expect(result.isError).toBeUndefined();
    expect(events.filter((event) => event.eventType.startsWith('authorization.')))
      .toEqual([
        expect.objectContaining({ eventType: 'authorization.evaluated', ...context }),
        expect.objectContaining({ eventType: 'authorization.approved', ...context }),
      ]);
  });

  it('omits unavailable optional attribution from policy audit events', async () => {
    const events: AuditEventInput[] = [];
    const middleware = await setup(async (event) => {
      events.push(event);
      return { status: 'pending', event: event as never };
    });
    const handler = middleware.withPolicyGate!(
      'repo.read',
      async () => ({ content: [{ type: 'text', text: 'ok' }] }),
      { scopeMatched: true },
    );

    await handler({}, undefined, {});

    const evaluated = events.find(
      (event) => event.eventType === 'authorization.evaluated',
    );
    expect(evaluated).not.toHaveProperty('responsibleParty');
    expect(evaluated).not.toHaveProperty('authorization');
  });

  it('audits policy denials and outcome-proof failures', async () => {
    const events: AuditEventInput[] = [];
    const middleware = await setup(async (event) => {
      events.push(event);
      return { status: 'pending', event: event as never };
    });
    vi.spyOn(middleware.proofGenerator, 'generateProof')
      .mockRejectedValueOnce('outcome signer unavailable');
    const handler = middleware.withPolicyGate!(
      'frobnicate',
      async () => ({ content: [{ type: 'text', text: 'must-not-run' }] }),
      { scopeMatched: true },
    );

    const result = await handler({});

    expect(result.isError).toBe(true);
    expect(events.map((event) => event.eventType)).toEqual([
      'authorization.evaluated',
      'authorization.denied',
      'tool.call.denied',
      'proof.rejected',
    ]);
  });

  it('audits the approval that satisfies a step-up quorum', async () => {
    const events: AuditEventInput[] = [];
    const middleware = await setup(async (event) => {
      events.push(event);
      return { status: 'pending', event: event as never };
    });
    const handler = middleware.withPolicyGate!(
      'db.drop',
      async () => ({ content: [{ type: 'text', text: 'ran' }] }),
      {
        resolveNamespace: () => 'prod',
        scopeMatched: true,
        isValidApprovalSignature: async () => true,
      },
    );
    const challenge = await handler({ table: 'users' });
    const { requestHash } = JSON.parse(challenge.content[0]!.text) as {
      requestHash: string;
    };

    const result = await handler({
      table: 'users',
      _kyaos_approvals: [{
        approvalRequestId: 'approval-1',
        approverDid: 'did:example:approver',
        requestHash,
        decision: 'approve',
        ts: 1,
        signature: 'signature',
      }],
    });

    expect(result.isError).toBeUndefined();
    expect(events.some((event) => event.eventType === 'authorization.approved'))
      .toBe(true);
  });

  it('marks a denial terminal when its explicit session is absent', async () => {
    const events: AuditEventInput[] = [];
    const middleware = await setup(async (event) => {
      events.push(event);
      return { status: 'pending', event: event as never };
    });
    const handler = middleware.withPolicyGate!(
      'frobnicate',
      async () => ({ content: [{ type: 'text', text: 'must-not-run' }] }),
      { scopeMatched: true },
    );

    const result = await handler({}, 'kyaos_missing');

    expect(result.isError).toBe(true);
    expect(result._meta).toMatchObject({
      'org.kya-os/audit': { terminal: true, outcome: 'denied' },
    });
    expect(events.map((event) => event.eventType)).toEqual([
      'authorization.evaluated', 'authorization.denied', 'tool.call.denied',
    ]);

    const copied = structuredClone(result);
    await middleware.wrapWithProof('frobnicate', async () => copied)({}, 'kyaos_missing');
    expect(events.map((event) => event.eventType)).toEqual([
      'authorization.evaluated', 'authorization.denied', 'tool.call.denied',
      'tool.call.started',
    ]);
  });

  it('bounds malformed delegation references and never lets audit failure escape denial', async () => {
    const events: AuditEventInput[] = [];
    const middleware = await setup(async (event) => {
      events.push(event);
      if (event.eventType === 'delegation.rejected') throw new Error('audit unavailable');
      return { status: 'pending', event: event as never };
    });
    const protectedHandler = vi.fn(async () => ({ content: [{ type: 'text', text: 'ran' }] }));
    const handler = middleware.wrapWithDelegation(
      'payments.create',
      { scopeId: 'payments:write', consentUrl: 'https://consent.example/authorize' },
      protectedHandler,
    );

    const result = await handler({ _kyaos_delegation: { id: 123, bogus: true } });

    expect(result.isError).toBe(true);
    expect(protectedHandler).not.toHaveBeenCalled();
    expect(events[0]).toMatchObject({
      eventType: 'delegation.rejected',
      details: { family: 'delegation', delegationRef: 'unknown' },
    });
  });

  it('extracts only bounded string references from malformed delegations', async () => {
    const references: string[] = [];
    const middleware = await setup(async (event) => {
      if (event.eventType === 'delegation.rejected') {
        references.push(event.details.delegationRef as string);
      }
      return { status: 'pending', event: event as never };
    });
    const protectedHandler = vi.fn(async () => ({ content: [{ type: 'text', text: 'ran' }] }));
    const handler = middleware.wrapWithDelegation(
      'payments.create',
      { scopeId: 'payments:write', consentUrl: 'https://consent.example/authorize' },
      protectedHandler,
    );
    const hostile = {};
    Object.defineProperty(hostile, 'id', {
      get: () => { throw new Error('hostile getter'); },
    });

    await handler({ _kyaos_delegation: { id: 'd'.repeat(300), bogus: true } });
    await handler({
      _kyaos_delegation: {
        credentialSubject: { delegation: { id: 'nested-delegation' } },
        bogus: true,
      },
    });
    await handler({
      _kyaos_delegation: {
        credentialSubject: { delegation: { id: 123 } },
        bogus: true,
      },
    });
    await handler({ _kyaos_delegation: hostile });

    expect(protectedHandler).not.toHaveBeenCalled();
    expect(references).toEqual([
      'd'.repeat(256),
      'nested-delegation',
      'unknown',
      'unknown',
    ]);
  });

  it('returns a denial marked degraded when required authorization audit delivery fails', async () => {
    const middleware = await setup(async (event) => {
      if (event.eventType === 'authorization.denied') throw new Error('audit unavailable');
      return { status: 'pending', event: event as never };
    });
    const handler = middleware.withPolicyGate!(
      'frobnicate',
      async () => ({ content: [{ type: 'text', text: 'must-not-run' }] }),
      { scopeMatched: true },
    );

    const result = await handler({});

    expect(result).toMatchObject({
      isError: true,
      _meta: {
        'org.kya-os/audit': { terminal: true, status: 'degraded', outcome: 'denied' },
      },
    });
  });

  it('retains a denial proof but marks it degraded when proof audit delivery fails', async () => {
    const middleware = await setup(async (event) => {
      if (event.eventType === 'proof.generated') throw new Error('audit unavailable');
      return { status: 'pending', event: event as never };
    });
    const handler = middleware.withPolicyGate!(
      'frobnicate',
      async () => ({ content: [{ type: 'text', text: 'must-not-run' }] }),
      { scopeMatched: true },
    );

    const result = await handler({});

    expect(result._meta?.[KYA_OS_PROOF_META_KEY]).toBeDefined();
    expect(result).toMatchObject({
      isError: true,
      _meta: { 'org.kya-os/audit': { terminal: true, status: 'degraded' } },
    });
  });
});
