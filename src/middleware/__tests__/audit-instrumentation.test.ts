import { describe, expect, it, vi } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { generateDidKeyFromBase64 } from '../../utils/did-helpers.js';
import { MemoryAuditLogProvider } from '../../providers/audit-log.js';
import type { AuditTrailService } from '../../audit/service.js';
import { createKyaOsMiddleware } from '../with-kya-os.js';

async function setup(record: Pick<AuditTrailService, 'record'>['record']) {
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
    autoSession: true,
    audit: { record },
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

  it('prevents tool execution when required intent delivery throws', async () => {
    const handler = vi.fn(async () => ({ content: [{ type: 'text', text: 'ran' }] }));
    const middleware = await setup(async () => { throw new Error('audit unavailable'); });
    await expect(middleware.wrapWithProof('write', handler)({}))
      .rejects.toThrow('audit unavailable');
    expect(handler).not.toHaveBeenCalled();
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
});
