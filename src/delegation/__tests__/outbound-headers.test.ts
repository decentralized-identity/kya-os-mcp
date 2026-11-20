/**
 * Outbound Delegation Headers Tests
 *
 * Tests for buildOutboundDelegationHeaders utility.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import {
  buildOutboundDelegationHeaders,
  type OutboundDelegationContext,
} from '../outbound-headers.js';
import type { SessionContext, DelegationRecord } from '../../types/protocol.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { generateDidKeyFromBase64 } from '../../utils/did-helpers.js';

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

let serverKeyPair: { privateKey: string; publicKey: string };
let serverDid: string;
let serverKid: string;
let agentDid: string;

beforeAll(async () => {
  const cryptoProvider = new NodeCryptoProvider();

  serverKeyPair = await cryptoProvider.generateKeyPair();
  serverDid = generateDidKeyFromBase64(serverKeyPair.publicKey);
  serverKid = `${serverDid}#${serverDid.replace('did:key:', '')}`;

  const agentKeyPair = await cryptoProvider.generateKeyPair();
  agentDid = generateDidKeyFromBase64(agentKeyPair.publicKey);
});

function createTestSession(overrides: Partial<SessionContext> = {}): SessionContext {
  return {
    sessionId: 'kyaos_test-session-123',
    audience: 'did:web:my-mcp-server.example.com',
    nonce: 'test-nonce-abc',
    timestamp: Math.floor(Date.now() / 1000),
    createdAt: Date.now(),
    lastActivity: Date.now(),
    ttlMinutes: 30,
    identityState: 'authenticated',
    agentDid,
    ...overrides,
  };
}

function createTestDelegation(overrides: Partial<DelegationRecord> = {}): DelegationRecord {
  return {
    id: 'del-test-123',
    issuerDid: serverDid,
    subjectDid: agentDid,
    vcId: 'urn:uuid:vc-test-456',
    constraints: {
      scopes: ['tool:execute', 'resource:read'],
    },
    signature: 'test-signature',
    status: 'active',
    createdAt: Date.now(),
    ...overrides,
  };
}

function createTestContext(
  overrides: Partial<OutboundDelegationContext> = {}
): OutboundDelegationContext {
  return {
    session: createTestSession(),
    delegation: createTestDelegation(),
    serverIdentity: {
      did: serverDid,
      kid: serverKid,
      privateKey: serverKeyPair.privateKey,
    },
    targetUrl: 'https://downstream-api.example.com/resource',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('buildOutboundDelegationHeaders', () => {
  it('builds correct headers from a valid session + delegation', async () => {
    const context = createTestContext();
    const headers = await buildOutboundDelegationHeaders(context);

    expect(headers).toHaveProperty('KYA-OS-Agent-DID');
    expect(headers).toHaveProperty('KYA-OS-Delegation-Chain');
    expect(headers).toHaveProperty('KYA-OS-Session-Id');
    expect(headers).toHaveProperty('KYA-OS-Delegation-Proof');
  });

  it('KYA-OS-Agent-DID matches session.agentDid', async () => {
    const context = createTestContext();
    const headers = await buildOutboundDelegationHeaders(context);

    expect(headers['KYA-OS-Agent-DID']).toBe(context.session.agentDid);
  });

  it('KYA-OS-Delegation-Chain matches delegation.vcId', async () => {
    const context = createTestContext();
    const headers = await buildOutboundDelegationHeaders(context);

    expect(headers['KYA-OS-Delegation-Chain']).toBe(context.delegation.vcId);
  });

  it('KYA-OS-Session-Id is the anchor of the session for the target host, never the session id', async () => {
    const context = createTestContext();
    const headers = await buildOutboundDelegationHeaders(context);

    // SHA-256(UTF8(domain) || 0x00 || JCS([sessionId, target host])), written as `sha256:<hex>`.
    const input = `org.kya-os.outbound.session-anchor.v1\0${JSON.stringify([context.session.sessionId, 'downstream-api.example.com'])}`;
    const anchor = `sha256:${createHash('sha256').update(input, 'utf8').digest('hex')}`;
    expect(headers['KYA-OS-Session-Id']).toBe(anchor);
    expect(headers['KYA-OS-Session-Id']).not.toContain(context.session.sessionId);
  });

  it('KYA-OS-Session-Id is one anchor for one session at one host, and another for another of either', async () => {
    const anchorOf = async (sessionId: string, targetUrl: string) =>
      (await buildOutboundDelegationHeaders(createTestContext({ session: createTestSession({ sessionId }), targetUrl })))['KYA-OS-Session-Id'];
    const here = await anchorOf('kyaos_one', 'https://downstream-api.example.com/a');

    expect(await anchorOf('kyaos_one', 'https://downstream-api.example.com/b?c=d')).toBe(here);
    expect(await anchorOf('kyaos_one', 'https://other-api.example.com/a')).not.toBe(here);
    expect(await anchorOf('kyaos_two', 'https://downstream-api.example.com/a')).not.toBe(here);
  });

  it('KYA-OS-Delegation-Proof is a valid JWT with correct claims', async () => {
    const context = createTestContext();
    const headers = await buildOutboundDelegationHeaders(context);

    const jwt = headers['KYA-OS-Delegation-Proof'];

    // Verify it's a valid JWT format (3 parts)
    expect(jwt.split('.')).toHaveLength(3);

    // Verify header
    const header = decodeProtectedHeader(jwt);
    expect(header.alg).toBe('EdDSA');
    expect(header.kid).toBe(serverKid);

    // Verify payload claims
    const payload = decodeJwt(jwt);
    expect(payload.iss).toBe(serverDid);           // server forwarding
    expect(payload.sub).toBe(agentDid);            // original agent
    expect(payload.aud).toBe('downstream-api.example.com');  // target hostname
    expect(payload.scope).toBe('delegation:propagate');
    expect(typeof payload.iat).toBe('number');
    expect(typeof payload.exp).toBe('number');
    expect(typeof payload.jti).toBe('string');
  });

  it('extracts hostname correctly from full URL for aud claim', async () => {
    const context = createTestContext({
      targetUrl: 'https://api.service.example.com:8443/v1/resource?query=test',
    });
    const headers = await buildOutboundDelegationHeaders(context);

    const payload = decodeJwt(headers['KYA-OS-Delegation-Proof']);
    expect(payload.aud).toBe('api.service.example.com');
  });

  it('reads a target given as host:port, with no scheme, as that host', async () => {
    const built = async (targetUrl: string) => {
      const headers = await buildOutboundDelegationHeaders(createTestContext({ targetUrl }));
      return { aud: decodeJwt(headers['KYA-OS-Delegation-Proof']).aud, anchor: headers['KYA-OS-Session-Id'] };
    };
    const full = await built('https://api.service.example.com:8443/v1/resource');
    const bare = await built('api.service.example.com:8443');

    // `new URL('host:8443')` parses, with `host:` as its scheme and no hostname at all.
    expect(bare.aud).toBe('api.service.example.com');
    expect(bare.anchor).toBe(full.anchor);
    expect((await built('other.example.com:8443')).anchor).not.toBe(bare.anchor);
    expect((await built('api.service.example.com')).aud).toBe('api.service.example.com');
    expect((await built('api.service.example.com/v1/resource')).aud).toBe('api.service.example.com');
  });

  it('works with http:// URLs', async () => {
    const context = createTestContext({
      targetUrl: 'http://internal-service.local/api',
    });
    const headers = await buildOutboundDelegationHeaders(context);

    const payload = decodeJwt(headers['KYA-OS-Delegation-Proof']);
    expect(payload.aud).toBe('internal-service.local');
  });

  it('works with https:// URLs', async () => {
    const context = createTestContext({
      targetUrl: 'https://secure.example.org/endpoint',
    });
    const headers = await buildOutboundDelegationHeaders(context);

    const payload = decodeJwt(headers['KYA-OS-Delegation-Proof']);
    expect(payload.aud).toBe('secure.example.org');
  });

  it('JWT exp is 60 seconds from iat', async () => {
    const context = createTestContext();
    const headers = await buildOutboundDelegationHeaders(context);

    const payload = decodeJwt(headers['KYA-OS-Delegation-Proof']);
    expect((payload.exp as number) - (payload.iat as number)).toBe(60);
  });

  it('throws when session is missing agentDid', async () => {
    const context = createTestContext({
      session: createTestSession({ agentDid: undefined }),
    });

    await expect(
      buildOutboundDelegationHeaders(context)
    ).rejects.toThrow('Session must have agentDid');
  });

  it('throws when session is missing sessionId', async () => {
    const context = createTestContext({
      session: createTestSession({ sessionId: '' }),
    });

    await expect(
      buildOutboundDelegationHeaders(context)
    ).rejects.toThrow('Session must have sessionId');
  });

  it('throws when delegation is missing vcId', async () => {
    const context = createTestContext({
      delegation: createTestDelegation({ vcId: '' }),
    });

    await expect(
      buildOutboundDelegationHeaders(context)
    ).rejects.toThrow('Delegation must have vcId');
  });

  it('throws for a delegation record that is not active', async () => {
    for (const [status, named] of [['revoked', '"revoked"'], ['expired', '"expired"'], [undefined, 'of type undefined']] as const) {
      const context = createTestContext({ delegation: createTestDelegation({ status: status as DelegationRecord['status'] }) });
      await expect(buildOutboundDelegationHeaders(context), String(status)).rejects.toThrow(
        `Delegation must be active for outbound delegation (its status is ${named})`,
      );
    }
  });

  it('throws for a delegation record past its notAfter, or whose notAfter is no number', async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    for (const notAfter of [nowSec - 60, Number.NaN, '4102444800' as unknown as number]) {
      const context = createTestContext({ delegation: createTestDelegation({ constraints: { scopes: ['tool:execute'], notAfter } }) });
      await expect(buildOutboundDelegationHeaders(context), String(notAfter)).rejects.toThrow(
        'Delegation must not be past its notAfter for outbound delegation',
      );
    }
    const inForce = createTestContext({ delegation: createTestDelegation({ constraints: { scopes: ['tool:execute'], notAfter: nowSec + 60 } }) });
    await expect(buildOutboundDelegationHeaders(inForce)).resolves.toHaveProperty('KYA-OS-Delegation-Proof');
  });

  it('throws for a delegation record before its notBefore, or whose notBefore is no number', async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    for (const notBefore of [nowSec + 60, Number.POSITIVE_INFINITY, null as unknown as number]) {
      const context = createTestContext({ delegation: createTestDelegation({ constraints: { scopes: ['tool:execute'], notBefore } }) });
      await expect(buildOutboundDelegationHeaders(context), String(notBefore)).rejects.toThrow(
        'Delegation must not be before its notBefore for outbound delegation',
      );
    }
    const begun = createTestContext({ delegation: createTestDelegation({ constraints: { scopes: ['tool:execute'], notBefore: nowSec - 60 } }) });
    await expect(buildOutboundDelegationHeaders(begun)).resolves.toHaveProperty('KYA-OS-Delegation-Proof');
  });

  it('throws for a delegation record whose audience does not admit the forwarding server', async () => {
    for (const audience of ['did:web:another-server.example.com', ['did:web:another-server.example.com'], 7 as unknown as string]) {
      const context = createTestContext({ delegation: createTestDelegation({ constraints: { scopes: ['tool:execute'], audience } }) });
      await expect(buildOutboundDelegationHeaders(context), JSON.stringify(audience)).rejects.toThrow(
        'Delegation audience must admit the forwarding server for outbound delegation',
      );
    }
    for (const audience of [serverDid, ['did:web:another-server.example.com', serverDid]]) {
      const context = createTestContext({ delegation: createTestDelegation({ constraints: { scopes: ['tool:execute'], audience } }) });
      await expect(buildOutboundDelegationHeaders(context)).resolves.toHaveProperty('KYA-OS-Delegation-Proof');
    }
  });

  it('throws for non-did:key server DID', async () => {
    const context = createTestContext({
      serverIdentity: {
        did: 'did:web:server.example.com',
        kid: 'did:web:server.example.com#key-1',
        privateKey: serverKeyPair.privateKey,
      },
    });

    await expect(
      buildOutboundDelegationHeaders(context)
    ).rejects.toThrow('Server DID must be did:key with Ed25519');
  });
});
