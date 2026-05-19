/**
 * Outbound Delegation Headers Tests
 *
 * Tests for buildOutboundDelegationHeaders utility.
 */

import { describe, it, expect, beforeAll } from 'vitest';
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
    sessionId: 'kya_test-session-123',
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

    expect(headers).toHaveProperty('KYA-Agent-DID');
    expect(headers).toHaveProperty('KYA-Delegation-Chain');
    expect(headers).toHaveProperty('KYA-Session-Id');
    expect(headers).toHaveProperty('KYA-Delegation-Proof');
  });

  it('KYA-Agent-DID matches session.agentDid', async () => {
    const context = createTestContext();
    const headers = await buildOutboundDelegationHeaders(context);

    expect(headers['KYA-Agent-DID']).toBe(context.session.agentDid);
  });

  it('KYA-Delegation-Chain matches delegation.vcId', async () => {
    const context = createTestContext();
    const headers = await buildOutboundDelegationHeaders(context);

    expect(headers['KYA-Delegation-Chain']).toBe(context.delegation.vcId);
  });

  it('KYA-Session-Id matches session.sessionId', async () => {
    const context = createTestContext();
    const headers = await buildOutboundDelegationHeaders(context);

    expect(headers['KYA-Session-Id']).toBe(context.session.sessionId);
  });

  it('KYA-Delegation-Proof is a valid JWT with correct claims', async () => {
    const context = createTestContext();
    const headers = await buildOutboundDelegationHeaders(context);

    const jwt = headers['KYA-Delegation-Proof'];

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

    const payload = decodeJwt(headers['KYA-Delegation-Proof']);
    expect(payload.aud).toBe('api.service.example.com');
  });

  it('works with http:// URLs', async () => {
    const context = createTestContext({
      targetUrl: 'http://internal-service.local/api',
    });
    const headers = await buildOutboundDelegationHeaders(context);

    const payload = decodeJwt(headers['KYA-Delegation-Proof']);
    expect(payload.aud).toBe('internal-service.local');
  });

  it('works with https:// URLs', async () => {
    const context = createTestContext({
      targetUrl: 'https://secure.example.org/endpoint',
    });
    const headers = await buildOutboundDelegationHeaders(context);

    const payload = decodeJwt(headers['KYA-Delegation-Proof']);
    expect(payload.aud).toBe('secure.example.org');
  });

  it('JWT exp is 60 seconds from iat', async () => {
    const context = createTestContext();
    const headers = await buildOutboundDelegationHeaders(context);

    const payload = decodeJwt(headers['KYA-Delegation-Proof']);
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
