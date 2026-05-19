/**
 * Integration Tests: server.ts — MCP Server with consent-based delegation
 *
 * Validates tool protection (needs_authorization flow), delegation
 * verification, proof generation, and argument stripping.
 *
 * Spec coverage: §4.3 (scope attenuation), §5.1 (DetachedProof),
 *                §5.2 (canonical hashing), §6.1 (needs_authorization),
 *                §6.2 (delegation verification)
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createKyaOsMiddleware, type KyaOsMiddleware } from '../../../src/middleware/index.js';
import { NodeCryptoProvider } from '../../../src/providers/node-crypto.js';
import { generateDidKeyFromBase64 } from '../../../src/utils/did-helpers.js';
import { createDelegationIssuerFromIdentity } from '../src/delegation-issuer.js';
import { createConsentFullMcpServer, type ToolResult } from '../src/server.js';
import type { DelegationCredential, NeedsAuthorizationError } from '../../../src/types/protocol.js';

const crypto = new NodeCryptoProvider();
const CONSENT_URL = 'http://localhost:9999/consent';

let kya: KyaOsMiddleware;
let browseHandler: (args: Record<string, unknown>, sessionId?: string) => Promise<ToolResult>;
let checkoutHandler: (args: Record<string, unknown>, sessionId?: string) => Promise<ToolResult>;
let serverDid: string;

async function issueTestDelegation(
  subjectDid: string,
  scopes: string[],
  notAfterOffset = 3600,
): Promise<DelegationCredential> {
  const factory = createDelegationIssuerFromIdentity(crypto, {
    did: kya.identity.did,
    kid: kya.identity.kid,
    privateKey: kya.identity.privateKey,
    publicKey: kya.identity.publicKey,
  });

  return factory.issuer.createAndIssueDelegation({
    id: `delegation-test-${Date.now()}`,
    issuerDid: kya.identity.did,
    subjectDid,
    constraints: {
      scopes,
      notAfter: Math.floor(Date.now() / 1000) + notAfterOffset,
    },
  });
}

describe('MCP Server with consent-full', () => {
  beforeAll(async () => {
    const keyPair = await crypto.generateKeyPair();
    const did = generateDidKeyFromBase64(keyPair.publicKey);
    const kid = `${did}#${did.replace('did:key:', '')}`;
    serverDid = did;

    kya = createKyaOsMiddleware(
      {
        identity: { did, kid, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey },
        session: { sessionTtlMinutes: 60 },
        autoSession: true,
      },
      crypto,
    );

    browseHandler = kya.wrapWithProof('browse', async (args) => ({
      content: [{
        type: 'text',
        text: `Browsing category: ${args['category'] ?? 'all'}. Found 3 items.`,
      }],
    })) as typeof browseHandler;

    checkoutHandler = kya.wrapWithDelegation(
      'checkout',
      { scopeId: 'cart:write', consentUrl: CONSENT_URL },
      kya.wrapWithProof('checkout', async (args) => ({
        content: [{
          type: 'text',
          text: `Order confirmed for item: ${args['item'] ?? 'unknown'}. Thank you!`,
        }],
      })),
    ) as typeof checkoutHandler;
  });

  // Public tool — no delegation needed
  it('should execute browse tool without delegation', async () => {
    const result = await browseHandler({ category: 'electronics' });

    expect(result.isError).toBeUndefined();
    expect(result.content[0]!.text).toContain('electronics');
  });

  it('should route _kya with action: "handshake" and return a valid session', async () => {
    const server = createConsentFullMcpServer(kya, { consentUrl: CONSENT_URL });
    const client = new Client({ name: 'consent-full-test-client', version: '1.0.0' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const result = await client.callTool({
      name: '_kya',
      arguments: {
        action: 'handshake',
        nonce: `consent-full-test-${Date.now()}`,
        audience: serverDid,
        timestamp: Math.floor(Date.now() / 1000),
      },
    });

    const parsed = JSON.parse(result.content[0]!.text) as {
      success: boolean;
      sessionId: string;
      serverDid: string;
    };
    expect(parsed.success).toBe(true);
    expect(parsed.sessionId).toMatch(/^kya_/);
    expect(parsed.serverDid).toBe(serverDid);

    await client.close();
    await server.close();
  });

  // §6.1 — needs_authorization
  it('should return needs_authorization for checkout without delegation', async () => {
    const result = await checkoutHandler({ item: 'widget' });

    const parsed = JSON.parse(result.content[0]!.text) as NeedsAuthorizationError;
    expect(parsed.error).toBe('needs_authorization');
    expect(parsed.authorizationUrl).toBe(CONSENT_URL);
    expect(parsed.scopes).toContain('cart:write');
    expect(parsed.resumeToken).toBeDefined();
    expect(typeof parsed.resumeToken).toBe('string');
    expect(parsed.resumeToken.length).toBeGreaterThan(0);
    expect(parsed.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  // §6.1 — resume token format (UUID-like: 8-4-4-4-12 hex chars)
  it('should include resumeToken in UUID-like format', async () => {
    const result = await checkoutHandler({ item: 'widget' });
    const parsed = JSON.parse(result.content[0]!.text) as NeedsAuthorizationError;

    expect(parsed.resumeToken).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  // §6.2 — Delegation verification (valid VC)
  it('should execute checkout with a valid delegation VC', async () => {
    const vc = await issueTestDelegation(serverDid, ['cart:write']);
    const result = await checkoutHandler({ item: 'widget', _kya_delegation: vc });

    expect(result.isError).toBeUndefined();
    expect(result.content[0]!.text).toContain('Order confirmed');
    expect(result.content[0]!.text).toContain('widget');
  });

  // §4.3 — Wrong scope
  it('should reject a delegation VC with wrong scope', async () => {
    const vc = await issueTestDelegation(serverDid, ['cart:read']);
    const result = await checkoutHandler({ item: 'widget', _kya_delegation: vc });

    expect(result.isError).toBe(true);
    const parsed = JSON.parse(result.content[0]!.text) as { error: string };
    expect(parsed.error).toBe('insufficient_scope');
  });

  // §4.2 — Expired delegation
  it('should reject an expired delegation VC', async () => {
    const expiredKya = createKyaOsMiddleware(
      {
        identity: kya.identity,
        session: { sessionTtlMinutes: 60 },
        autoSession: true,
      },
      crypto,
    );

    const expiredCheckout = expiredKya.wrapWithDelegation(
      'checkout',
      { scopeId: 'cart:write', consentUrl: CONSENT_URL },
      async (args) => ({
        content: [{ type: 'text', text: `Order: ${args['item']}` }],
      }),
    );

    const vc = await issueTestDelegation(serverDid, ['cart:write'], -3600);
    const result = await expiredCheckout({ item: 'widget', _kya_delegation: vc });

    expect(result.isError).toBe(true);
    const parsed = JSON.parse(result.content[0]!.text) as { error: string };
    expect(parsed.error).toBe('delegation_invalid');
  });

  // §5.1 — Detached proof on browse
  it('should attach a detached proof to browse tool response', async () => {
    const result = await browseHandler({ category: 'books' });

    expect(result._meta).toBeDefined();
    expect(result._meta!.proof).toBeDefined();

    const proof = result._meta!.proof!;
    // JWS: 3 dot-separated base64url parts
    expect(proof.jws).toBeDefined();
    expect(proof.jws.split('.').length).toBe(3);
    // Meta fields
    expect(proof.meta.did).toBeDefined();
    expect((proof.meta.did as string).startsWith('did:key:')).toBe(true);
    expect((proof.meta.requestHash as string).startsWith('sha256:')).toBe(true);
    expect((proof.meta.responseHash as string).startsWith('sha256:')).toBe(true);
  });

  // §5.2 — Deterministic hashing
  it('should produce deterministic hashes for identical requests', async () => {
    const result1 = await browseHandler({ category: 'books' });
    const result2 = await browseHandler({ category: 'books' });

    expect(result1._meta!.proof!.meta.requestHash).toBe(
      result2._meta!.proof!.meta.requestHash,
    );
  });

  // §4.3 — _kya_delegation stripping
  it('should not pass _kya_delegation to the tool handler', async () => {
    let capturedArgs: Record<string, unknown> | undefined;
    const testKya = createKyaOsMiddleware(
      {
        identity: kya.identity,
        session: { sessionTtlMinutes: 60 },
        autoSession: true,
      },
      crypto,
    );

    const handler = testKya.wrapWithDelegation(
      'checkout',
      { scopeId: 'cart:write', consentUrl: CONSENT_URL },
      async (args) => {
        capturedArgs = args;
        return { content: [{ type: 'text', text: 'ok' }] };
      },
    );

    const vc = await issueTestDelegation(serverDid, ['cart:write']);
    await handler({ item: 'widget', _kya_delegation: vc });

    expect(capturedArgs).toBeDefined();
    expect(capturedArgs!['item']).toBe('widget');
    expect(capturedArgs!['_kya_delegation']).toBeUndefined();
  });
});
