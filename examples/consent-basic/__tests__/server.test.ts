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
import { createKyaOsMiddleware, NodeCryptoProvider, generateDidKeyFromBase64, KYA_OS_PROOF_META_KEY, type KyaOsMiddleware, type DelegationCredential, type NeedsAuthorizationError } from '@kya-os/mcp';
import { createDelegationIssuerFromIdentity } from '../src/delegation-issuer.js';

const crypto = new NodeCryptoProvider();
const CONSENT_URL = 'http://localhost:9999/consent';

interface ToolResult {
  content: Array<{ type: string; text: string; [key: string]: unknown }>;
  isError?: boolean;
  _meta?: Record<string, { jws: string; meta: Record<string, unknown> } | undefined>;
  [key: string]: unknown;
}

let kyaos: KyaOsMiddleware;
let browseHandler: (args: Record<string, unknown>, sessionId?: string) => Promise<ToolResult>;
let checkoutHandler: (args: Record<string, unknown>, sessionId?: string) => Promise<ToolResult>;
let serverDid: string;

async function issueTestDelegation(
  subjectDid: string,
  scopes: string[],
  notAfterOffset = 3600,
): Promise<DelegationCredential> {
  const factory = createDelegationIssuerFromIdentity(crypto, {
    did: kyaos.identity.did,
    kid: kyaos.identity.kid,
    privateKey: kyaos.identity.privateKey,
    publicKey: kyaos.identity.publicKey,
  });

  return factory.issuer.createAndIssueDelegation({
    id: `delegation-test-${Date.now()}`,
    issuerDid: kyaos.identity.did,
    subjectDid,
    constraints: {
      scopes,
      notAfter: Math.floor(Date.now() / 1000) + notAfterOffset,
    },
  });
}

describe('MCP Server with consent-basic', () => {
  beforeAll(async () => {
    const keyPair = await crypto.generateKeyPair();
    const did = generateDidKeyFromBase64(keyPair.publicKey);
    const kid = `${did}#${did.replace('did:key:', '')}`;
    serverDid = did;

    kyaos = createKyaOsMiddleware(
      {
        identity: { did, kid, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey },
        session: { sessionTtlMinutes: 60 },
        autoSession: true,
      },
      crypto,
    );

    browseHandler = kyaos.wrapWithProof('browse', async (args) => ({
      content: [{
        type: 'text',
        text: `Browsing category: ${args['category'] ?? 'all'}. Found 3 items.`,
      }],
    })) as typeof browseHandler;

    checkoutHandler = kyaos.wrapWithDelegation(
      'checkout',
      { scopeId: 'cart:write', consentUrl: CONSENT_URL },
      kyaos.wrapWithProof('checkout', async (args) => ({
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
    const result = await checkoutHandler({ item: 'widget', _kyaos_delegation: vc });

    expect(result.isError).toBeUndefined();
    expect(result.content[0]!.text).toContain('Order confirmed');
    expect(result.content[0]!.text).toContain('widget');
  });

  // §4.3 — Wrong scope
  it('should reject a delegation VC with wrong scope', async () => {
    const vc = await issueTestDelegation(serverDid, ['cart:read']);
    const result = await checkoutHandler({ item: 'widget', _kyaos_delegation: vc });

    expect(result.isError).toBe(true);
    const parsed = JSON.parse(result.content[0]!.text) as { error: string };
    expect(parsed.error).toBe('insufficient_scope');
  });

  // §4.2 — Expired delegation
  it('should reject an expired delegation VC', async () => {
    // Use a dedicated middleware instance to avoid shared state interference
    const expiredKyaOs = createKyaOsMiddleware(
      {
        identity: kyaos.identity,
        session: { sessionTtlMinutes: 60 },
        autoSession: true,
      },
      crypto,
    );

    const expiredCheckout = expiredKyaOs.wrapWithDelegation(
      'checkout',
      { scopeId: 'cart:write', consentUrl: CONSENT_URL },
      async (args) => ({
        content: [{ type: 'text', text: `Order: ${args['item']}` }],
      }),
    );

    const vc = await issueTestDelegation(serverDid, ['cart:write'], -3600);
    const result = await expiredCheckout({ item: 'widget', _kyaos_delegation: vc });

    expect(result.isError).toBe(true);
    const parsed = JSON.parse(result.content[0]!.text) as { error: string };
    expect(parsed.error).toBe('delegation_invalid');
  });

  // §5.1 — Detached proof on browse
  it('should attach a detached proof to browse tool response', async () => {
    const result = await browseHandler({ category: 'books' });

    expect(result._meta).toBeDefined();
    expect(result._meta![KYA_OS_PROOF_META_KEY]).toBeDefined();

    const proof = result._meta![KYA_OS_PROOF_META_KEY]!;
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

    expect(result1._meta![KYA_OS_PROOF_META_KEY]!.meta.requestHash).toBe(
      result2._meta![KYA_OS_PROOF_META_KEY]!.meta.requestHash,
    );
  });

  // §4.3 — _kyaos_delegation stripping
  it('should not pass _kyaos_delegation to the tool handler', async () => {
    let capturedArgs: Record<string, unknown> | undefined;
    const testKyaOs = createKyaOsMiddleware(
      {
        identity: kyaos.identity,
        session: { sessionTtlMinutes: 60 },
        autoSession: true,
      },
      crypto,
    );

    const handler = testKyaOs.wrapWithDelegation(
      'checkout',
      { scopeId: 'cart:write', consentUrl: CONSENT_URL },
      async (args) => {
        capturedArgs = args;
        return { content: [{ type: 'text', text: 'ok' }] };
      },
    );

    const vc = await issueTestDelegation(serverDid, ['cart:write']);
    await handler({ item: 'widget', _kyaos_delegation: vc });

    expect(capturedArgs).toBeDefined();
    expect(capturedArgs!['item']).toBe('widget');
    expect(capturedArgs!['_kyaos_delegation']).toBeUndefined();
  });
});
