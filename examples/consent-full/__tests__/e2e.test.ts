/**
 * E2E Tests: Full consent -> delegation -> execution cycle
 *
 * Validates the complete KYA-OS consent flow using @kya-os/consent:
 * tool call -> needs_authorization -> consent page -> approve -> delegation -> retry -> success.
 *
 * Spec coverage: §4.1 (delegation chain), §5.1 (proof), §6.1 (needs_authorization),
 *                §6.2 (delegation verification)
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createKyaOsMiddleware, type KyaOsMiddleware } from '../../../src/middleware/index.js';
import { NodeCryptoProvider } from '../../../src/providers/node-crypto.js';
import { generateDidKeyFromBase64 } from '../../../src/utils/did-helpers.js';
import { startConsentServer, type ConsentServer } from '../src/consent-server.js';
import { createDelegationIssuerFromIdentity } from '../src/delegation-issuer.js';
import type { ToolResult } from '../src/server.js';
import type { DelegationCredential, NeedsAuthorizationError } from '../../../src/types/protocol.js';

const crypto = new NodeCryptoProvider();

let consentServer: ConsentServer;
let kya: KyaOsMiddleware;
let browseHandler: (args: Record<string, unknown>) => Promise<ToolResult>;
let checkoutHandler: (args: Record<string, unknown>) => Promise<ToolResult>;

describe('E2E: consent -> delegation -> execution', () => {
  beforeAll(async () => {
    // 1. Create MCP middleware with fresh identity
    const keyPair = await crypto.generateKeyPair();
    const did = generateDidKeyFromBase64(keyPair.publicKey);
    const kid = `${did}#${did.replace('did:key:', '')}`;

    kya = createKyaOsMiddleware(
      {
        identity: { did, kid, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey },
        session: { sessionTtlMinutes: 60 },
        autoSession: true,
      },
      crypto,
    );

    // 2. Start consent server with the MCP server's identity (shared trust domain)
    const factory = createDelegationIssuerFromIdentity(crypto, {
      did, kid, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey,
    });
    consentServer = await startConsentServer({ port: 0, factory });

    browseHandler = kya.wrapWithProof('browse', async (args) => ({
      content: [{ type: 'text', text: `Browsing: ${args['category'] ?? 'all'}` }],
    })) as typeof browseHandler;

    checkoutHandler = kya.wrapWithDelegation(
      'checkout',
      {
        scopeId: 'cart:write',
        consentUrl: `${consentServer.url}/consent?tool=checkout&scopes=cart:write&agent_did=${encodeURIComponent(did)}`,
      },
      kya.wrapWithProof('checkout', async (args) => ({
        content: [{ type: 'text', text: `Order confirmed: ${args['item']}` }],
      })),
    ) as typeof checkoutHandler;
  });

  afterAll(async () => {
    await consentServer.close();
  });

  // Full cycle: §6.1 -> §4.1 -> §6.2 -> §5.1
  it('should complete the full consent flow', async () => {
    // 3. Call checkout -> get needs_authorization
    const firstAttempt = await checkoutHandler({ item: 'laptop' });
    const authError = JSON.parse(firstAttempt.content[0]!.text) as NeedsAuthorizationError;
    expect(authError.error).toBe('needs_authorization');
    expect(authError.scopes).toContain('cart:write');

    // 4. Parse authorizationUrl
    const authUrl = new URL(authError.authorizationUrl);
    const tool = authUrl.searchParams.get('tool');
    const scopes = authUrl.searchParams.get('scopes');
    const agentDid = authUrl.searchParams.get('agent_did');

    // 5. POST /consent/approve to consent server (JSON — simulating approval)
    const approveRes = await fetch(`${consentServer.url}/consent/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool,
        scopes: scopes ? `["${scopes}"]` : '[]',
        agent_did: agentDid,
      }),
    });
    expect(approveRes.status).toBe(200);

    // 6. Parse the delegation token
    const approveData = (await approveRes.json()) as {
      success: boolean;
      delegationToken: DelegationCredential;
    };
    expect(approveData.success).toBe(true);
    expect(approveData.delegationToken).toBeDefined();
    const vc = approveData.delegationToken;
    expect(vc.type).toContain('DelegationCredential');

    // 7. Retry checkout with the VC
    const retryResult = await checkoutHandler({
      item: 'laptop',
      _kya_delegation: vc,
    });

    // 8. Tool executes successfully
    expect(retryResult.isError).toBeUndefined();
    expect(retryResult.content[0]!.text).toContain('Order confirmed');
    expect(retryResult.content[0]!.text).toContain('laptop');

    // 9. Response includes proof
    expect(retryResult._meta).toBeDefined();
    expect(retryResult._meta!.proof).toBeDefined();
    expect(retryResult._meta!.proof!.jws).toBeDefined();
  });

  // §4.3 — scope mismatch across tools
  it('should not allow reuse of delegation for different tools', async () => {
    const factory = createDelegationIssuerFromIdentity(crypto, {
      did: kya.identity.did,
      kid: kya.identity.kid,
      privateKey: kya.identity.privateKey,
      publicKey: kya.identity.publicKey,
    });

    const vc = await factory.issuer.createAndIssueDelegation({
      id: `wrong-scope-${Date.now()}`,
      issuerDid: kya.identity.did,
      subjectDid: kya.identity.did,
      constraints: {
        scopes: ['admin:write'],
        notAfter: Math.floor(Date.now() / 1000) + 3600,
      },
    });

    const result = await checkoutHandler({ item: 'laptop', _kya_delegation: vc });
    expect(result.isError).toBe(true);
    const parsed = JSON.parse(result.content[0]!.text) as { error: string };
    expect(parsed.error).toBe('insufficient_scope');
  });

  // Deny flow
  it('should handle denial gracefully — no delegation issued', async () => {
    const result = await checkoutHandler({ item: 'laptop' });
    const parsed = JSON.parse(result.content[0]!.text) as NeedsAuthorizationError;
    expect(parsed.error).toBe('needs_authorization');
  });

  // Browse still works without any delegation
  it('should execute browse with proof but no delegation', async () => {
    const result = await browseHandler({ category: 'electronics' });
    expect(result.isError).toBeUndefined();
    expect(result.content[0]!.text).toContain('electronics');
    expect(result._meta?.proof).toBeDefined();
  });

  // Consent page rendered by @kya-os/consent
  it('should serve a consent page with <mcp-consent> web component', async () => {
    const res = await fetch(
      `${consentServer.url}/consent?tool=checkout&scopes=cart:write&agent_did=did:key:z6MkTest`,
    );

    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('<mcp-consent');
    expect(body).toContain('checkout');
  });
});
