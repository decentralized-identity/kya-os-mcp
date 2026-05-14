/**
 * E2E Tests: Full consent → delegation → execution cycle
 *
 * Validates the complete MCP-I consent flow as a user would experience it:
 * tool call → needs_authorization → consent page → approve → delegation → retry → success.
 *
 * Spec coverage: §4.1 (delegation chain), §5.1 (proof), §6.1 (needs_authorization),
 *                §6.2 (delegation verification)
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createMCPIMiddleware, type MCPIMiddleware } from '../../../src/middleware/with-mcpi.js';
import { NodeCryptoProvider } from '../../../src/providers/node-crypto.js';
import { generateDidKeyFromBase64 } from '../../../src/utils/did-helpers.js';
import { startConsentServer, type ConsentServer } from '../src/consent-server.js';
import { createDelegationIssuerFromIdentity } from '../src/delegation-issuer.js';
import type { DelegationCredential, NeedsAuthorizationError } from '../../../src/types/protocol.js';

const crypto = new NodeCryptoProvider();

interface ToolResult {
  content: Array<{ type: string; text: string; [key: string]: unknown }>;
  isError?: boolean;
  _meta?: { proof?: { jws: string; meta: Record<string, unknown> } };
  [key: string]: unknown;
}

let consentServer: ConsentServer;
let mcpi: MCPIMiddleware;
let browseHandler: (args: Record<string, unknown>) => Promise<ToolResult>;
let checkoutHandler: (args: Record<string, unknown>) => Promise<ToolResult>;

describe('E2E: consent -> delegation -> execution', () => {
  beforeAll(async () => {
    // 1. Create MCP middleware with fresh identity
    const keyPair = await crypto.generateKeyPair();
    const did = generateDidKeyFromBase64(keyPair.publicKey);
    const kid = `${did}#${did.replace('did:key:', '')}`;

    mcpi = createMCPIMiddleware(
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

    browseHandler = mcpi.wrapWithProof('browse', async (args) => ({
      content: [{ type: 'text', text: `Browsing: ${args['category'] ?? 'all'}` }],
    })) as typeof browseHandler;

    checkoutHandler = mcpi.wrapWithDelegation(
      'checkout',
      {
        scopeId: 'cart:write',
        consentUrl: `${consentServer.url}/consent?tool=checkout&scopes=cart:write&agent_did=${encodeURIComponent(did)}`,
      },
      mcpi.wrapWithProof('checkout', async (args) => ({
        content: [{ type: 'text', text: `Order confirmed: ${args['item']}` }],
      })),
    ) as typeof checkoutHandler;
  });

  afterAll(async () => {
    await consentServer.close();
  });

  // Full cycle: §6.1 → §4.1 → §6.2 → §5.1
  it('should complete the full consent flow', async () => {
    // 3. Call checkout → get needs_authorization
    const firstAttempt = await checkoutHandler({ item: 'laptop' });
    const authError = JSON.parse(firstAttempt.content[0]!.text) as NeedsAuthorizationError;
    expect(authError.error).toBe('needs_authorization');
    expect(authError.scopes).toContain('cart:write');

    // 4. Parse authorizationUrl
    const authUrl = new URL(authError.authorizationUrl);
    const tool = authUrl.searchParams.get('tool');
    const scopes = authUrl.searchParams.get('scopes');
    const agentDid = authUrl.searchParams.get('agent_did');

    // 5. POST /approve to consent server
    const approveRes = await fetch(`${consentServer.url}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool, scopes, agentDid }),
    });
    expect(approveRes.status).toBe(200);

    // 6. Parse the delegation token (returned as object, not string)
    const approveData = (await approveRes.json()) as { delegationToken: DelegationCredential };
    expect(approveData.delegationToken).toBeDefined();
    const vc = approveData.delegationToken;
    expect(vc.type).toContain('DelegationCredential');

    // 7. Retry checkout with the consent server's VC directly.
    //    This works because both servers share the same identity.
    const retryResult = await checkoutHandler({
      item: 'laptop',
      _mcpi_delegation: vc,
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

  // Full cycle with VC-JWT format: §6.1 → §4.1 → §6.2 → §5.1
  it('should complete the full consent flow with VC-JWT format', async () => {
    // 3. Call checkout → get needs_authorization
    const firstAttempt = await checkoutHandler({ item: 'headphones' });
    const authError = JSON.parse(firstAttempt.content[0]!.text) as NeedsAuthorizationError;
    expect(authError.error).toBe('needs_authorization');

    // 4. Parse authorizationUrl
    const authUrl = new URL(authError.authorizationUrl);
    const tool = authUrl.searchParams.get('tool');
    const scopes = authUrl.searchParams.get('scopes');
    const agentDid = authUrl.searchParams.get('agent_did');

    // 5. POST /approve with format=jwt
    const approveRes = await fetch(`${consentServer.url}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool, scopes, agentDid, format: 'jwt' }),
    });
    expect(approveRes.status).toBe(200);

    // 6. Parse the delegation token — should be a JWT string (not object)
    const approveData = (await approveRes.json()) as { delegationToken: string };
    expect(typeof approveData.delegationToken).toBe('string');
    expect(approveData.delegationToken.split('.').length).toBe(3);

    // 7. Retry checkout with the JWT string as _mcpi_delegation
    const retryResult = await checkoutHandler({
      item: 'headphones',
      _mcpi_delegation: approveData.delegationToken,
    });

    // 8. Tool executes successfully — middleware parsed the JWT transparently
    expect(retryResult.isError).toBeUndefined();
    expect(retryResult.content[0]!.text).toContain('Order confirmed');
    expect(retryResult.content[0]!.text).toContain('headphones');

    // 9. Response includes proof
    expect(retryResult._meta?.proof).toBeDefined();
  });

  // §4.3 — scope mismatch across tools
  it('should not allow reuse of delegation for different tools', async () => {
    // A delegation for cart:write should not work for a tool requiring admin:write
    const factory = createDelegationIssuerFromIdentity(crypto, {
      did: mcpi.identity.did,
      kid: mcpi.identity.kid,
      privateKey: mcpi.identity.privateKey,
      publicKey: mcpi.identity.publicKey,
    });

    const vc = await factory.issuer.createAndIssueDelegation({
      id: `wrong-scope-${Date.now()}`,
      issuerDid: mcpi.identity.did,
      subjectDid: mcpi.identity.did,
      constraints: {
        scopes: ['admin:write'],
        notAfter: Math.floor(Date.now() / 1000) + 3600,
      },
    });

    const result = await checkoutHandler({ item: 'laptop', _mcpi_delegation: vc });
    expect(result.isError).toBe(true);
    const parsed = JSON.parse(result.content[0]!.text) as { error: string };
    expect(parsed.error).toBe('insufficient_scope');
  });

  // Deny flow
  it('should handle denial gracefully — no delegation issued', async () => {
    // Without approving, subsequent calls still return needs_authorization
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
});
