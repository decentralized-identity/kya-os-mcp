/**
 * Interactive retry regression test (mcp-inspector style).
 *
 * Unlike e2e.test.ts (which wires checkoutHandler directly and re-passes the VC
 * on retry), this drives the REAL server handler chain —
 * createConsentFullMcpServer → formatAsConsentLink → DelegationStore — over a
 * live MCP client + a real consent server, exactly as a generic client
 * (mcp-inspector) would: it NEVER re-passes the delegation on retry.
 *
 * Guards the bug the user hit: a peek→consume regression (or dropping the
 * auto-apply) would make the 3rd call fail, so the suite would catch it.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import {
  createKyaOsMiddleware,
  NodeCryptoProvider,
  generateDidKeyFromBase64,
  type KyaOsMiddleware,
} from '@kya-os/mcp';
import { createConsentFullMcpServer, DelegationStore } from '../src/server.js';
import { startConsentServer, type ConsentServer } from '../src/consent-server.js';
import { createDelegationIssuerFromIdentity } from '../src/delegation-issuer.js';

const crypto = new NodeCryptoProvider();

interface ToolCallResult {
  content?: Array<{ text?: string }>;
  isError?: boolean;
}
const textOf = (r: ToolCallResult): string => r.content?.[0]?.text ?? '';

describe('consent-full interactive retry (mcp-inspector style, no re-paste)', () => {
  let consentServer: ConsentServer;
  let client: Client;
  let store: DelegationStore;
  let kyaos: KyaOsMiddleware;

  beforeAll(async () => {
    const keyPair = await crypto.generateKeyPair();
    const did = generateDidKeyFromBase64(keyPair.publicKey);
    const kid = `${did}#${did.replace('did:key:', '')}`;
    const identity = { did, kid, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey };

    kyaos = createKyaOsMiddleware(
      { identity, session: { sessionTtlMinutes: 60 }, autoSession: true, emitLegacyProofKey: false },
      crypto,
    );

    const factory = createDelegationIssuerFromIdentity(crypto, identity);
    store = new DelegationStore();
    // Shared store: the consent server writes the approved VC, the MCP server reads it.
    consentServer = await startConsentServer({ port: 0, factory, delegationStore: store });

    // The ACTUAL server handler chain (wraps checkout with formatAsConsentLink).
    const server = createConsentFullMcpServer(kyaos, {
      consentUrl: `${consentServer.url}/consent`,
      delegationStore: store,
    });
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    await server.connect(serverT);
    client = new Client({ name: 'inspector-mimic', version: '1.0.0' }, { capabilities: {} });
    await client.connect(clientT);
  });

  afterAll(async () => {
    await consentServer.close();
  });

  it('approve once, then retry twice with NO re-paste — both succeed (peek, not consume)', async () => {
    // 1. checkout WITHOUT a delegation → needs_authorization (consent link).
    const r1 = (await client.callTool({ name: 'checkout', arguments: { item: 'laptop' } })) as ToolCallResult;
    const t1 = textOf(r1);
    expect(t1).toMatch(/Authorization required|needs_authorization/);
    const resumeToken = (t1.match(/resume_token=([^)\s&]+)/) ?? [])[1] ?? '';
    expect(resumeToken).toBeTruthy();

    // 2. Approve via the consent server (stores the delegation, keyed by resume token).
    const approveRes = await fetch(`${consentServer.url}/consent/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'checkout',
        scopes: JSON.stringify(['cart:write']),
        agent_did: kyaos.identity.did,
        session_id: resumeToken,
        auth_mode: 'consent-only',
        termsAccepted: true,
      }),
    });
    expect(((await approveRes.json()) as { success?: boolean }).success).toBe(true);

    // 3. Retry WITHOUT re-passing the VC → SUCCESS (re-presented from the store).
    const r2 = (await client.callTool({ name: 'checkout', arguments: { item: 'laptop' } })) as ToolCallResult;
    expect(r2.isError ?? false).toBe(false);
    expect(textOf(r2)).toContain('Order confirmed');

    // 4. Retry AGAIN WITHOUT the VC → still SUCCESS (proves PEEK, not consume).
    const r3 = (await client.callTool({ name: 'checkout', arguments: { item: 'laptop' } })) as ToolCallResult;
    expect(r3.isError ?? false).toBe(false);
    expect(textOf(r3)).toContain('Order confirmed');
  });
});
