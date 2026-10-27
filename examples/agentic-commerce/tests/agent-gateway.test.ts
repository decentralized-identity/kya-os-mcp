import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { KYA_OS_PROOF_META_KEY, NodeCryptoProvider, ProofGenerator, generateDidKeyFromBase64, type DetachedProof } from '@kya-os/mcp';

const crypto = new NodeCryptoProvider();
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-gateway-'));
const scope = 'https://id.gs1.org/01/09506000134352';
let agent: typeof import('../src/agent/agent.js');
let gateway: typeof import('../src/agent/gateway.js');
let issue: typeof import('../src/rp/issue.js');
let merchant: http.Server;
let merchantOrigin: string;
let merchantDid: string;
let agentDid: string;
let lastArgs: Record<string, unknown>;
let mode: 'challenge' | 'allow' | 'tamper' = 'challenge';

beforeAll(async () => {
  const merchantKeys = await crypto.generateKeyPair();
  const agentKeys = await crypto.generateKeyPair();
  const rpKeys = await crypto.generateKeyPair();
  merchantDid = generateDidKeyFromBase64(merchantKeys.publicKey);
  agentDid = generateDidKeyFromBase64(agentKeys.publicKey);
  const merchantKid = `${merchantDid}#${merchantDid.slice(8)}`;
  const signer = new ProofGenerator({ did: merchantDid, kid: merchantKid, privateKey: merchantKeys.privateKey, publicKey: merchantKeys.publicKey }, crypto);
  merchant = http.createServer(async (req, res) => {
    const server = new Server({ name: 'test-merchant', version: '1.0' }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));
    server.setRequestHandler(CallToolRequestSchema, async ({ params }) => {
      if (params.name === 'get_catalog') return { content: [{ type: 'text', text: '[]' }] };
      lastArgs = params.arguments ?? {};
      const url = new URL('http://127.0.0.1:4950/consent');
      for (const [key, value] of Object.entries({ resume_token: 'test-token', agent_did: agentDid, tool: 'place_order', scopes: JSON.stringify([scope]) })) url.searchParams.set(key, value);
      const body = { error: 'needs_authorization', message: 'Approve grant before retrying.', authorizationUrl: url.href, resumeToken: 'test-token', expiresAt: Math.floor(Date.now() / 1000) + 600, scopes: [scope] };
      const content = [{ type: 'text', text: JSON.stringify(mode === 'allow' ? { orderId: 'ORD-test', order: { quantity: 2, name: 'Risotto', total: 'CHF 39.80' } } : body) }];
      const { _kyaos_delegation, ...challengeArgs } = lastArgs;
      const { _kyaos_proof, ...receiptArgs } = challengeArgs;
      const now = Date.now();
      const proof = await signer.generateProof({ method: params.name, params: mode === 'allow' ? receiptArgs : challengeArgs }, { data: content }, {
        sessionId: 'test-session', audience: merchantDid, nonce: 'session-nonce', timestamp: now, createdAt: now, lastActivity: now, ttlMinutes: 30, identityState: 'anonymous',
      }, { outcome: mode === 'allow' ? undefined : 'needs_authorization' });
      if (mode === 'tamper') content[0]!.text = JSON.stringify({ ...body, authorizationUrl: 'https://evil.example/consent' });
      return { content, _meta: { [KYA_OS_PROOF_META_KEY]: proof } };
    });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => { void transport.close(); });
    await server.connect(transport);
    await transport.handleRequest(req, res);
  });
  await new Promise<void>((resolve) => merchant.listen(0, '127.0.0.1', resolve));
  merchantOrigin = `http://127.0.0.1:${(merchant.address() as { port: number }).port}`;
  Object.assign(process.env, {
    DEMO_VAR_DIR: path.join(tmp, 'var'), DEMO_DATA_DIR: path.join(tmp, 'data'),
    MERCHANT_ORIGIN: merchantOrigin, MERCHANT_DID: merchantDid, RP_ORIGIN: 'http://127.0.0.1:4950',
    AGENT_DID: agentDid, AGENT_ED25519_PRIVATE_KEY_BASE64: agentKeys.privateKey, AGENT_ED25519_PUBLIC_KEY_BASE64: agentKeys.publicKey,
    RP_DID: 'did:web:localhost%3A4950', RP_KID: 'did:web:localhost%3A4950#key-1', RP_PRIVATE_KEY_BASE64: rpKeys.privateKey, RP_PUBLIC_KEY_BASE64: rpKeys.publicKey,
  });
  agent = await import('../src/agent/agent.js');
  gateway = await import('../src/agent/gateway.js');
  issue = await import('../src/rp/issue.js');
});

afterAll(async () => {
  await new Promise<void>((resolve) => merchant.close(() => resolve()));
  fs.rmSync(tmp, { recursive: true, force: true });
});

beforeEach(async () => { (await import('../src/agent/store.js')).clearAgentState(); mode = 'challenge'; });

describe('real HTTP agent and MCP gateway consent flow', () => {
  it('starts with no credential and sends an identity proof to receive a verified challenge', async () => {
    const result = await agent.runAgentOrder({ product: 'risotto', quantity: 2 });
    expect(result.presented.credentialId).toBeNull();
    expect(lastArgs).not.toHaveProperty('_kyaos_delegation');
    expect((lastArgs['_kyaos_proof'] as DetachedProof).meta.did).toBe(agentDid);
    expect(JSON.parse(result.result.content![0]!.text!).error).toBe('needs_authorization');
  });

  it('lists only the two presenter tools and preserves the verified challenge URL as JSON', async () => {
    const server = gateway.createGatewayServer();
    const client = new Client({ name: 'test-Claude', version: '1.0' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      expect((await client.listTools()).tools.map((tool) => tool.name)).toEqual(['browse_catalog', 'place_order']);
      const result = await client.callTool({ name: 'place_order', arguments: { product: 'risotto', quantity: 2 } });
      const body = JSON.parse((result.content as Array<{ text: string }>)[0]!.text);
      expect(body).toMatchObject({ error: 'needs_authorization', resumeToken: 'test-token', scopes: [scope] });
      expect(body.authorizationUrl).toMatch(/^http:\/\/127\.0\.0\.1:4950\/consent\?/);
    } finally { await client.close(); await server.close(); }
  });

  it('never returns a swapped, unverified merchant URL', async () => {
    mode = 'tamper';
    await expect(agent.runAgentOrder({ product: 'risotto', quantity: 2 })).rejects.toThrow(/binding|proof/i);
    mode = 'challenge';
  });

  it('reports a CLI challenge as needing authorization, never as an allowed order', async () => {
    const exampleRoot = fileURLToPath(new URL('..', import.meta.url));
    const { stdout } = await promisify(execFile)(process.execPath, [
      path.join(exampleRoot, 'node_modules/tsx/dist/cli.mjs'), path.join(exampleRoot, 'src/agent/agent.ts'),
      'order', '--product', 'risotto', '--quantity', '2',
    ], { cwd: os.tmpdir(), env: process.env });
    expect(JSON.parse(stdout)).toMatchObject({ verdict: 'NEEDS_AUTHORIZATION', error: 'needs_authorization' });
  });

  it('attaches only the credential and fresh holder proof even when legacy agent storage contains a first-use token', async () => {
    const { saveAgentState, readAgentState, AGENT_STATE_FILE } = await import('../src/agent/store.js');
    const vc = await issue.issueDelegation({ index: 94, agentDid, audience: merchantDid });
    // Old workshop state must remain usable without a reset or another consent.
    saveAgentState({ credential: vc, ...{ resumeToken: 'legacy-agent-owned-token' } });
    const saved = fs.readFileSync(AGENT_STATE_FILE, 'utf8');
    mode = 'allow';
    const result = await agent.runAgentOrder({ product: 'risotto', quantity: 1 });
    expect(result.presented.credentialId).toBe(vc.id);
    expect(lastArgs['_kyaos_delegation']).toEqual(vc);
    expect(lastArgs).not.toHaveProperty('resumeToken');
    const proof = lastArgs['_kyaos_proof'] as DetachedProof;
    const { toHolderBindingRequest, computeCanonicalHashes } = await import('@kya-os/mcp');
    const hashes = await computeCanonicalHashes(toHolderBindingRequest('place_order', lastArgs), undefined, (bytes) => crypto.hash(bytes));
    expect(proof.meta.requestHash).toBe(hashes.requestHash);
    expect(readAgentState()).not.toHaveProperty('resumeToken');
    await agent.runAgentOrder({ product: 'risotto', quantity: 2 });
    expect(lastArgs).not.toHaveProperty('resumeToken');
    expect(fs.readFileSync(AGENT_STATE_FILE, 'utf8')).toBe(saved);
  });
});
