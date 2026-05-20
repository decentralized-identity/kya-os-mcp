/**
 * withKyaOs() Integration Tests
 *
 * Tests the dream API: `withKyaOs(server, { crypto })` auto-registers
 * the `_kyaos` protocol tool and auto-attaches proofs to all tool responses.
 */

import { describe, it, expect, afterEach } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { z } from 'zod';
import { withKyaOs, generateIdentity } from '../../middleware/with-kya-os-server.js';
import { NodeCryptoProvider } from '../utils/node-crypto-provider.js';

// ── Helpers ──────────────────────────────────────────────────────

async function createTestPair(options?: {
  proofAllTools?: boolean;
  excludeTools?: string[];
  autoSession?: boolean;
  registerToolsBeforeWithKyaOs?: boolean;
  handshakeExposure?: 'tool' | 'none';
}) {
  const crypto = new NodeCryptoProvider();
  const server = new McpServer(
    { name: 'withKyaOs-test', version: '1.0.0' },
    { instructions: 'Test server for withKyaOs integration' },
  );

  // Register tools BEFORE withKyaOs to test pre-existing tool interception
  if (options?.registerToolsBeforeWithKyaOs) {
    server.registerTool(
      'greet',
      {
        description: 'Greet someone',
        inputSchema: { name: z.string() },
      },
      async ({ name }) => ({
        content: [{ type: 'text', text: `Hello, ${name}!` }],
      }),
    );
  }

  const kyaos = await withKyaOs(server, {
    crypto,
    autoSession: options?.autoSession ?? true,
    proofAllTools: options?.proofAllTools,
    excludeTools: options?.excludeTools,
    handshakeExposure: options?.handshakeExposure,
  });

  // Register tools AFTER withKyaOs to test late registration
  if (!options?.registerToolsBeforeWithKyaOs) {
    server.registerTool(
      'greet',
      {
        description: 'Greet someone',
        inputSchema: { name: z.string() },
      },
      async ({ name }) => ({
        content: [{ type: 'text', text: `Hello, ${name}!` }],
      }),
    );
  }

  server.registerTool(
    'add',
    {
      description: 'Add two numbers',
      inputSchema: { a: z.number(), b: z.number() },
    },
    async ({ a, b }) => ({
      content: [{ type: 'text', text: `${a + b}` }],
    }),
  );

  const client = new Client(
    { name: 'withKyaOs-test-client', version: '1.0.0' },
  );

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  return { client, server, kyaos, crypto };
}

// ── Tests ──────────────────────────────────────────────────────

describe('withKyaOs()', () => {
  const pairs: Array<{ client: Client; server: McpServer }> = [];

  afterEach(async () => {
    for (const pair of pairs) {
      await pair.client.close();
      await pair.server.close();
    }
    pairs.length = 0;
  });

  async function create(options?: Parameters<typeof createTestPair>[0]) {
    const pair = await createTestPair(options);
    pairs.push(pair);
    return pair;
  }

  it('auto-registers _kyaos tool', async () => {
    const { client } = await create();

    const result = await client.listTools();
    const toolNames = result.tools.map((t) => t.name);

    expect(toolNames).toContain('_kyaos');
  });

  it('handshakeExposure: none does not auto-register _kyaos', async () => {
    const { client } = await create({ handshakeExposure: 'none' });

    const result = await client.listTools();
    const toolNames = result.tools.map((t) => t.name);

    expect(toolNames).not.toContain('_kyaos');
    expect(toolNames).toContain('greet');
  });

  it('auto-proofs all registered tools', async () => {
    const { client } = await create();

    const result = await client.callTool({
      name: 'greet',
      arguments: { name: 'World' },
    });

    const first = result.content[0] as { type: string; text: string };
    expect(first.text).toBe('Hello, World!');

    // Proof should be present via auto-session + auto-proof
    expect(result._meta).toBeDefined();
    const proof = (result._meta as Record<string, unknown>).proof as {
      jws: string;
      meta: Record<string, unknown>;
    };
    expect(proof).toBeDefined();
    expect(proof.jws).toBeDefined();
    expect(proof.meta.did).toMatch(/^did:key:/);
    expect(proof.meta.sessionId).toMatch(/^kyaos_/);
  });

  it('tools registered before withKyaOs also get proofs', async () => {
    const { client } = await create({ registerToolsBeforeWithKyaOs: true });

    const result = await client.callTool({
      name: 'greet',
      arguments: { name: 'Early Bird' },
    });

    const first = result.content[0] as { type: string; text: string };
    expect(first.text).toBe('Hello, Early Bird!');

    expect(result._meta).toBeDefined();
    const proof = (result._meta as Record<string, unknown>).proof as {
      jws: string;
    };
    expect(proof).toBeDefined();
    expect(proof.jws).toBeDefined();
  });

  it('excludeTools skips proof for specified tools', async () => {
    const { client } = await create({ excludeTools: ['greet'] });

    // 'greet' should NOT have proof
    const greetResult = await client.callTool({
      name: 'greet',
      arguments: { name: 'No Proof' },
    });

    const greetContent = greetResult.content[0] as { type: string; text: string };
    expect(greetContent.text).toBe('Hello, No Proof!');

    // _meta may be undefined or proof should not be present
    const greetProof = (greetResult._meta as Record<string, unknown> | undefined)?.proof;
    expect(greetProof).toBeUndefined();

    // 'add' should still have proof
    const addResult = await client.callTool({
      name: 'add',
      arguments: { a: 2, b: 3 },
    });

    expect(addResult._meta).toBeDefined();
    const addProof = (addResult._meta as Record<string, unknown>).proof as {
      jws: string;
    };
    expect(addProof).toBeDefined();
    expect(addProof.jws).toBeDefined();
  });

  it('proofAllTools: false disables auto-proofing', async () => {
    const { client } = await create({ proofAllTools: false });

    const result = await client.callTool({
      name: 'greet',
      arguments: { name: 'No Auto-Proof' },
    });

    const first = result.content[0] as { type: string; text: string };
    expect(first.text).toBe('Hello, No Auto-Proof!');

    // No proof — auto-proofing is off
    const proof = (result._meta as Record<string, unknown> | undefined)?.proof;
    expect(proof).toBeUndefined();
  });

  it('handshake establishes session through withKyaOs', async () => {
    const { client, kyaos } = await create({ autoSession: false });

    const result = await client.callTool({
      name: '_kyaos',
      arguments: {
        action: 'handshake',
        nonce: `test-${Date.now()}`,
        audience: kyaos.identity.did,
        timestamp: Math.floor(Date.now() / 1000),
      },
    });

    const first = result.content[0] as { type: string; text: string };
    const parsed = JSON.parse(first.text);
    expect(parsed.success).toBe(true);
    expect(parsed.sessionId).toMatch(/^kyaos_/);
    expect(parsed.serverDid).toBe(kyaos.identity.did);
  });

  it('manual handshake API works when handshake tool is not exposed', async () => {
    const { client, kyaos } = await create({
      autoSession: false,
      handshakeExposure: 'none',
    });

    await kyaos.handleHandshake({
      nonce: `manual-${Date.now()}`,
      audience: kyaos.identity.did,
      timestamp: Math.floor(Date.now() / 1000),
    });

    const result = await client.callTool({
      name: 'greet',
      arguments: { name: 'Manual Handshake' },
    });

    const first = result.content[0] as { type: string; text: string };
    expect(first.text).toBe('Hello, Manual Handshake!');

    expect(result._meta).toBeDefined();
    const proof = (result._meta as Record<string, unknown>).proof as {
      jws: string;
      meta: Record<string, unknown>;
    };
    expect(proof).toBeDefined();
    expect(proof.jws).toBeDefined();
    expect(proof.meta.sessionId).toMatch(/^kyaos_/);
  });

  it('multiple tools share the same auto-session', async () => {
    const { client } = await create();

    const result1 = await client.callTool({
      name: 'greet',
      arguments: { name: 'Alice' },
    });
    const result2 = await client.callTool({
      name: 'add',
      arguments: { a: 1, b: 2 },
    });

    const proof1 = (result1._meta as Record<string, unknown>).proof as {
      meta: Record<string, unknown>;
    };
    const proof2 = (result2._meta as Record<string, unknown>).proof as {
      meta: Record<string, unknown>;
    };

    expect(proof1.meta.sessionId).toBe(proof2.meta.sessionId);
  });

  it('wrapWithDelegation still works alongside withKyaOs', async () => {
    const crypto = new NodeCryptoProvider();
    const server = new McpServer(
      { name: 'delegation-test', version: '1.0.0' },
    );

    const kyaos = await withKyaOs(server, { crypto, autoSession: true });

    // Use wrapWithDelegation for a restricted tool
    const restrictedHandler = kyaos.wrapWithDelegation(
      'restricted-tool',
      { scopeId: 'admin:write', consentUrl: 'https://example.com/consent' },
      async (args) => ({
        content: [{ type: 'text', text: `Restricted: ${(args as { data: string }).data}` }],
      }),
    );

    server.registerTool(
      'restricted-tool',
      {
        description: 'Requires delegation',
        inputSchema: { data: z.string() },
      },
      async (args) => restrictedHandler(args as Record<string, unknown>),
    );

    const client = new Client({ name: 'delegation-client', version: '1.0.0' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    pairs.push({ client, server });

    // Call without delegation — should get needs_authorization
    const result = await client.callTool({
      name: 'restricted-tool',
      arguments: { data: 'test' },
    });

    const first = result.content[0] as { type: string; text: string };
    const parsed = JSON.parse(first.text);
    expect(parsed.error).toBe('needs_authorization');
    expect(parsed.authorizationUrl).toBe('https://example.com/consent');
  });
});

describe('generateIdentity()', () => {
  it('returns valid DID identity', async () => {
    const crypto = new NodeCryptoProvider();
    const identity = await generateIdentity(crypto);

    expect(identity.did).toMatch(/^did:key:z6Mk/);
    expect(identity.kid).toBe(`${identity.did}#${identity.did.replace('did:key:', '')}`);
    expect(identity.privateKey).toBeDefined();
    expect(identity.publicKey).toBeDefined();
    // Keys should be base64 strings
    expect(() => atob(identity.privateKey)).not.toThrow();
    expect(() => atob(identity.publicKey)).not.toThrow();
  });

  it('generates unique identities each call', async () => {
    const crypto = new NodeCryptoProvider();
    const id1 = await generateIdentity(crypto);
    const id2 = await generateIdentity(crypto);

    expect(id1.did).not.toBe(id2.did);
    expect(id1.privateKey).not.toBe(id2.privateKey);
  });
});
