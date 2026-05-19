/**
 * McpServer (High-Level API) + KYA-OS Integration Test
 *
 * Proves that KYA-OS middleware works with the high-level McpServer API
 * used by most real-world MCP servers (including Context7).
 *
 * This is distinct from mcp-transport.test.ts which uses the low-level
 * Server API. The key difference: McpServer uses registerTool() with
 * zod schemas, not setRequestHandler(CallToolRequestSchema, ...).
 */

import { describe, it, expect, afterEach } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { z } from 'zod';
import { createKyaOsMiddleware } from '../../middleware/with-kya-os.js';
import { withKyaOs } from '../../middleware/with-kya-os-server.js';
import { NodeCryptoProvider } from '../utils/node-crypto-provider.js';
import { generateDidKeyFromBase64 } from '../../utils/did-helpers.js';

// ── Helpers ──────────────────────────────────────────────────────

async function setupMcpServerPair(options?: { autoSession?: boolean }) {
  const crypto = new NodeCryptoProvider();
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  const kid = `${did}#${did.replace('did:key:', '')}`;

  const kya = createKyaOsMiddleware(
    {
      identity: { did, kid, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey },
      session: { sessionTtlMinutes: 60 },
      autoSession: options?.autoSession,
    },
    crypto,
  );

  // ── McpServer (high-level API, same as Context7) ──

  const server = new McpServer(
    { name: 'kya-os-mcpserver-test', version: '1.0.0' },
    { instructions: 'Test server for McpServer + KYA-OS integration' },
  );

  // Register unified _kya tool (same pattern as Context7 integration)
  server.registerTool(
    '_kya',
    {
      description: 'KYA-OS protocol',
      inputSchema: {
        action: z.enum(['handshake', 'identity', 'reputation']),
        nonce: z.string().optional(),
        audience: z.string().optional(),
        timestamp: z.number().optional(),
      },
    },
    async (args) => kya.handleKya(args as Record<string, unknown>),
  );

  // Wrap a test tool with proof (simulates Context7's resolve-library-id)
  const searchHandler = kya.wrapWithProof(
    'search',
    async (args) => ({
      content: [{
        type: 'text',
        text: `Found results for: ${(args as { query: string }).query}`,
      }],
    }),
  );

  server.registerTool(
    'search',
    {
      description: 'Search for something',
      inputSchema: {
        query: z.string().describe('Search query'),
      },
      annotations: { readOnlyHint: true },
    },
    async (args) => searchHandler(args as Record<string, unknown>),
  );

  // Wrap a second tool (simulates Context7's query-docs)
  const fetchHandler = kya.wrapWithProof(
    'fetch-docs',
    async (args) => ({
      content: [{
        type: 'text',
        text: `Docs for ${(args as { libraryId: string }).libraryId}: example content`,
      }],
    }),
  );

  server.registerTool(
    'fetch-docs',
    {
      description: 'Fetch documentation for a library',
      inputSchema: {
        libraryId: z.string().describe('Library identifier'),
        query: z.string().describe('What to search for in docs'),
      },
    },
    async (args) => fetchHandler(args as Record<string, unknown>),
  );

  // ── Client + transport ──

  const client = new Client(
    { name: 'kya-os-mcpserver-test-client', version: '1.0.0' },
  );

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  return { client, server, did, kid, keyPair, crypto };
}

// ── Tests ──────────────────────────────────────────────────────

describe('McpServer (High-Level API) + KYA-OS Integration', () => {
  const pairs: Array<{ client: Client; server: McpServer }> = [];

  afterEach(async () => {
    for (const pair of pairs) {
      await pair.client.close();
      await pair.server.close();
    }
    pairs.length = 0;
  });

  async function createPair(options?: { autoSession?: boolean }) {
    const pair = await setupMcpServerPair(options);
    pairs.push(pair);
    return pair;
  }

  it('listTools returns _kya + registered tools', async () => {
    const { client } = await createPair();

    const result = await client.listTools();
    const toolNames = result.tools.map((t) => t.name);

    expect(toolNames).toContain('_kya');
    expect(toolNames).toContain('search');
    expect(toolNames).toContain('fetch-docs');
  });

  it('handshake establishes session via McpServer', async () => {
    const { client, did } = await createPair();

    const result = await client.callTool({
      name: '_kya',
      arguments: {
        action: 'handshake',
        nonce: `mcpserver-test-${Date.now()}`,
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      },
    });

    expect(result.content).toHaveLength(1);
    const first = result.content[0] as { type: string; text: string };
    expect(first.type).toBe('text');

    const parsed = JSON.parse(first.text);
    expect(parsed.success).toBe(true);
    expect(parsed.sessionId).toMatch(/^kya_/);
    expect(parsed.serverDid).toBe(did);
  });

  it('tool returns proof in _meta after handshake', async () => {
    const { client, did } = await createPair();

    // Handshake first
    await client.callTool({
      name: '_kya',
      arguments: {
        action: 'handshake',
        nonce: `mcpserver-test-${Date.now()}`,
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      },
    });

    // Call search tool
    const result = await client.callTool({
      name: 'search',
      arguments: { query: 'react hooks' },
    });

    // Verify tool output
    const first = result.content[0] as { type: string; text: string };
    expect(first.text).toBe('Found results for: react hooks');

    // Verify proof in _meta
    expect(result._meta).toBeDefined();
    const proof = (result._meta as Record<string, unknown>).proof as {
      jws: string;
      meta: Record<string, unknown>;
    };
    expect(proof).toBeDefined();
    expect(proof.jws).toBeDefined();
    expect(proof.meta.did).toMatch(/^did:key:/);
    expect(proof.meta.sessionId).toMatch(/^kya_/);
    expect(proof.meta.requestHash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(proof.meta.responseHash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('autoSession attaches proof without handshake (McpServer)', async () => {
    const { client } = await createPair({ autoSession: true });

    // Call tool directly — no handshake
    const result = await client.callTool({
      name: 'search',
      arguments: { query: 'next.js routing' },
    });

    const first = result.content[0] as { type: string; text: string };
    expect(first.text).toBe('Found results for: next.js routing');

    // Proof should be present via auto-session
    expect(result._meta).toBeDefined();
    const proof = (result._meta as Record<string, unknown>).proof as {
      jws: string;
      meta: Record<string, unknown>;
    };
    expect(proof).toBeDefined();
    expect(proof.jws).toBeDefined();
    expect(proof.meta.sessionId).toMatch(/^kya_/);
  });

  it('second tool also gets proof (McpServer)', async () => {
    const { client } = await createPair({ autoSession: true });

    const result = await client.callTool({
      name: 'fetch-docs',
      arguments: { libraryId: '/vercel/next.js', query: 'app router' },
    });

    const first = result.content[0] as { type: string; text: string };
    expect(first.text).toBe('Docs for /vercel/next.js: example content');

    // Verify proof is attached
    expect(result._meta).toBeDefined();
    const proof = (result._meta as Record<string, unknown>).proof as {
      jws: string;
      meta: Record<string, unknown>;
    };
    expect(proof).toBeDefined();
    expect(proof.jws).toBeDefined();
  });

  it('multiple tools share the same session', async () => {
    const { client } = await createPair({ autoSession: true });

    const result1 = await client.callTool({
      name: 'search',
      arguments: { query: 'express middleware' },
    });
    const result2 = await client.callTool({
      name: 'fetch-docs',
      arguments: { libraryId: '/expressjs/express', query: 'middleware' },
    });

    const proof1 = (result1._meta as Record<string, unknown>).proof as {
      meta: Record<string, unknown>;
    };
    const proof2 = (result2._meta as Record<string, unknown>).proof as {
      meta: Record<string, unknown>;
    };

    // Same session ID across tools
    expect(proof1.meta.sessionId).toBe(proof2.meta.sessionId);
  });
});

// ── withKyaOs() path — same tests, dream API ───────────────────

describe('McpServer + withKyaOs() (Dream API)', () => {
  const pairs: Array<{ client: Client; server: McpServer }> = [];

  afterEach(async () => {
    for (const pair of pairs) {
      await pair.client.close();
      await pair.server.close();
    }
    pairs.length = 0;
  });

  async function createWithKyaOsPair(options?: { autoSession?: boolean }) {
    const crypto = new NodeCryptoProvider();
    const server = new McpServer(
      { name: 'kya-os-withkyaos-test', version: '1.0.0' },
      { instructions: 'Test server for withKyaOs integration' },
    );

    const kya = await withKyaOs(server, {
      crypto,
      autoSession: options?.autoSession ?? true,
    });

    // Register tools AFTER withKyaOs — they should still get proofs
    server.registerTool(
      'search',
      {
        description: 'Search for something',
        inputSchema: { query: z.string().describe('Search query') },
        annotations: { readOnlyHint: true },
      },
      async ({ query }) => ({
        content: [{ type: 'text', text: `Found results for: ${query}` }],
      }),
    );

    server.registerTool(
      'fetch-docs',
      {
        description: 'Fetch documentation for a library',
        inputSchema: {
          libraryId: z.string().describe('Library identifier'),
          query: z.string().describe('What to search for in docs'),
        },
      },
      async ({ libraryId }) => ({
        content: [{ type: 'text', text: `Docs for ${libraryId}: example content` }],
      }),
    );

    const client = new Client(
      { name: 'kya-os-withkyaos-test-client', version: '1.0.0' },
    );

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    pairs.push({ client, server });
    return { client, server, kya };
  }

  it('listTools returns _kya + registered tools (withKyaOs)', async () => {
    const { client } = await createWithKyaOsPair();

    const result = await client.listTools();
    const toolNames = result.tools.map((t) => t.name);

    expect(toolNames).toContain('_kya');
    expect(toolNames).toContain('search');
    expect(toolNames).toContain('fetch-docs');
  });

  it('autoSession attaches proof without handshake (withKyaOs)', async () => {
    const { client } = await createWithKyaOsPair();

    const result = await client.callTool({
      name: 'search',
      arguments: { query: 'next.js routing' },
    });

    const first = result.content[0] as { type: string; text: string };
    expect(first.text).toBe('Found results for: next.js routing');

    expect(result._meta).toBeDefined();
    const proof = (result._meta as Record<string, unknown>).proof as {
      jws: string;
      meta: Record<string, unknown>;
    };
    expect(proof).toBeDefined();
    expect(proof.jws).toBeDefined();
    expect(proof.meta.sessionId).toMatch(/^kya_/);
  });

  it('handshake works through withKyaOs', async () => {
    const { client, kya } = await createWithKyaOsPair({ autoSession: false });

    const result = await client.callTool({
      name: '_kya',
      arguments: {
        action: 'handshake',
        nonce: `withkyaos-test-${Date.now()}`,
        audience: kya.identity.did,
        timestamp: Math.floor(Date.now() / 1000),
      },
    });

    const first = result.content[0] as { type: string; text: string };
    const parsed = JSON.parse(first.text);
    expect(parsed.success).toBe(true);
    expect(parsed.sessionId).toMatch(/^kya_/);
    expect(parsed.serverDid).toBe(kya.identity.did);
  });

  it('no per-tool wrapping needed — proofs are automatic (withKyaOs)', async () => {
    const { client } = await createWithKyaOsPair();

    // Both tools should get proofs without any manual wrapping
    const searchResult = await client.callTool({
      name: 'search',
      arguments: { query: 'react hooks' },
    });
    const docsResult = await client.callTool({
      name: 'fetch-docs',
      arguments: { libraryId: '/vercel/next.js', query: 'app router' },
    });

    for (const result of [searchResult, docsResult]) {
      expect(result._meta).toBeDefined();
      const proof = (result._meta as Record<string, unknown>).proof as {
        jws: string;
      };
      expect(proof).toBeDefined();
      expect(proof.jws).toBeDefined();
    }
  });
});
