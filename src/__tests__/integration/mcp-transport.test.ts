/**
 * End-to-End MCP Transport Integration Test
 *
 * Exercises the KYA-OS middleware through a real MCP SDK Client→Server
 * transport (InMemoryTransport). Unlike unit tests that call handlers
 * directly, these tests go through full JSON-RPC serialization and
 * MCP protocol framing.
 */

import { describe, it, expect, afterEach } from 'vitest';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { createKyaOsMiddleware } from '../../middleware/with-kya-os.js';
import { NodeCryptoProvider } from '../utils/node-crypto-provider.js';
import { generateDidKeyFromBase64 } from '../../utils/did-helpers.js';
import { DelegationCredentialIssuer } from '../../delegation/vc-issuer.js';
import { ProofVerifier } from '../../proof/verifier.js';
import { MemoryNonceCacheProvider } from '../../providers/memory.js';
import { ClockProvider, FetchProvider } from '../../providers/base.js';
import {
  createDidKeyResolver,
  extractPublicKeyFromDidKey,
  publicKeyToJwk,
} from '../../delegation/did-key-resolver.js';
import { base64urlEncodeFromBytes } from '../../utils/base64.js';
import type {
  DelegationCredential,
  DIDDocument,
  StatusList2021Credential,
  DelegationRecord,
  Proof,
} from '../../types/protocol.js';

// ── Test providers for ProofVerifier ──────────────────────────────

class TestClockProvider extends ClockProvider {
  now(): number { return Date.now(); }
  isWithinSkew(timestampMs: number, skewSeconds: number): boolean {
    return Math.abs(Date.now() - timestampMs) <= skewSeconds * 1000;
  }
  hasExpired(expiresAt: number): boolean { return Date.now() > expiresAt; }
  calculateExpiry(ttlSeconds: number): number { return Date.now() + ttlSeconds * 1000; }
  format(timestamp: number): string { return new Date(timestamp).toISOString(); }
}

class TestFetchProvider extends FetchProvider {
  private didResolver = createDidKeyResolver();
  async resolveDID(did: string): Promise<DIDDocument | null> {
    return this.didResolver.resolve(did);
  }
  async fetchStatusList(): Promise<StatusList2021Credential | null> { return null; }
  async fetchDelegationChain(): Promise<DelegationRecord[]> { return []; }
  async fetch(): Promise<Response> { throw new Error('Not implemented'); }
}

// ── Helpers ──────────────────────────────────────────────────────

async function setupMcpPair(options?: { autoSession?: boolean }) {
  const crypto = new NodeCryptoProvider();
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  const kid = `${did}#${did.replace('did:key:', '')}`;

  const kyaos = createKyaOsMiddleware(
    {
      identity: { did, kid, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey },
      session: { sessionTtlMinutes: 60 },
      autoSession: options?.autoSession,
    },
    crypto,
  );

  // ── Tool handlers (mirrors examples/node-server/server.ts) ──

  const greetHandler = kyaos.wrapWithProof('greet', async (args) => ({
    content: [{ type: 'text', text: `Hello, ${args['name'] ?? 'world'}!` }],
  }));

  const restrictedGreetHandler = kyaos.wrapWithDelegation(
    'restricted_greet',
    {
      scopeId: 'greeting:restricted',
      consentUrl: 'https://example.com/consent?scope=greeting:restricted',
    },
    kyaos.wrapWithProof('restricted_greet', async (args) => ({
      content: [{ type: 'text', text: `Hello, ${args['name'] ?? 'world'}! (delegation verified)` }],
    })),
  );

  // ── MCP Server ──

  const server = new Server(
    { name: 'kya-os-transport-test', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      kyaos.kyaOsTool,
      {
        name: 'greet',
        description: 'Returns a greeting with proof',
        inputSchema: {
          type: 'object' as const,
          properties: { name: { type: 'string' } },
        },
      },
      {
        name: 'restricted_greet',
        description: 'Protected greeting requiring delegation',
        inputSchema: {
          type: 'object' as const,
          properties: {
            name: { type: 'string' },
            _kyaos_delegation: { type: 'object' },
          },
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;

    if (name === '_kyaos') {
      return kyaos.handleKyaOs(args as Record<string, unknown>);
    }
    if (name === 'greet') {
      return greetHandler(args as Record<string, unknown>);
    }
    if (name === 'restricted_greet') {
      return restrictedGreetHandler(args as Record<string, unknown>);
    }

    return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
  });

  // ── Client + transport ──

  const client = new Client(
    { name: 'kya-os-transport-test-client', version: '1.0.0' },
  );

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  return { client, server, did, kid, keyPair, crypto };
}

async function issueDelegationVC(scopes: string[]): Promise<DelegationCredential> {
  const crypto = new NodeCryptoProvider();
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  const kid = `${did}#${did.replace('did:key:', '')}`;

  const signingFn = async (
    canonicalVC: string,
    _issuerDid: string,
    kidArg: string,
  ): Promise<Proof> => {
    const data = new TextEncoder().encode(canonicalVC);
    const sigBytes = await crypto.sign(data, keyPair.privateKey);
    const proofValue = base64urlEncodeFromBytes(sigBytes);
    return {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: kidArg,
      proofPurpose: 'assertionMethod',
      proofValue,
    };
  };

  const issuer = new DelegationCredentialIssuer(
    { getDid: () => did, getKeyId: () => kid, getPrivateKey: () => keyPair.privateKey },
    signingFn,
  );

  return issuer.createAndIssueDelegation({
    id: `test-delegation-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    issuerDid: did,
    subjectDid: did,
    constraints: {
      scopes,
      notAfter: Math.floor(Date.now() / 1000) + 3600,
    },
  });
}

// ── Tests ──────────────────────────────────────────────────────

describe('MCP Transport Integration', () => {
  const pairs: Array<{ client: Client; server: Server }> = [];

  afterEach(async () => {
    for (const pair of pairs) {
      await pair.client.close();
      await pair.server.close();
    }
    pairs.length = 0;
  });

  async function createPair(options?: { autoSession?: boolean }) {
    const pair = await setupMcpPair(options);
    pairs.push(pair);
    return pair;
  }

  it('listTools returns _kyaos + app tools', async () => {
    const { client } = await createPair();

    const result = await client.listTools();
    const toolNames = result.tools.map((t) => t.name);

    expect(toolNames).toHaveLength(3);
    expect(toolNames).toContain('_kyaos');
    expect(toolNames).toContain('greet');
    expect(toolNames).toContain('restricted_greet');
  });

  it('handshake establishes session via MCP transport', async () => {
    const { client, did } = await createPair();

    const result = await client.callTool({
      name: '_kyaos',
      arguments: {
        action: 'handshake',
        nonce: `transport-test-${Date.now()}`,
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      },
    });

    expect(result.content).toHaveLength(1);
    const first = result.content[0] as { type: string; text: string };
    expect(first.type).toBe('text');

    const parsed = JSON.parse(first.text);
    expect(parsed.success).toBe(true);
    expect(parsed.sessionId).toMatch(/^kyaos_/);
    expect(parsed.serverDid).toBe(did);
  });

  it('greet returns proof in _meta after handshake', async () => {
    const { client, did } = await createPair();

    // Handshake first
    await client.callTool({
      name: '_kyaos',
      arguments: {
        action: 'handshake',
        nonce: `transport-test-${Date.now()}`,
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      },
    });

    // Call greet
    const result = await client.callTool({
      name: 'greet',
      arguments: { name: 'KYA-OS' },
    });

    // Verify tool output
    const first = result.content[0] as { type: string; text: string };
    expect(first.text).toBe('Hello, KYA-OS!');

    // Verify proof in _meta (top-level on the result)
    expect(result._meta).toBeDefined();
    const proof = (result._meta as Record<string, unknown>).proof as {
      jws: string;
      meta: Record<string, unknown>;
    };
    expect(proof).toBeDefined();
    expect(proof.jws).toBeDefined();
    expect(proof.meta.did).toMatch(/^did:key:/);
    expect(proof.meta.sessionId).toMatch(/^kyaos_/);
    expect(proof.meta.requestHash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(proof.meta.responseHash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('proof from greet verifies cryptographically', async () => {
    const { client, did, kid } = await createPair();

    // Handshake
    await client.callTool({
      name: '_kyaos',
      arguments: {
        action: 'handshake',
        nonce: `transport-test-${Date.now()}`,
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      },
    });

    // Call greet
    const result = await client.callTool({
      name: 'greet',
      arguments: { name: 'Verifier' },
    });

    const proof = (result._meta as Record<string, unknown>).proof as {
      jws: string;
      meta: Record<string, unknown>;
    };

    // Resolve server's public key from did:key
    const publicKeyBytes = extractPublicKeyFromDidKey(did);
    expect(publicKeyBytes).not.toBeNull();
    const publicKeyJwk = publicKeyToJwk(publicKeyBytes!);

    // Create verifier and verify
    const crypto = new NodeCryptoProvider();
    const verifier = new ProofVerifier({
      cryptoProvider: crypto,
      clockProvider: new TestClockProvider(),
      nonceCacheProvider: new MemoryNonceCacheProvider(),
      fetchProvider: new TestFetchProvider(),
      timestampSkewSeconds: 300,
    });

    const jwkWithKid = { ...publicKeyJwk, kid };
    const verificationResult = await verifier.verifyProof(proof as any, jwkWithKid as any);
    expect(verificationResult.valid).toBe(true);
  });

  it('autoSession attaches proof without handshake', async () => {
    const { client } = await createPair({ autoSession: true });

    // Call greet directly — no handshake
    const result = await client.callTool({
      name: 'greet',
      arguments: { name: 'Auto' },
    });

    const first = result.content[0] as { type: string; text: string };
    expect(first.text).toBe('Hello, Auto!');

    // Proof should be present via auto-session
    expect(result._meta).toBeDefined();
    const proof = (result._meta as Record<string, unknown>).proof as {
      jws: string;
      meta: Record<string, unknown>;
    };
    expect(proof).toBeDefined();
    expect(proof.jws).toBeDefined();
    expect(proof.meta.sessionId).toMatch(/^kyaos_/);
  });

  it('restricted_greet without delegation returns needs_authorization', async () => {
    const { client } = await createPair();

    const result = await client.callTool({
      name: 'restricted_greet',
      arguments: { name: 'Unauthorized' },
    });

    const first = result.content[0] as { type: string; text: string };
    const parsed = JSON.parse(first.text);
    expect(parsed.error).toBe('needs_authorization');
    expect(parsed.authorizationUrl).toContain('consent');
    expect(parsed.scopes).toContain('greeting:restricted');
    expect(parsed.resumeToken).toBeDefined();
  });

  it('restricted_greet with valid delegation VC returns greeting with proof', async () => {
    const { client, did } = await createPair({ autoSession: true });

    const vc = await issueDelegationVC(['greeting:restricted']);

    const result = await client.callTool({
      name: 'restricted_greet',
      arguments: { name: 'DIF', _kyaos_delegation: vc },
    });

    const first = result.content[0] as { type: string; text: string };
    expect(first.text).toBe('Hello, DIF! (delegation verified)');

    // Proof from inner wrapWithProof
    expect(result._meta).toBeDefined();
    const proof = (result._meta as Record<string, unknown>).proof as {
      jws: string;
      meta: Record<string, unknown>;
    };
    expect(proof).toBeDefined();
    expect(proof.jws).toBeDefined();
  });
});
