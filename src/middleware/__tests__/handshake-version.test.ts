/**
 * The handshake response, and the protocol version a handshake states (SPEC.md §5.3, §13).
 *
 * A response states the session, the server's DID and key, the protocol version the server speaks,
 * `1.0`, and the session's lifetime in seconds, and validates under the published schema. A refusal
 * states the version too, so a client of another major version learns which one the server speaks.
 * A server refuses a handshake whose `clientProtocolVersion` is of another major version with
 * `protocol_version_unsupported`. For the 1.x line it reads the three-part form 1.x clients were told
 * to send, and reads a value that is not a version as none.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { withKyaOs } from '../with-kya-os-server.js';
import { createMiddleware } from './helpers/received-proof.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';

const load = (name: string): object =>
  JSON.parse(readFileSync(new URL(`../../../schemas/${name}`, import.meta.url), 'utf8')) as object;
const ajv = new (Ajv2020 as unknown as typeof Ajv2020.default)({ strict: false, allErrors: true });
const validResponse = ajv.compile(load('handshake-response.json'));
const validRequest = ajv.compile(load('handshake-request.json'));

let nonces = 0;
const nonce = (): string => `k7Hy9mNpQrStUvWxYz${String((nonces += 1)).padStart(4, '0')}`;

async function answer(extra: Record<string, unknown> = {}) {
  const kyaos = await createMiddleware({ session: { sessionTtlMinutes: 30 } });
  const result = await kyaos.handleHandshake({
    nonce: nonce(),
    audience: kyaos.identity.did,
    timestamp: Math.floor(Date.now() / 1000),
    ...extra,
  });
  return { kyaos, result, body: JSON.parse(result.content[0]!.text) as Record<string, unknown> };
}

describe('the handshake response', () => {
  it('states the session, the server, the version and the lifetime in seconds, valid under the schema', async () => {
    const { kyaos, result, body } = await answer();
    expect(result.isError).toBeUndefined();
    expect(body).toEqual({
      success: true,
      sessionId: expect.stringMatching(/^kyaos_/),
      serverDid: kyaos.identity.did,
      serverKid: kyaos.identity.kid,
      protocolVersion: '1.0',
      sessionTtl: 1800,
    });
    expect(validResponse(body), JSON.stringify(validResponse.errors)).toBe(true);
  });

  it('states the version it speaks in a refusal too', async () => {
    const { body } = await answer({ timestamp: 1 });
    expect(body).toMatchObject({ success: false, protocolVersion: '1.0', error: { code: 'handshake_failed' } });
  });
});

describe('the protocol version a handshake states', () => {
  it.each(['1.0', '1.7', '1.0.0'])('accepts %s', async (stated) => {
    const { body } = await answer({ clientProtocolVersion: stated });
    expect(body.success).toBe(true);
  });

  it('accepts a handshake that states none, as one of 1.0', async () => {
    expect((await answer()).body.success).toBe(true);
  });

  it.each(['2.0', '0.9', '2.0.0'])('refuses %s, of another major version', async (stated) => {
    const { result, body } = await answer({ clientProtocolVersion: stated });
    expect(result.isError).toBe(true);
    expect(body).toMatchObject({ success: false, protocolVersion: '1.0', error: { code: 'protocol_version_unsupported' } });
  });

  it.each(['2026-07-28', 'not-a-version', '1', '1.x', '1.0.0.0', '', 1])(
    'reads %j, which is not a version, as none for the 1.x line',
    async (stated) => {
      expect((await answer({ clientProtocolVersion: stated })).body.success).toBe(true);
    },
  );

  it('is checked before the nonce, so a refused handshake spends none', async () => {
    const kyaos = await createMiddleware();
    const request = { nonce: nonce(), audience: kyaos.identity.did, timestamp: Math.floor(Date.now() / 1000) };
    await kyaos.handleHandshake({ ...request, clientProtocolVersion: '2.0' });
    const retried = JSON.parse((await kyaos.handleHandshake({ ...request, clientProtocolVersion: '1.0' })).content[0]!.text);
    expect(retried.success).toBe(true);
  });

  it('is checked before the rest of the request is read', async () => {
    const kyaos = await createMiddleware();
    const result = await kyaos.handleHandshake({ nonce: nonce(), audience: kyaos.identity.did, clientProtocolVersion: '2.0' });
    expect(JSON.parse(result.content[0]!.text).error.code).toBe('protocol_version_unsupported');
  });

  it('is declared by both protocol tools, so an MCP SDK passes it on', async () => {
    const kyaos = await createMiddleware();
    expect(Object.keys(kyaos.kyaOsTool.inputSchema.properties)).toContain('clientProtocolVersion');
    expect(Object.keys(kyaos.handshakeTool.inputSchema.properties)).toContain('clientProtocolVersion');
  });

  it('reaches the server through the _kyaos tool withKyaOs registers', async () => {
    const crypto = new NodeCryptoProvider();
    const server = new McpServer({ name: 'version-test', version: '1.0.0' });
    const kyaos = await withKyaOs(server, { crypto });
    const [clientEnd, serverEnd] = InMemoryTransport.createLinkedPair();
    await server.connect(serverEnd);
    const client = new Client({ name: 'version-client', version: '1.0.0' });
    await client.connect(clientEnd);
    try {
      const result = await client.callTool({
        name: '_kyaos',
        arguments: { action: 'handshake', nonce: nonce(), audience: kyaos.identity.did, timestamp: Math.floor(Date.now() / 1000), clientProtocolVersion: '2.0' },
      });
      const content = result.content as Array<{ text: string }>;
      expect(JSON.parse(content[0]!.text).error.code).toBe('protocol_version_unsupported');
    } finally {
      await client.close();
    }
  });

  it('is advertised with a type for every input of the _kyaos tool, clientProtocolVersion a string, so no client refuses the tool', async () => {
    const crypto = new NodeCryptoProvider();
    const server = new McpServer({ name: 'version-test', version: '1.0.0' });
    await withKyaOs(server, { crypto });
    const [clientEnd, serverEnd] = InMemoryTransport.createLinkedPair();
    await server.connect(serverEnd);
    const client = new Client({ name: 'version-client', version: '1.0.0' });
    await client.connect(clientEnd);
    try {
      const kyaosTool = (await client.listTools()).tools.find((tool) => tool.name === '_kyaos')!;
      const properties = kyaosTool.inputSchema.properties as Record<string, Record<string, unknown>>;
      expect(properties.clientProtocolVersion).toMatchObject({ type: 'string' });
      for (const [name, property] of Object.entries(properties)) {
        expect([name, property.type ?? property.enum]).not.toEqual([name, undefined]);
      }
    } finally {
      await client.close();
    }
  });

  it('reaches the server as a value that is not a string, which the 1.x line reads as none', async () => {
    const crypto = new NodeCryptoProvider();
    const server = new McpServer({ name: 'version-test', version: '1.0.0' });
    const kyaos = await withKyaOs(server, { crypto });
    const [clientEnd, serverEnd] = InMemoryTransport.createLinkedPair();
    await server.connect(serverEnd);
    const client = new Client({ name: 'version-client', version: '1.0.0' });
    await client.connect(clientEnd);
    try {
      const result = await client.callTool({
        name: '_kyaos',
        arguments: { action: 'handshake', nonce: nonce(), audience: kyaos.identity.did, timestamp: Math.floor(Date.now() / 1000), clientProtocolVersion: 1 },
      });
      const content = result.content as Array<{ text: string }>;
      expect(JSON.parse(content[0]!.text).success).toBe(true);
    } finally {
      await client.close();
    }
  });

  it('is the one the identity action states', async () => {
    const kyaos = await createMiddleware();
    const identity = JSON.parse((await kyaos.handleKyaOs({ action: 'identity' })).content[0]!.text);
    expect(identity.protocolVersion).toBe('1.0');
  });
});

describe('the published handshake request schema', () => {
  const request = { nonce: 'k7Hy9mNpQrStUvWxYz01Aa', audience: 'did:web:example.com', timestamp: 1710268800 };

  it('takes the three-part version 1.x clients send', () => {
    expect(validRequest({ ...request, clientProtocolVersion: '1.0.0' })).toBe(true);
  });

  it('takes an agent DID of any method', () => {
    expect(validRequest({ ...request, agentDid: 'did:cheqd:mainnet:7bf81a20-633c-4cc7-bc4a-5a45801005e0' })).toBe(true);
  });
});
