/**
 * Integration tests for the OAuth Inspector demo server.
 *
 * Drives the real MCP server over an in-memory client transport — the same way
 * MCP Inspector talks to it — and asserts the protected tool returns a
 * needs_authorization challenge when unauthorized and runs once a valid
 * authorization code is supplied. Deterministic and network-free.
 */
import { describe, it, expect } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createOauthInspectorMcpServer, type ToolResult } from '../src/server.js';

async function connectedClient() {
  const { server, readVault } = createOauthInspectorMcpServer();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test-client', version: '1.0.0' });
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
  return { client, readVault };
}

function textOf(result: { content?: Array<{ type: string; text?: string }> }): string {
  return (result.content ?? []).map((c) => c.text ?? '').join('\n');
}

describe('oauth-inspector demo server', () => {
  it('lists the protected read_vault tool', async () => {
    const { client } = await connectedClient();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toContain('read_vault');
  });

  it('returns a needs_authorization challenge when read_vault is called unauthorized', async () => {
    const { client } = await connectedClient();
    const result = (await client.callTool({ name: 'read_vault', arguments: {} })) as ToolResult;
    const text = textOf(result);
    expect(text).toContain('requires authorization');
    expect(text).toContain('code_challenge_method=S256');
    expect(text).toMatch(/resume_token:\s*\S+/);
  });

  it('reads the vault once a valid authorization code is supplied', async () => {
    // Drive the handler directly to thread the resume token from the challenge
    // into the follow-up call (mirrors what an agent does across two tool calls).
    const { readVault } = await connectedClient();
    const challenge = await readVault({});
    const resumeToken = /resume_token:\s*(\S+)/.exec(textOf(challenge))?.[1];
    expect(resumeToken).toBeTruthy();

    const authorized = await readVault({
      authorization_code: 'demo-auth-code',
      resume_token: resumeToken,
      state: 'demo-state',
    });
    const text = textOf(authorized);
    expect(authorized.isError).toBeFalsy();
    expect(text).toContain('Vault read authorized');
    expect(text).toContain('vault:read');
  });

  it('fails closed when the state does not match the challenge', async () => {
    const { readVault } = await connectedClient();
    const challenge = await readVault({});
    const resumeToken = /resume_token:\s*(\S+)/.exec(textOf(challenge))?.[1];

    const result = await readVault({
      authorization_code: 'demo-auth-code',
      resume_token: resumeToken,
      state: 'WRONG-state',
    });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/state/i);
  });
});
