/**
 * Integration tests for the demo MCP server over an in-memory client transport
 * (the stdio path's behavior). Drives the real MCP server and asserts the
 * one-token flow: an unauthorized call returns a challenge with a resume_token
 * (and no code/state to copy), and re-calling with the resume_token reads the
 * vault. Uses the in-memory session (approval simulated), so it is deterministic
 * and network-free.
 */
import { describe, it, expect } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createAuthzInspectorMcpServer, type ToolResult } from '../src/server.js';
import { createInMemorySession } from '../src/session-inmemory.js';

async function connected() {
  const session = createInMemorySession(['vault:read']);
  const { server, readVault } = createAuthzInspectorMcpServer({
    session,
    callbackUri: 'memory://app/callback',
    visitable: false,
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test-client', version: '1.0.0' });
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
  return { client, readVault };
}

function textOf(result: { content?: Array<{ type: string; text?: string }> }): string {
  return (result.content ?? []).map((c) => c.text ?? '').join('\n');
}

describe('authz-inspector demo server (in-memory session)', () => {
  it('lists the protected read_vault tool', async () => {
    const { client } = await connected();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toContain('read_vault');
  });

  it('returns a challenge with a resume_token and no code/state to copy', async () => {
    const { client } = await connected();
    const result = (await client.callTool({ name: 'read_vault', arguments: {} })) as ToolResult;
    const text = textOf(result);
    expect(text).toContain('requires authorization');
    expect(text).toMatch(/resume_token:\s*\S+/);
    expect(text).not.toContain('authorization_code:');
  });

  it('reads the vault when re-called with only the resume_token', async () => {
    const { readVault } = await connected();
    const challenge = await readVault({});
    const resumeToken = /resume_token:\s*(\S+)/.exec(textOf(challenge))?.[1];
    expect(resumeToken).toBeTruthy();

    const authorized = await readVault({ resume_token: resumeToken });
    expect(authorized.isError).toBeFalsy();
    const text = textOf(authorized);
    expect(text).toContain('Vault read authorized');
    expect(text).toContain('vault:read');
  });
});
