/**
 * Authorization-server demo — MCP Inspector ready.
 *
 * A minimal MCP server with one protected tool, `read_vault`, gated by the
 * `@kya-os/mcp/authz` authorization seam. When an agent calls the tool without
 * authorization, the server returns the `needs_authorization` challenge the
 * adapter produces — the authorize URL, scopes, and a resume token — which MCP
 * Inspector renders as an actionable prompt. Supplying the returned
 * authorization code completes the flow and the tool runs.
 *
 * The authorization logic is the tested seam (GenericOidcAdapter +
 * AuthorizationServerRegistry); this file is only the thin MCP shell over it.
 * The token exchange is backed by an in-memory provider so the demo is
 * deterministic and runs with no external identity provider or network.
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
} from '@modelcontextprotocol/sdk/types.js';
import {
  AuthorizationServerRegistry,
  GenericOidcAdapter,
  type FetchImpl,
  type ToolProtection,
} from '@kya-os/mcp/authz';

export interface ToolResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

const READ_VAULT_PROTECTION: ToolProtection = {
  toolName: 'read_vault',
  requirement: { type: 'oauth', provider: 'generic-oidc', requiredScopes: ['vault:read'] },
};

/**
 * An in-memory token endpoint standing in for a live OIDC provider, so the demo
 * is deterministic and network-free. Returns the granted scopes for any
 * well-formed authorization-code exchange.
 */
export function inMemoryTokenEndpoint(grantedScopes: string[]): FetchImpl {
  return async (url, init) => {
    if (url !== 'memory://idp/token') {
      throw new Error(`unexpected external call to ${url}`);
    }
    const body = String(init?.body ?? '');
    if (!body.includes('grant_type=authorization_code') || !body.includes('code_verifier=')) {
      return new Response('invalid_request', { status: 400 });
    }
    return new Response(
      JSON.stringify({ access_token: 'demo-access-token', token_type: 'Bearer', scope: grantedScopes.join(' ') }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  };
}

/** Build the registry holding the generic-OIDC reference adapter for the demo. */
export function createDemoRegistry(fetchImpl: FetchImpl = inMemoryTokenEndpoint(['vault:read'])): {
  registry: AuthorizationServerRegistry;
  adapter: GenericOidcAdapter;
} {
  const adapter = new GenericOidcAdapter({
    type: 'oauth',
    issuer: 'memory://idp',
    authorizationEndpoint: 'memory://idp/authorize',
    tokenEndpoint: 'memory://idp/token',
    clientId: 'oauth-inspector-demo',
    scopes: ['vault:read'],
    resource: 'memory://resource/vault',
    fetchImpl,
  });
  const registry = new AuthorizationServerRegistry();
  registry.register(adapter);
  registry.seal();
  return { registry, adapter };
}

/**
 * Build the demo MCP server plus the bound tool handler. Returning the handler
 * lets a test drive it directly while the same instance is mounted on the
 * server for Inspector.
 */
export function createAuthzInspectorMcpServer(
  agentDid = 'did:key:zDemoAgent',
  fetchImpl?: FetchImpl,
): { server: Server; readVault: (args: Record<string, unknown>) => Promise<ToolResult> } {
  const { registry } = createDemoRegistry(fetchImpl);

  const readVault = async (args: Record<string, unknown>): Promise<ToolResult> => {
    const adapter = registry.resolve(READ_VAULT_PROTECTION);
    if (!adapter) {
      return { content: [{ type: 'text', text: 'read_vault is misconfigured: no adapter.' }], isError: true };
    }

    const code = typeof args['authorization_code'] === 'string' ? (args['authorization_code'] as string) : undefined;
    const resumeToken = typeof args['resume_token'] === 'string' ? (args['resume_token'] as string) : undefined;
    const state = typeof args['state'] === 'string' ? (args['state'] as string) : undefined;

    // Unauthorized call → produce the needs_authorization challenge.
    if (!code || !resumeToken || !state) {
      const challenge = await adapter.initiateFlow({
        protection: READ_VAULT_PROTECTION,
        agentDid,
        redirectUri: 'memory://app/callback',
        state: 'demo-state',
      });
      return {
        content: [
          {
            type: 'text',
            text:
              `"read_vault" requires authorization (scopes: ${challenge.scopes.join(', ')}).\n\n` +
              `1. Visit the authorization URL:\n   ${challenge.authorizationUrl}\n\n` +
              `2. Re-call read_vault with:\n` +
              `   resume_token: ${challenge.resumeToken}\n` +
              `   state: demo-state\n` +
              `   authorization_code: <the code the provider returns>  (demo accepts: demo-auth-code)`,
          },
        ],
      };
    }

    // Authorized call → verify and run.
    const result = await adapter.verifyAuthorization(resumeToken, { code, state });
    if (!result.valid) {
      return { content: [{ type: 'text', text: `Authorization failed: ${result.reason ?? 'unknown'}` }], isError: true };
    }
    return {
      content: [
        {
          type: 'text',
          text:
            `Vault read authorized for ${result.credential?.agent_did} ` +
            `(scopes: ${result.credential?.scopes.join(', ')}).\n` +
            `Contents: [ "note-1.md", "note-2.md" ]`,
        },
      ],
    };
  };

  const server = new Server(
    { name: 'kya-os-authz-inspector', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'read_vault',
        description: 'Read the user vault. Protected: requires an OAuth authorization flow.',
        inputSchema: {
          type: 'object',
          properties: {
            authorization_code: { type: 'string', description: 'Code returned by the authorization server' },
            resume_token: { type: 'string', description: 'Resume token from the needs_authorization challenge' },
            state: { type: 'string', description: 'State echoed from the challenge' },
          },
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
    const { name, arguments: args = {} } = request.params;
    const result =
      name === 'read_vault'
        ? await readVault(args as Record<string, unknown>)
        : { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
    return result as CallToolResult;
  });

  return { server, readVault };
}
