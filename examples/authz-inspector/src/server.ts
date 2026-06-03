/**
 * Authorization-server demo — MCP Inspector ready.
 *
 * A minimal MCP server with one protected tool, `read_vault`, gated by the
 * `@kya-os/mcp/authz` seam. The caller only ever handles one value, a
 * `resume_token`:
 *
 *   - call read_vault with no args → a `needs_authorization` challenge: an
 *     authorize URL to open, and a resume_token
 *   - approve in the browser → the server completes the OAuth + PKCE exchange
 *     itself and caches the grant under the resume_token
 *   - re-call read_vault { resume_token } → the cached grant is auto-applied and
 *     the vault reads
 *
 * No authorization code, state, or PKCE verifier is ever surfaced to the
 * caller — the OAuth plumbing stays server-side, mirroring the consent-full
 * "approve once, retry once" pattern. The authorization logic is the tested
 * seam (GenericOidcAdapter + AuthorizationServerRegistry, via the session).
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
} from '@modelcontextprotocol/sdk/types.js';
import type { VerifyDelegationResult } from '@kya-os/mcp';
import type { AuthzSession } from './session.js';
import { READ_VAULT_PROTECTION } from './session.js';

export interface ToolResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

export interface AuthzInspectorServerOptions {
  /** The shared authorization session (challenge + grant store). */
  session: AuthzSession;
  /** The agent DID the demo acts as. */
  agentDid?: string;
  /** The authorization server's callback URI (where Approve redirects). */
  callbackUri: string;
  /** Whether the authorize URL is a real, visitable page. */
  visitable?: boolean;
}

/**
 * Build the demo MCP server plus the bound tool handler. Returning the handler
 * lets a test drive it directly while the same instance is mounted on the
 * server for Inspector.
 */
export function createAuthzInspectorMcpServer(
  options: AuthzInspectorServerOptions,
): { server: Server; readVault: (args: Record<string, unknown>, extra?: { sessionId?: string }) => Promise<ToolResult> } {
  const { session } = options;
  const agentDid = options.agentDid ?? 'did:key:zDemoAgent';

  function vaultResult(grant: VerifyDelegationResult): ToolResult {
    return {
      content: [
        {
          type: 'text',
          text:
            `Vault read authorized for ${grant.credential?.agent_did} ` +
            `(scopes: ${grant.credential?.scopes.join(', ')}).\n` +
            `Contents: [ "note-1.md", "note-2.md" ]`,
        },
      ],
    };
  }

  /** Does the connected client support URL-mode elicitation? */
  function clientSupportsElicitation(): boolean {
    const caps = server.getClientCapabilities();
    return Boolean(caps && (caps as { elicitation?: unknown }).elicitation);
  }

  const readVault = async (
    args: Record<string, unknown>,
    extra?: { sessionId?: string },
  ): Promise<ToolResult> => {
    const resumeToken = typeof args['resume_token'] === 'string' ? (args['resume_token'] as string) : undefined;
    const sessionId = extra?.sessionId;

    // 1. Already authorized for this SESSION → auto-apply, no token to paste.
    if (sessionId) {
      const sessionGrant = session.grantForSession(sessionId, READ_VAULT_PROTECTION.toolName);
      if (sessionGrant?.valid) return vaultResult(sessionGrant);
    }
    // 1b. Explicit resume_token (stateless fallback) → auto-apply.
    if (resumeToken) {
      const grant = session.grantFor(resumeToken);
      if (grant?.valid) return vaultResult(grant);
    }

    // Restate a still-pending challenge for a known token, or issue a fresh one
    // (bound to this session). Reusing the pending challenge means a
    // retry-before-approval does not invalidate the token the user holds.
    const challenge =
      (resumeToken ? session.pendingFor(resumeToken) : undefined) ??
      (await session.challenge(READ_VAULT_PROTECTION, agentDid, options.callbackUri, sessionId));

    // 2. Progressive enhancement: if the client supports elicitation, ask it to
    //    open the authorize URL and wait — resolving in this single call.
    if (clientSupportsElicitation()) {
      try {
        const elicit = await server.elicitInput({
          message: `Authorize read_vault (scopes: ${challenge.scopes.join(', ')}).`,
          mode: 'url',
          url: challenge.authorizationUrl,
        } as Parameters<Server['elicitInput']>[0]);
        if ((elicit as { action?: string }).action === 'accept') {
          const grant =
            (sessionId ? session.grantForSession(sessionId, READ_VAULT_PROTECTION.toolName) : undefined) ??
            session.grantFor(challenge.resumeToken);
          if (grant?.valid) return vaultResult(grant);
        }
        // Declined/cancelled, or grant not yet recorded → fall through to guidance.
      } catch {
        // Elicitation failed at runtime → degrade gracefully to the link flow.
      }
    }

    // 3. Graceful degradation: a clickable link + the no-paste retry (session
    //    binding) or, for a stateless client, the explicit resume_token.
    const linkLine = options.visitable
      ? `1. Approve here: [Approve read_vault](${challenge.authorizationUrl})\n   (or open the URL: ${challenge.authorizationUrl})\n\n`
      : `1. (In-memory demo: there is no page to visit; approval is simulated.)\n\n`;
    const retryLine = sessionId
      ? `2. Then just re-run read_vault (no arguments needed) — the approval is applied automatically.`
      : `2. Then re-call read_vault with:  resume_token: ${challenge.resumeToken}`;
    return {
      content: [
        {
          type: 'text',
          text:
            `"read_vault" requires authorization (scopes: ${challenge.scopes.join(', ')}).\n\n` +
            linkLine +
            retryLine,
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
        description:
          'Read the user vault. Protected: returns an authorization challenge on first call; ' +
          'approve in the browser, then re-call with the resume_token.',
        inputSchema: {
          type: 'object',
          properties: {
            resume_token: {
              type: 'string',
              description: 'The resume token from the needs_authorization challenge (omit on the first call).',
            },
          },
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request, extra): Promise<CallToolResult> => {
    const { name, arguments: args = {} } = request.params;
    const result =
      name === 'read_vault'
        ? await readVault(args as Record<string, unknown>, { sessionId: extra?.sessionId })
        : { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
    return result as CallToolResult;
  });

  return { server, readVault };
}
