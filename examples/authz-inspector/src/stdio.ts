/**
 * Stdio entrypoint for the authz Inspector demo.
 *
 * Launch with MCP Inspector:
 *   npx @modelcontextprotocol/inspector npx tsx examples/authz-inspector/src/stdio.ts
 *
 * stdio has no HTTP server to host a consent page, so it uses an in-memory
 * authorization session: the challenge shows the real OAuth request shape and
 * approval is simulated in-process. The caller experience is the same — call
 * read_vault with no args to get the challenge, then re-call with the
 * resume_token to read the vault. For the genuine browser consent flow, use the
 * Streamable HTTP entrypoint (src/http.ts).
 */
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createAuthzInspectorMcpServer } from './server.js';
import { createInMemorySession } from './session-inmemory.js';

async function main(): Promise<void> {
  const session = createInMemorySession(['vault:read']);
  const { server } = createAuthzInspectorMcpServer({
    session,
    callbackUri: 'memory://app/callback',
    visitable: false,
  });
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Diagnostics go to stderr so they never corrupt the stdio JSON-RPC stream.
  console.error('[kya-os] authz Inspector demo running on stdio. Call "read_vault".');
}

main().catch((error) => {
  console.error('[kya-os] fatal:', error);
  process.exit(1);
});
