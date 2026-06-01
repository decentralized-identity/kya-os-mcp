/**
 * Stdio entrypoint for the OAuth Inspector demo.
 *
 * Launch with MCP Inspector:
 *   npx @modelcontextprotocol/inspector npx tsx examples/oauth-inspector/src/stdio.ts
 *
 * Then call `read_vault` with no arguments to see the needs_authorization
 * challenge, and re-call it with the returned resume_token + state +
 * authorization_code (the demo accepts `demo-auth-code`) to read the vault.
 */
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createAuthzInspectorMcpServer } from './server.js';

async function main(): Promise<void> {
  const { server } = createAuthzInspectorMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Diagnostics go to stderr so they never corrupt the stdio JSON-RPC stream.
  console.error('[kya-os] OAuth Inspector demo running on stdio. Call "read_vault".');
}

main().catch((error) => {
  console.error('[kya-os] fatal:', error);
  process.exit(1);
});
