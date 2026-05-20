import tools from './tools/index.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import pkg from '../package.json' with { type: 'json' };
import { isToolPermittedByUser } from './config.js';
import { type SmitheryConfig, setOptions } from './config.js';
import { withKyaOs, generateIdentity } from '../../../src/middleware/index.js';
import type { KyaOsIdentityConfig } from '../../../src/middleware/index.js';
import { NodeCryptoProvider } from '../../node-server/node-crypto.js';
export { configSchema } from './config.js';

// Shared crypto + identity — generated once, reused across all McpServer instances
const crypto = new NodeCryptoProvider();
let sharedIdentity: KyaOsIdentityConfig | undefined;

type CreateMcpServerOptions = {
  config: SmitheryConfig;
};

export default async function createMcpServer(
  options?: CreateMcpServerOptions
): Promise<McpServer> {
  if (options?.config) setOptions(options.config);

  // Generate identity once on first call
  if (!sharedIdentity) {
    sharedIdentity = await generateIdentity(crypto);
    console.error(`[kya-os] Server DID: ${sharedIdentity.did}`);
  }

  const mcpServer = new McpServer(
    {
      version: pkg.version,
      name: 'brave-search-mcp-server',
      title: 'Brave Search MCP Server',
    },
    {
      capabilities: {
        logging: {},
        tools: { listChanged: false },
      },
      instructions: `Use this server to search the Web for various types of data via the Brave Search API.`,
    }
  );

  // KYA-OS: auto-register handshake + auto-proof all tools (reuses shared identity)
  await withKyaOs(mcpServer, { crypto, identity: sharedIdentity });

  for (const tool of Object.values(tools)) {
    // The user may have enabled/disabled this tool at runtime
    if (!isToolPermittedByUser(tool.name)) continue;
    tool.register(mcpServer);
  }

  return mcpServer;
}
