/**
 * KYA-OS Middleware
 *
 * Primary entry point: `withKyaOs(server, { crypto })` — adds identity,
 * handshake, and auto-proofs to any McpServer instance in one call.
 *
 * For the low-level `Server` API or custom patterns, use `createKyaOsMiddleware` directly.
 */

export {
  createKyaOsMiddleware,
  type KyaOsConfig,
  type KyaOsDelegationConfig,
  type KyaOsIdentityConfig,
  type KyaOsMiddleware,
  type KyaOsToolDefinition,
  type KyaOsToolHandler,
  type KyaOsServer,
} from './with-kya-os.js';

export {
  withKyaOs,
  generateIdentity,
  type WithKyaOsOptions,
} from './with-kya-os-server.js';

export {
  createKyaOsTransport,
  type Transport,
  type JSONRPCMessage,
} from './kya-os-transport.js';
