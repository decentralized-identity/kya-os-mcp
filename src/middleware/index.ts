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

// Entity Card DevX surface — the 10-minute adoption path. The fluent `card()` builder and the
// `withKyaOsCard` / `requireProof` wrappers hide the RFC 9421/9449/8785 machinery behind
// ergonomics (see `src/card/builder.ts` + `src/card/middleware.ts`).
export {
  card,
  CardBuilder,
  type CardBuilderInit,
  type AccountableToOptions,
  type VcInput,
} from '../card/builder.js';

export {
  withKyaOsCard,
  requireProof,
  readCardProof,
  type KyaOsCardMount,
  type ServerJsonLike,
  type DidDocumentLike,
  type ProofGuard,
  type ProofGateResult,
  type ProofGateError,
  type ProofGateCode,
  type RequireProofOptions,
  type MinProofLevel,
} from '../card/middleware.js';
