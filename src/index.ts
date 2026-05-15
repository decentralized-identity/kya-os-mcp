/**
 * @kya-os/mcp — MCP-I Protocol Reference Implementation
 *
 * Delegation, proof, and session for Model Context Protocol Identity.
 * This package is a DIF TAAWG protocol reference implementation.
 *
 * Related Spec: https://modelcontextprotocol-identity.io
 *
 * ## Error handling strategy
 *
 * - **Validation functions** (`verify*`, `validate*`) return result objects `{ valid, reason }` — never throw
 * - **Construction/setup functions** throw `Error` on invalid configuration
 * - **Resolution functions** (`resolve*`, `fetch*`) return `null` on failure — never throw
 *
 * This ensures callers can always handle failures without try/catch on validation paths.
 */

// Error contract
export {
  MCPI_ERROR_CODES,
  createMCPIError,
  type MCPIErrorCode,
  type MCPIErrorResponse,
} from './errors.js';

// Protocol types
export type {
  DelegationConstraints,
  DelegationRecord,
  DelegationCredential,
  DelegationStatus,
  CredentialStatus,
  StatusList2021Credential,
  Proof,
  HandshakeRequest,
  SessionContext,
  NonceCache,
  MCPClientInfo,
  MCPClientSessionInfo,
  SessionIdentityState,
  DetachedProof,
  ProofMeta,
  CanonicalHashes,
  AuditRecord,
  AuditContext,
  AuditEventContext,
  NeedsAuthorizationError,
  AuthorizationDisplay,
  CrispBudget,
  CrispScope,
} from './types/protocol.js';

export {
  wrapDelegationAsVC,
  extractDelegationFromVC,
  isDelegationCredentialExpired,
  isDelegationCredentialNotYetValid,
  validateDelegationCredential,
  validateDetachedProof,
  createNeedsAuthorizationError,
  isNeedsAuthorizationError,
  DELEGATION_CREDENTIAL_CONTEXT,
  DEFAULT_SESSION_TTL_MINUTES,
  DEFAULT_TIMESTAMP_SKEW_SECONDS,
  NONCE_LENGTH_BYTES,
} from './types/protocol.js';

// Delegation module
export {
  DelegationCredentialIssuer,
  createDelegationIssuer,
  type IssueDelegationOptions,
  type VCSigningFunction,
  type IdentityProvider as DelegationIdentityProvider,
} from './delegation/vc-issuer.js';

export {
  DelegationCredentialVerifier,
  createDelegationVerifier,
  type DelegationVCVerificationResult,
  type VerifyDelegationVCOptions,
  type DIDResolver,
  type DIDDocument,
  type VerificationMethod,
  type StatusListResolver,
  type SignatureVerificationFunction,
} from './delegation/vc-verifier.js';

export {
  DelegationGraphManager,
  createDelegationGraph,
  type DelegationNode,
  type DelegationGraphStorageProvider,
} from './delegation/delegation-graph.js';

export {
  StatusList2021Manager,
  createStatusListManager,
  type StatusListStorageProvider,
  type StatusListIdentityProvider,
} from './delegation/statuslist-manager.js';

export {
  CascadingRevocationManager,
  createCascadingRevocationManager,
  type RevocationEvent,
  type RevocationHook,
  type CascadingRevocationOptions,
} from './delegation/cascading-revocation.js';

export {
  BitstringManager,
  isIndexSet,
  type CompressionFunction,
  type DecompressionFunction,
} from './delegation/bitstring.js';

export {
  verifyDelegationAudience,
} from './delegation/audience-validator.js';

export {
  buildDelegationProofJWT,
  buildChainString,
  type DelegationProofOptions,
  type Ed25519PrivateJWK,
} from './delegation/outbound-proof.js';

export {
  buildOutboundDelegationHeaders,
  OUTBOUND_HEADER_NAMES,
  type OutboundDelegationContext,
  type OutboundDelegationHeaders,
} from './delegation/outbound-headers.js';

export {
  canonicalizeJSON,
  createUnsignedVCJWT,
  completeVCJWT,
  parseVCJWT,
  type VCJWTHeader,
  type VCJWTPayload,
} from './delegation/utils.js';

export { MemoryStatusListStorage } from './delegation/storage/memory-statuslist-storage.js';

export { MemoryDelegationGraphStorage } from './delegation/storage/memory-graph-storage.js';

export {
  createDidKeyResolver,
  resolveDidKeySync,
  isEd25519DidKey,
  extractPublicKeyFromDidKey,
  publicKeyToJwk,
} from './delegation/did-key-resolver.js';

export {
  DidWebResolver,
  createDidWebResolver,
  isDidWeb,
  parseDidWeb,
  didWebToUrl,
  buildDidWebDocument,
  type BuildDidWebDocumentOptions,
} from './delegation/did-web-resolver.js';

// Utils
export {
  base58Encode,
  base58Decode,
  isValidBase58,
} from './utils/base58.js';

export {
  isValidDid,
  getDidMethod,
  normalizeDid,
  compareDids,
  getServerDid,
  extractAgentId,
  extractAgentSlug,
  generateDidKeyFromBytes,
  generateDidKeyFromBase64,
  didKeyFragment,
} from './utils/did-helpers.js';

// Auth module
export {
  verifyOrHints,
  hasSensitiveScopes,
  MemoryResumeTokenStore,
  type AuthHandshakeConfig,
  type VerifyOrHintsResult,
  type AgentReputation,
  type ResumeTokenStore,
  type UnknownAgentPolicy,
  type DelegationVerifier,
  type VerifyDelegationResult,
} from './auth/index.js';

// Proof module
export {
  ProofGenerator,
  createProofResponse,
  extractCanonicalData,
  type ProofAgentIdentity,
  type ToolRequest,
  type ToolResponse,
  type ProofOptions,
} from './proof/index.js';

export {
  ProofVerifier,
  type ProofVerifierConfig,
  type ProofVerificationResult,
} from './proof/verifier.js';

export {
  ProofVerificationError,
  PROOF_VERIFICATION_ERROR_CODES,
  createProofVerificationError,
  type ProofVerificationErrorCode,
} from './proof/errors.js';

// Session module
export {
  SessionManager,
  createHandshakeRequest,
  validateHandshakeFormat,
  type SessionConfig,
  type HandshakeResult,
} from './session/index.js';

// Providers
export {
  CryptoProvider,
  ClockProvider,
  FetchProvider,
  StorageProvider,
  NonceCacheProvider,
  IdentityProvider,
  type Identity,
  type AgentIdentity,
} from './providers/base.js';

export {
  MemoryStorageProvider,
  MemoryNonceCacheProvider,
  MemoryIdentityProvider,
} from './providers/memory.js';

export { NodeCryptoProvider } from './providers/node-crypto.js';

export {
  createDidKeyIdentity,
  createDidWebIdentity,
  createIdentity,
  type ProvisionedIdentity,
  type CreateIdentityOptions,
  type CreateIdentityMethod,
  type CreateIdentityRequest,
  type CreateDidWebIdentityArgs,
  type CreateDidWebIdentityOptions,
} from './providers/identity-factory.js';

// Middleware
export {
  createMCPIMiddleware,
  type MCPIConfig,
  type MCPIDelegationConfig,
  type MCPIIdentityConfig,
  type MCPIMiddleware,
  type MCPIToolDefinition,
  type MCPIToolHandler,
  type MCPIServer,
  withMCPI,
  generateIdentity,
  type WithMCPIOptions,
} from './middleware/index.js';

// Logging
export {
  logger,
  createDefaultConsoleLogger,
  type Logger,
  type Level,
} from './logging/index.js';

// Ed25519 Constants
export {
  ED25519_PKCS8_DER_HEADER,
  ED25519_SPKI_DER_HEADER_LENGTH,
  ED25519_KEY_SIZE,
} from './utils/index.js';
