/**
 * Delegation Module Exports (Platform-Agnostic)
 *
 * W3C VC-based delegation issuance and verification.
 * Platform-specific adapters (Node.js, Cloudflare) provide signing/verification functions.
 */

export * from './vc-issuer.js';
export * from './vc-verifier.js';
export * from './bitstring.js';
export * from './statuslist-manager.js';
export * from './delegation-graph.js';
export * from './cascading-revocation.js';
export * from './utils.js';
export * from './outbound-proof.js';
export * from './outbound-headers.js';
export * from './audience-validator.js';
export * from './scope-matcher.js';
export {
  createDidKeyResolver,
  resolveDidKeySync,
  isEd25519DidKey,
  extractPublicKeyFromDidKey,
  publicKeyToJwk,
} from './did-key-resolver.js';
export {
  DidWebResolver,
  createDidWebResolver,
  isDidWeb,
  parseDidWeb,
  didWebToUrl,
  buildDidWebDocument,
} from './did-web-resolver.js';
export { MemoryStatusListStorage } from './storage/memory-statuslist-storage.js';
export { MemoryDelegationGraphStorage } from './storage/memory-graph-storage.js';
