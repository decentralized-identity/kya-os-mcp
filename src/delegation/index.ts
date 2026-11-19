/**
 * Delegation Module Exports (Platform-Agnostic)
 *
 * W3C VC-based delegation issuance and verification.
 * Platform-specific adapters (Node.js, Cloudflare) provide signing/verification functions.
 */

export * from './vc-issuer.js';
export * from './vc-verifier.js';
export { REFUSAL_CODES, isRefusalCode, isTransientRefusal, type RefusalCode } from '../refusal-codes.js';
export { RefusalError } from '../utils/refusal.js';
export * from './status-cache.js';
export * from './verification-method-key.js';
export * from './vc-jwt-verify.js';
export * from './bitstring.js';
export { statusListGzipCodec } from '../utils/statuslist-gzip.js';
export {
  acceptEntrySize,
  acceptStatusList,
  statusListExpectationFor,
  statusListKeeperFor,
  type StatusCheckContext,
  type StatusListExpectation,
  type StatusListIssuers,
  type StatusListKeeper,
  type StatusListVerdict,
} from '../utils/statuslist-acceptance.js';
export { acceptStatusListValidity } from '../utils/statuslist-validity.js';
export * from './statuslist-manager.js';
export type {
  StatusEntryAllocationOptions,
  StatusEntryOwner,
  StatusEntryOwners,
  StatusEntryOwnerStorageProvider,
} from './status-entry-owner.js';
export * from './delegation-graph.js';
export * from './cascading-revocation.js';
export * from './utils.js';
export * from './outbound-proof.js';
export * from './outbound-headers.js';
export * from './audience-validator.js';
export * from './scope-matcher.js';
export * from './holder-binding.js';
export * from './chain-enforcement.js';
export {
  delegationCredentialDigest,
  delegationChainDigest,
  digestDelegationChain,
  DELEGATION_CREDENTIAL_DIGEST_DOMAIN,
  DELEGATION_CHAIN_DIGEST_DOMAIN,
  type DelegationChainDigests,
  type ReceivedCredential,
  type Sha256,
} from './chain-digest.js';
export * from './delegation-ref.js';
export {
  signedForm,
  signingInput,
  NoSignedFormError,
  MAX_CREDENTIAL_NESTING_DEPTH,
  type SignedForm,
  type SignedCredential,
  type SignedJwt,
} from './signed-form.js';
export * from './did-resolver-registry.js';
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
export {
  verifyDidLinkage,
  type DidLinkageVerificationResult,
  type VerifyDidLinkageOptions,
} from './did-linkage.js';
export { MemoryStatusListStorage } from './storage/memory-statuslist-storage.js';
export { MemoryDelegationGraphStorage } from './storage/memory-graph-storage.js';
