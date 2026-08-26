export {
  ProofGenerator,
  createProofResponse,
  extractCanonicalData,
  computeCanonicalHashes,
  buildProofJwsPayload,
  KYA_OS_PROOF_META_KEY,
  LEGACY_NAMESPACED_PROOF_META_KEY,
  LEGACY_PROOF_META_KEY,
  RESPONSE_PROOF_PROFILE_BODY,
  RESPONSE_PROOF_PROFILE_ENVELOPE,
  type ProofAgentIdentity,
  type ToolRequest,
  type ToolResponse,
  type ProofOptions,
  type ResponseProofProfile,
} from './generator.js';

export {
  ProofVerifier,
  validateMetaStructure,
  extractProofFromMeta,
  DEFAULT_CLOCK_SKEW_SECONDS,
  MIN_CLOCK_SKEW_SECONDS,
  MAX_CLOCK_SKEW_SECONDS,
  type ProofVerifierConfig,
  type ProofVerificationResult,
} from './verifier.js';

export {
  ProofVerificationError,
  PROOF_VERIFICATION_ERROR_CODES,
  createProofVerificationError,
  type ProofVerificationErrorCode,
} from './errors.js';
