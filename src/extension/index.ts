/**
 * KYA-OS MCP extension negotiation (`org.kya-os/decentralized-authority`).
 *
 * The MCP binding surface of SPEC-MCP-EXTENSION.md: the extension id and
 * settings object (§1, §3), the declaration reader for both carriage forms
 * (§3.1), the admission gate with core `-32021` required-mode enforcement
 * (§4), and the JSON-RPC error mapping that keeps snake_case reason codes as
 * the dispatch surface (§5). Strictly additive: nothing here runs unless the
 * host opts in.
 */

export {
  KYA_OS_EXTENSION_ID,
  MCP_CLIENT_CAPABILITIES_META_KEY,
  MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
  EXTENSION_NOT_DECLARED_REASON,
  ExtensionSettingsSchema,
  DEFAULT_EXTENSION_SETTINGS,
  parseExtensionSettings,
  resolveExtensionSettings,
  buildExtensionSettings,
  buildExtensionsEntry,
  type KyaOsExtensionSettings,
  type ResolvedExtensionSettings,
} from './settings.js';

export {
  readExtensionDeclaration,
  type DeclarationCarriage,
  type ExtensionDeclaration,
  type ReadDeclarationInput,
} from './declaration.js';

export {
  KYA_OS_DOMAIN_ERROR_CODE,
  requireExtension,
  missingRequiredCapabilityError,
  proofGateToJsonRpcError,
  type ExtensionGateResult,
  type ExtensionGuard,
  type JsonRpcErrorObject,
  type ProofGateErrorLike,
} from './gate.js';
