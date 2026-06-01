/**
 * Authorization-server seam for KYA-OS.
 *
 * A neutral, pluggable authorization layer mirroring the policy seam: a small
 * port ({@link AuthorizationServerAdapter}), a registry that routes a tool's
 * protection to an adapter, a generic-OIDC reference adapter, and the
 * accountability projection that feeds the policy principal. Concrete vendor
 * adapters (commercial identity providers, an identity-provider plugin) live
 * downstream and bind the same port without changing this core.
 */
export {
  AuthorizationRequirementSchema,
  ToolProtectionSchema,
  type AuthorizationRequirement,
  type ToolProtection,
} from './requirement.js';

export {
  requirementMatchesAdapter,
  type AuthorizationServerAdapter,
  type FlowParams,
} from './adapter.js';

export { buildAuthorizeUrl, type AuthorizeUrlParams } from './authorize.js';

export {
  buildAuthorizationServerMetadata,
  buildProtectedResourceMetadata,
  type AuthorizationServerMetadata,
  type AuthorizationServerMetadataInput,
  type ProtectedResourceMetadata,
  type ProtectedResourceMetadataInput,
} from './metadata.js';

export {
  isS256ChallengeMethod,
  computeS256Challenge,
  verifyS256Challenge,
  type S256,
} from './pkce.js';

export {
  GenericOidcAdapter,
  type GenericOidcAdapterConfig,
  type FetchImpl,
} from './oidc-adapter.js';

export { AuthorizationServerRegistry } from './registry.js';

export {
  projectAccountability,
  accountabilityToPolicyPrincipal,
  type AccountabilityContext,
} from './accountability.js';
