/**
 * Authorization-server and protected-resource metadata assembly (RFC 8414 and
 * RFC 9728). Pure: shapes the metadata objects from configuration, no network.
 * S256-only PKCE is advertised unconditionally.
 */

export interface AuthorizationServerMetadataInput {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  scopesSupported?: string[];
  /** Defaults to ['code'] (authorization-code only). */
  responseTypesSupported?: string[];
  /** Defaults to ['authorization_code', 'refresh_token']. */
  grantTypesSupported?: string[];
  jwksUri?: string;
  revocationEndpoint?: string;
}

/** RFC 8414 Authorization Server Metadata (S256-only PKCE). */
export interface AuthorizationServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  response_types_supported: string[];
  grant_types_supported: string[];
  code_challenge_methods_supported: ['S256'];
  scopes_supported?: string[];
  jwks_uri?: string;
  revocation_endpoint?: string;
}

export function buildAuthorizationServerMetadata(
  input: AuthorizationServerMetadataInput,
): AuthorizationServerMetadata {
  const metadata: AuthorizationServerMetadata = {
    issuer: input.issuer,
    authorization_endpoint: input.authorizationEndpoint,
    token_endpoint: input.tokenEndpoint,
    response_types_supported: input.responseTypesSupported ?? ['code'],
    grant_types_supported: input.grantTypesSupported ?? ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
  };
  if (input.scopesSupported) metadata.scopes_supported = input.scopesSupported;
  if (input.jwksUri) metadata.jwks_uri = input.jwksUri;
  if (input.revocationEndpoint) metadata.revocation_endpoint = input.revocationEndpoint;
  return metadata;
}

export interface ProtectedResourceMetadataInput {
  resource: string;
  authorizationServers: string[];
  scopesSupported?: string[];
}

/** RFC 9728 Protected Resource Metadata. */
export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  scopes_supported?: string[];
}

export function buildProtectedResourceMetadata(
  input: ProtectedResourceMetadataInput,
): ProtectedResourceMetadata {
  const metadata: ProtectedResourceMetadata = {
    resource: input.resource,
    authorization_servers: input.authorizationServers,
  };
  if (input.scopesSupported) metadata.scopes_supported = input.scopesSupported;
  return metadata;
}
