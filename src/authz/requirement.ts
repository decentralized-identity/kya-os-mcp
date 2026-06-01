import { z } from 'zod';

/**
 * Authorization requirement vocabulary.
 *
 * An {@link AuthorizationRequirement} describes *what kind* of authorization a
 * tool needs, independent of any concrete authorization server. It is the
 * neutral input an {@link AuthorizationServerAdapter} dispatches on — the same
 * separation the policy layer draws between a neutral request and a pluggable
 * engine. Concrete adapters (a generic-OIDC reference adapter ships in this
 * package; vendor adapters live downstream) implement the behavior for a given
 * `type`.
 *
 * The variants mirror the authorization methods the protocol anticipates:
 * `oauth` (an authorization-code/OIDC flow), `mdl` (an ISO mDL presentation),
 * `idv` (an identity-verification flow), `credential` (a directly held
 * verifiable credential), and `none` (no authorization required).
 */
const oauthRequirement = z.object({
  type: z.literal('oauth'),
  /** The provider id an adapter registry resolves to a concrete adapter. */
  provider: z.string().min(1),
  /** Scopes the flow must obtain; omitted means the adapter's default set. */
  requiredScopes: z.array(z.string()).optional(),
});

const mdlRequirement = z.object({ type: z.literal('mdl') });
const idvRequirement = z.object({ type: z.literal('idv') });
const credentialRequirement = z.object({ type: z.literal('credential') });
const noneRequirement = z.object({ type: z.literal('none') });

export const AuthorizationRequirementSchema = z.discriminatedUnion('type', [
  oauthRequirement,
  mdlRequirement,
  idvRequirement,
  credentialRequirement,
  noneRequirement,
]);

export type AuthorizationRequirement = z.infer<typeof AuthorizationRequirementSchema>;

/**
 * Binds a tool to the authorization it requires. The PEP consults the
 * requirement before dispatching a tool, and an adapter turns an unmet
 * requirement into a `needs_authorization` challenge.
 */
export const ToolProtectionSchema = z.object({
  toolName: z.string().min(1),
  requirement: AuthorizationRequirementSchema,
});

export type ToolProtection = z.infer<typeof ToolProtectionSchema>;
