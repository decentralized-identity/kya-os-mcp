/**
 * KYA-OS MCP extension negotiation - identifiers and the settings object
 * (SPEC-MCP-EXTENSION.md §1, §3; wire schema: `schemas/mcp-extension-settings.json`).
 *
 * The extension is declared under `capabilities.extensions["org.kya-os/decentralized-authority"]`
 * as a small settings object. Per SEP-2133 an empty object means "supported, with
 * default configuration". Every identifier lives here as a single constant
 * (mirroring `KYA_OS_PROOF_META_KEY`), so a future re-pointing of the extension id
 * (SEP-2133 graduation) is a constant change, never a call-site sweep.
 */

import { z } from 'zod';
import { PROOF_PROFILE_ID } from '../card/schema.js';

/** The proposed reverse-DNS MCP extension id (SPEC-MCP-EXTENSION.md §1.1). */
export const KYA_OS_EXTENSION_ID = 'org.kya-os/decentralized-authority';

/** The per-request `_meta` key carrying MCP `ClientCapabilities` (SEP-2575, stateless carriage). */
export const MCP_CLIENT_CAPABILITIES_META_KEY = 'io.modelcontextprotocol/clientCapabilities';

/** Core MCP `MissingRequiredClientCapabilityError` code (2026-07-28 error allocation policy). */
export const MISSING_REQUIRED_CLIENT_CAPABILITY_CODE = -32021;

/**
 * The reason codes this extension defines itself (SPEC-MCP-EXTENSION.md §5.2),
 * each riding the `data.reason` member of a core JSON-RPC error:
 * `extension_not_declared` inside a `-32021` (required mode, no declaration) and
 * `malformed_declaration` inside a `-32602` (required mode, a present-but-
 * unparseable declaration). Every other reason code is defined by
 * SPEC-ENTITY-CARD Appendix D or SPEC.md Appendix A.
 */
export const EXTENSION_NOT_DECLARED_REASON = 'extension_not_declared';
export const MALFORMED_DECLARATION_REASON = 'malformed_declaration';

const SEMVER = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;
const DID_METHOD = /^did:[a-z0-9]+$/;

const unique = (values: readonly string[]): boolean => new Set(values).size === values.length;

/**
 * Zod mirror of `schemas/mcp-extension-settings.json`: every member OPTIONAL,
 * unknown members tolerated (and stripped on parse) for forward compatibility.
 * `required` is meaningful only on a server declaration and ignored client-side
 * (SPEC-MCP-EXTENSION.md §3.2).
 */
export const ExtensionSettingsSchema = z.object({
  version: z.string().regex(SEMVER, 'version must be a semver string').optional(),
  proofProfiles: z
    .array(z.string().min(1))
    .min(1)
    .refine(unique, 'proofProfiles must be unique')
    .optional(),
  didMethods: z
    .array(z.string().regex(DID_METHOD, 'didMethods entries look like "did:web"'))
    .min(1)
    .refine(unique, 'didMethods must be unique')
    .optional(),
  required: z.boolean().optional(),
});

/** A declared (wire-shaped) settings object; all members optional, `{}` legal. */
export type KyaOsExtensionSettings = z.infer<typeof ExtensionSettingsSchema>;

/** Settings with every default applied (SPEC-MCP-EXTENSION.md §3.2 defaults column). */
export interface ResolvedExtensionSettings {
  version: string;
  proofProfiles: string[];
  didMethods: string[];
  required: boolean;
}

/** The §3.2 defaults an empty declaration resolves to. */
export const DEFAULT_EXTENSION_SETTINGS: ResolvedExtensionSettings = {
  version: '1.0.0',
  proofProfiles: [PROOF_PROFILE_ID],
  didMethods: ['did:key', 'did:web'],
  required: false,
};

/**
 * Parse a PEER's settings value. A malformed value returns `undefined` - the
 * declaration is treated as ABSENT (fail closed to non-declaration, never a
 * guess at intent; SPEC-MCP-EXTENSION.md §3.2). `{}` parses successfully.
 */
export function parseExtensionSettings(value: unknown): KyaOsExtensionSettings | undefined {
  const parsed = ExtensionSettingsSchema.safeParse(value);
  return parsed.success ? parsed.data : undefined;
}

/** Apply the §3.2 defaults to a declared settings object. */
export function resolveExtensionSettings(
  settings: KyaOsExtensionSettings = {},
): ResolvedExtensionSettings {
  return {
    version: settings.version ?? DEFAULT_EXTENSION_SETTINGS.version,
    proofProfiles: settings.proofProfiles ?? [...DEFAULT_EXTENSION_SETTINGS.proofProfiles],
    didMethods: settings.didMethods ?? [...DEFAULT_EXTENSION_SETTINGS.didMethods],
    required: settings.required ?? DEFAULT_EXTENSION_SETTINGS.required,
  };
}

/**
 * Validate OWN settings before putting them on the wire. Unlike a peer's input
 * (parsed fail-closed), malformed own settings are a programmer error and throw.
 */
export function buildExtensionSettings(
  settings: KyaOsExtensionSettings = {},
): KyaOsExtensionSettings {
  const parsed = ExtensionSettingsSchema.safeParse(settings);
  if (!parsed.success) {
    throw new Error(`invalid ${KYA_OS_EXTENSION_ID} settings: ${parsed.error.message}`);
  }
  return parsed.data;
}

/**
 * Build the `extensions` map fragment - `{ "org.kya-os/decentralized-authority": settings }` -
 * ready to merge into `ClientCapabilities.extensions` / `ServerCapabilities.extensions`
 * (or the per-request `_meta` carriage; SPEC-MCP-EXTENSION.md §3.1).
 */
export function buildExtensionsEntry(
  settings: KyaOsExtensionSettings = {},
  extensionId: string = KYA_OS_EXTENSION_ID,
): Record<string, KyaOsExtensionSettings> {
  return { [extensionId]: buildExtensionSettings(settings) };
}
