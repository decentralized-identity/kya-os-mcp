/**
 * The `org.kya-os/decentralized-authority` admission gate (SPEC-MCP-EXTENSION.md §4-§5).
 *
 * Mirrors the `requireProof` guard idiom (`src/card/middleware.ts`): the host
 * builds a guard once from its server settings and runs it per request. Nothing
 * in the default path changes for hosts that never install the gate - the
 * extension is strictly opt-in.
 *
 *   - `required: false` (default): an undeclared peer gets core MCP behavior;
 *     the gate always admits and merely reports the declaration when present.
 *   - `required: true`: a request without a declaration is rejected with the
 *     core MCP error `-32021` (`MissingRequiredClientCapabilityError`) carrying
 *     `error.data = { reason: "extension_not_declared", extension: <id> }`.
 *
 * A stripped or malformed declaration is an ABSENT declaration (fail closed,
 * §4.3) - never silent acceptance, never a guess.
 */

import { PROOF_PROFILE_ID } from '../card/schema.js';
import {
  readExtensionDeclaration,
  type ExtensionDeclaration,
} from './declaration.js';
import {
  EXTENSION_NOT_DECLARED_REASON,
  KYA_OS_EXTENSION_ID,
  MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
  buildExtensionSettings,
  resolveExtensionSettings,
  type KyaOsExtensionSettings,
} from './settings.js';

/**
 * Default implementation-defined JSON-RPC code for KYA-OS domain failures
 * (SPEC-MCP-EXTENSION.md §5). The number is deliberately NOT the dispatch
 * surface - clients dispatch on `error.data.reason` - and it stays inside the
 * JSON-RPC implementation-defined range (`-32000..-32019`).
 */
export const KYA_OS_DOMAIN_ERROR_CODE = -32000;

/** The MCP-reserved code range this extension MUST NOT allocate from (§5.1). */
const MCP_RESERVED_MIN = -32099;
const MCP_RESERVED_MAX = -32020;

/** A JSON-RPC error object (the `error` member of a JSON-RPC response). */
export interface JsonRpcErrorObject {
  code: number;
  message: string;
  data: {
    /** The snake_case KYA-OS reason code - the mandatory dispatch surface (§5.2). */
    reason: string;
    /** The extension id, on negotiation failures. */
    extension?: string;
    /** The proof profile, on proof-gate failures. */
    profile?: string;
    /** Fine-grained verification reasons (SPEC-ENTITY-CARD Appendix D.1), for diagnostics. */
    reasons?: string[];
  };
}

/** The gate verdict: admitted (with the declaration when one was made) or a JSON-RPC rejection. */
export type ExtensionGateResult =
  | { ok: true; declaration?: ExtensionDeclaration }
  | { ok: false; error: JsonRpcErrorObject };

/** Per-request admission guard built by {@link requireExtension}. */
export type ExtensionGuard = (input: {
  meta?: unknown;
  initializeCapabilities?: unknown;
}) => ExtensionGateResult;

/**
 * Build the admission guard from the server's own settings (validated here,
 * throwing on malformed OWN settings - a programmer error, unlike peer input).
 */
export function requireExtension(
  serverSettings: KyaOsExtensionSettings = {},
  opts: { extensionId?: string } = {},
): ExtensionGuard {
  const settings = resolveExtensionSettings(buildExtensionSettings(serverSettings));
  const extensionId = opts.extensionId ?? KYA_OS_EXTENSION_ID;
  return (input) => {
    const declaration = readExtensionDeclaration({ ...input, extensionId });
    if (declaration !== undefined) {
      return { ok: true, declaration };
    }
    if (!settings.required) {
      return { ok: true };
    }
    return { ok: false, error: missingRequiredCapabilityError(extensionId) };
  };
}

/** The `-32021` rejection for a required-but-undeclared extension (SPEC-MCP-EXTENSION.md §4.2). */
export function missingRequiredCapabilityError(
  extensionId: string = KYA_OS_EXTENSION_ID,
): JsonRpcErrorObject {
  return {
    code: MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
    message: `Missing required client capability: ${extensionId}`,
    data: { reason: EXTENSION_NOT_DECLARED_REASON, extension: extensionId },
  };
}

/** The 401-shaped proof-gate error shape (`requireProof`, `src/card/middleware.ts`), structurally. */
export interface ProofGateErrorLike {
  /** A snake_case gate code (`proof_missing` | `proof_invalid` | `proof_level_insufficient`). */
  code: string;
  message: string;
  reasons?: string[];
}

/**
 * Map a proof-gate rejection onto the JSON-RPC surface per SPEC-MCP-EXTENSION.md
 * §5.2: the snake_case code rides `error.data.reason` VERBATIM, the numeric code
 * stays implementation-defined, and codes inside the MCP-reserved range
 * (`-32099..-32020`) are refused outright.
 */
export function proofGateToJsonRpcError(
  gateError: ProofGateErrorLike,
  opts: { code?: number; profile?: string } = {},
): JsonRpcErrorObject {
  if (opts.code !== undefined && opts.code >= MCP_RESERVED_MIN && opts.code <= MCP_RESERVED_MAX) {
    throw new Error(
      `JSON-RPC code ${opts.code} is inside the MCP-reserved range (${MCP_RESERVED_MIN}..${MCP_RESERVED_MAX}); ` +
        'KYA-OS domain errors use implementation-defined codes (SPEC-MCP-EXTENSION.md §5.1)',
    );
  }
  return {
    code: opts.code ?? KYA_OS_DOMAIN_ERROR_CODE,
    message: gateError.message,
    data: {
      reason: gateError.code,
      profile: opts.profile ?? PROOF_PROFILE_ID,
      ...(gateError.reasons && gateError.reasons.length > 0
        ? { reasons: [...gateError.reasons] }
        : {}),
    },
  };
}
