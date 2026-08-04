/**
 * Reading a peer's `org.kya-os/decentralized-authority` declaration (SPEC-MCP-EXTENSION.md §3.1).
 *
 * Two carriage forms are normalized into one shape:
 *
 *   - stateless (2026-07-28): the request's
 *     `params._meta["io.modelcontextprotocol/clientCapabilities"].extensions[id]`
 *   - initialize-era (2025-11-25): `capabilities.extensions[id]` from the
 *     initialize exchange, supplied by the host as `initializeCapabilities`
 *
 * Precedence: the per-request stateless entry, when PRESENT, is final - a
 * malformed stateless entry is classified as `malformed` (never a silent
 * fallback to the initialize-era entry), because the per-request carriage
 * supersedes initialize-era state. What a malformed entry MEANS is the gate's
 * call (§3.2): degrade-to-absent in optional mode, -32602 in required mode.
 */

import { isRecord } from '../utils/guards.js';
import {
  KYA_OS_EXTENSION_ID,
  MCP_CLIENT_CAPABILITIES_META_KEY,
  parseExtensionSettings,
  type KyaOsExtensionSettings,
} from './settings.js';

/** Which carriage form a declaration arrived on. */
export type DeclarationCarriage = 'stateless' | 'initialize';

/** A normalized, validated peer declaration. */
export interface ExtensionDeclaration {
  settings: KyaOsExtensionSettings;
  carriage: DeclarationCarriage;
}

/** Input to {@link readExtensionDeclaration}; both carriage sources are optional. */
export interface ReadDeclarationInput {
  /** The request's `params._meta` bag (stateless carriage). */
  meta?: unknown;
  /** Initialize-era `ClientCapabilities` (2025-11-25 carriage). */
  initializeCapabilities?: unknown;
  /** Extension id override (defaults to {@link KYA_OS_EXTENSION_ID}). */
  extensionId?: string;
}

/** The three outcomes of reading a peer's declaration (SPEC-MCP-EXTENSION.md §3.2). */
export type DeclarationClassification =
  | { status: 'declared'; declaration: ExtensionDeclaration }
  | { status: 'absent' }
  | { status: 'malformed'; carriage: DeclarationCarriage };

/**
 * Classify the peer's declaration from either carriage, distinguishing a
 * present-but-malformed entry from a genuinely absent one. That distinction is
 * what lets the gate answer malformed with `-32602` in required mode (§3.2)
 * while still degrading it to core behavior in optional mode - so a corrupted,
 * untrusted, proof-excluded `_meta` member never turns an otherwise-valid
 * optional-mode request into a rejection.
 */
export function classifyExtensionDeclaration(
  input: ReadDeclarationInput,
): DeclarationClassification {
  const id = input.extensionId ?? KYA_OS_EXTENSION_ID;

  const stateless = extensionsEntry(clientCapabilitiesFromMeta(input.meta), id);
  if (stateless.present) {
    const settings = parseExtensionSettings(stateless.value);
    return settings === undefined
      ? { status: 'malformed', carriage: 'stateless' }
      : { status: 'declared', declaration: { settings, carriage: 'stateless' } };
  }

  const legacy = extensionsEntry(input.initializeCapabilities, id);
  if (legacy.present) {
    const settings = parseExtensionSettings(legacy.value);
    return settings === undefined
      ? { status: 'malformed', carriage: 'initialize' }
      : { status: 'declared', declaration: { settings, carriage: 'initialize' } };
  }

  return { status: 'absent' };
}

/**
 * Read and validate the peer's declaration from either carriage.
 * Returns `undefined` when there is no usable declaration - including a
 * malformed one; callers that must distinguish malformed from absent (the gate)
 * use {@link classifyExtensionDeclaration} instead.
 */
export function readExtensionDeclaration(
  input: ReadDeclarationInput,
): ExtensionDeclaration | undefined {
  const classification = classifyExtensionDeclaration(input);
  return classification.status === 'declared' ? classification.declaration : undefined;
}

/** Pull `io.modelcontextprotocol/clientCapabilities` out of a `_meta` bag. */
function clientCapabilitiesFromMeta(meta: unknown): unknown {
  return isRecord(meta) ? meta[MCP_CLIENT_CAPABILITIES_META_KEY] : undefined;
}

/**
 * Locate the extension's entry inside a capabilities object. Presence is
 * detected with `hasOwnProperty` so an explicit empty-object declaration
 * (`{ "org.kya-os/decentralized-authority": {} }` - legal per SEP-2133) is distinguishable
 * from an absent one.
 */
function extensionsEntry(
  capabilities: unknown,
  id: string,
): { present: boolean; value?: unknown } {
  if (!isRecord(capabilities)) return { present: false };
  const extensions = capabilities['extensions'];
  if (!isRecord(extensions)) return { present: false };
  if (!Object.prototype.hasOwnProperty.call(extensions, id)) return { present: false };
  return { present: true, value: extensions[id] };
}
