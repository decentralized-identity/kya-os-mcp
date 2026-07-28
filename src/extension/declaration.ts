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
 * malformed stateless entry is treated as no declaration (fail closed, §3.2)
 * and the initialize-era entry is NOT consulted as a fallback, because the
 * per-request carriage supersedes initialize-era state.
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

/**
 * Read and validate the peer's declaration from either carriage.
 * Returns `undefined` when the extension is not declared - including when the
 * declared settings object is malformed (treated as absent, §3.2).
 */
export function readExtensionDeclaration(
  input: ReadDeclarationInput,
): ExtensionDeclaration | undefined {
  const id = input.extensionId ?? KYA_OS_EXTENSION_ID;

  const stateless = extensionsEntry(clientCapabilitiesFromMeta(input.meta), id);
  if (stateless.present) {
    const settings = parseExtensionSettings(stateless.value);
    return settings === undefined ? undefined : { settings, carriage: 'stateless' };
  }

  const legacy = extensionsEntry(input.initializeCapabilities, id);
  if (legacy.present) {
    const settings = parseExtensionSettings(legacy.value);
    return settings === undefined ? undefined : { settings, carriage: 'initialize' };
  }

  return undefined;
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
