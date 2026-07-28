/**
 * Declaration reading across both carriage forms (SPEC-MCP-EXTENSION.md §3.1):
 * the per-request stateless `_meta` carriage, the initialize-era carriage, the
 * stateless-wins precedence, and the malformed-treated-as-absent rule.
 */

import { describe, it, expect } from 'vitest';
import { readExtensionDeclaration } from '../declaration.js';
import { KYA_OS_EXTENSION_ID, MCP_CLIENT_CAPABILITIES_META_KEY } from '../settings.js';

/** A `params._meta` bag whose clientCapabilities declare the given extension entry. */
function metaDeclaring(entry: unknown, id: string = KYA_OS_EXTENSION_ID): Record<string, unknown> {
  return {
    [MCP_CLIENT_CAPABILITIES_META_KEY]: { extensions: { [id]: entry } },
  };
}

describe('readExtensionDeclaration - stateless carriage', () => {
  it('reads a valid per-request declaration', () => {
    const declaration = readExtensionDeclaration({
      meta: metaDeclaring({ version: '1.0.0', didMethods: ['did:web'] }),
    });
    expect(declaration).toEqual({
      settings: { version: '1.0.0', didMethods: ['did:web'] },
      carriage: 'stateless',
    });
  });

  it('treats an explicit empty-object entry as declared', () => {
    const declaration = readExtensionDeclaration({ meta: metaDeclaring({}) });
    expect(declaration).toEqual({ settings: {}, carriage: 'stateless' });
  });

  it('returns undefined when nothing declares the extension', () => {
    expect(readExtensionDeclaration({})).toBeUndefined();
    expect(readExtensionDeclaration({ meta: {} })).toBeUndefined();
  });

  it.each([
    ['a non-record meta', 'not-a-record'],
    ['a null meta', null],
    ['an array meta', []],
  ])('returns undefined for %s', (_label, meta) => {
    expect(readExtensionDeclaration({ meta })).toBeUndefined();
  });

  it('returns undefined when clientCapabilities is not a record', () => {
    const meta = { [MCP_CLIENT_CAPABILITIES_META_KEY]: 'capabilities' };
    expect(readExtensionDeclaration({ meta })).toBeUndefined();
  });

  it('returns undefined when extensions is not a record', () => {
    const meta = { [MCP_CLIENT_CAPABILITIES_META_KEY]: { extensions: ['x'] } };
    expect(readExtensionDeclaration({ meta })).toBeUndefined();
  });

  it('ignores declarations of other extensions', () => {
    const meta = metaDeclaring({}, 'io.modelcontextprotocol/tasks');
    expect(readExtensionDeclaration({ meta })).toBeUndefined();
  });

  it('treats a malformed entry as absent (fail closed)', () => {
    const meta = metaDeclaring({ proofProfiles: 'not-an-array' });
    expect(readExtensionDeclaration({ meta })).toBeUndefined();
  });
});

describe('readExtensionDeclaration - initialize-era carriage', () => {
  it('reads the initialize-era declaration when no stateless entry exists', () => {
    const declaration = readExtensionDeclaration({
      meta: { [MCP_CLIENT_CAPABILITIES_META_KEY]: {} },
      initializeCapabilities: { extensions: { [KYA_OS_EXTENSION_ID]: { required: false } } },
    });
    expect(declaration).toEqual({ settings: { required: false }, carriage: 'initialize' });
  });

  it('treats a malformed initialize-era entry as absent', () => {
    const declaration = readExtensionDeclaration({
      initializeCapabilities: { extensions: { [KYA_OS_EXTENSION_ID]: 42 } },
    });
    expect(declaration).toBeUndefined();
  });
});

describe('readExtensionDeclaration - precedence', () => {
  it('a present-but-malformed stateless entry is final: no initialize-era fallback', () => {
    const declaration = readExtensionDeclaration({
      meta: metaDeclaring({ version: 7 }),
      initializeCapabilities: { extensions: { [KYA_OS_EXTENSION_ID]: {} } },
    });
    expect(declaration).toBeUndefined();
  });

  it('a valid stateless entry wins over a differing initialize-era one', () => {
    const declaration = readExtensionDeclaration({
      meta: metaDeclaring({ version: '2.0.0' }),
      initializeCapabilities: { extensions: { [KYA_OS_EXTENSION_ID]: { version: '1.0.0' } } },
    });
    expect(declaration?.carriage).toBe('stateless');
    expect(declaration?.settings.version).toBe('2.0.0');
  });
});

describe('readExtensionDeclaration - id override', () => {
  it('reads a declaration under an overridden extension id', () => {
    const id = 'io.modelcontextprotocol/decentralized-authority';
    const declaration = readExtensionDeclaration({ meta: metaDeclaring({}, id), extensionId: id });
    expect(declaration).toEqual({ settings: {}, carriage: 'stateless' });
  });
});
