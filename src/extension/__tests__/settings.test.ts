/**
 * Settings-object validation (SPEC-MCP-EXTENSION.md §3.2, mirrored by
 * schemas/mcp-extension-settings.json): every member optional, `{}` legal,
 * unknown members tolerated, malformed peer input parsed fail-closed to
 * "not declared".
 */

import { describe, it, expect } from 'vitest';
import {
  DEFAULT_EXTENSION_SETTINGS,
  KYA_OS_EXTENSION_ID,
  buildExtensionSettings,
  buildExtensionsEntry,
  parseExtensionSettings,
  resolveExtensionSettings,
} from '../settings.js';

describe('parseExtensionSettings', () => {
  it('accepts the empty object (SEP-2133: supported with default configuration)', () => {
    expect(parseExtensionSettings({})).toEqual({});
  });

  it('accepts a fully-populated settings object', () => {
    const settings = {
      version: '1.0.0',
      proofProfiles: ['org.kya-os/proof@1'],
      didMethods: ['did:key', 'did:web'],
      required: true,
    };
    expect(parseExtensionSettings(settings)).toEqual(settings);
  });

  it('tolerates and strips unknown members (forward compatibility)', () => {
    const parsed = parseExtensionSettings({ version: '2.1.0', futureKnob: 'x' });
    expect(parsed).toEqual({ version: '2.1.0' });
  });

  it('accepts a prerelease version string', () => {
    expect(parseExtensionSettings({ version: '1.0.0-rc.1' })).toEqual({ version: '1.0.0-rc.1' });
  });

  it.each([null, undefined, [], 'settings', 42, true])(
    'rejects a non-object value (%s)',
    (value) => {
      expect(parseExtensionSettings(value)).toBeUndefined();
    },
  );

  it.each([
    ['a non-semver version', { version: 'v1' }],
    ['a numeric version', { version: 1 }],
    ['a string proofProfiles', { proofProfiles: 'org.kya-os/proof@1' }],
    ['an empty proofProfiles array', { proofProfiles: [] }],
    ['duplicate proofProfiles', { proofProfiles: ['p', 'p'] }],
    ['an empty proofProfiles entry', { proofProfiles: [''] }],
    ['a didMethods entry without the did: prefix', { didMethods: ['web'] }],
    ['an uppercase didMethods entry', { didMethods: ['did:WEB'] }],
    ['duplicate didMethods', { didMethods: ['did:web', 'did:web'] }],
    ['a non-boolean required', { required: 'true' }],
  ])('rejects %s', (_label, value) => {
    expect(parseExtensionSettings(value)).toBeUndefined();
  });

  it('accepts an opt-in did method like did:cheqd', () => {
    expect(parseExtensionSettings({ didMethods: ['did:cheqd'] })).toEqual({
      didMethods: ['did:cheqd'],
    });
  });
});

describe('resolveExtensionSettings', () => {
  it('resolves the empty declaration to the §3.2 defaults', () => {
    expect(resolveExtensionSettings({})).toEqual(DEFAULT_EXTENSION_SETTINGS);
  });

  it('keeps declared members and defaults the rest', () => {
    const resolved = resolveExtensionSettings({ required: true, didMethods: ['did:web'] });
    expect(resolved.required).toBe(true);
    expect(resolved.didMethods).toEqual(['did:web']);
    expect(resolved.version).toBe(DEFAULT_EXTENSION_SETTINGS.version);
    expect(resolved.proofProfiles).toEqual(DEFAULT_EXTENSION_SETTINGS.proofProfiles);
  });

  it('returns copies so callers cannot mutate the shared defaults', () => {
    const resolved = resolveExtensionSettings({});
    resolved.proofProfiles.push('mutated');
    resolved.didMethods.push('did:mutated');
    expect(DEFAULT_EXTENSION_SETTINGS.proofProfiles).toEqual(['org.kya-os/proof@1']);
    expect(DEFAULT_EXTENSION_SETTINGS.didMethods).toEqual(['did:key', 'did:web']);
  });
});

describe('buildExtensionSettings / buildExtensionsEntry', () => {
  it('throws on malformed own settings (programmer error, not peer input)', () => {
    expect(() => buildExtensionSettings({ version: 'nope' })).toThrow(KYA_OS_EXTENSION_ID);
  });

  it('builds the extensions-map fragment under the extension id', () => {
    const entry = buildExtensionsEntry({ required: true });
    expect(entry).toEqual({ [KYA_OS_EXTENSION_ID]: { required: true } });
  });

  it('supports an id override for graduation re-pointing', () => {
    const entry = buildExtensionsEntry({}, 'io.modelcontextprotocol/delegation');
    expect(Object.keys(entry)).toEqual(['io.modelcontextprotocol/delegation']);
  });
});
