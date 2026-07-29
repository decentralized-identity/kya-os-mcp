/**
 * The card-proof `_meta` carrier key vs MCP's key grammar (SPEC-ENTITY-CARD §8.1).
 *
 * MCP's `_meta` key grammar permits only alphanumerics, hyphens, underscores, and dots in a
 * key's name segment - no `@` - so the profile id `org.kya-os/proof.v1` cannot itself be the
 * carrier key. The canonical key is its key-safe form (`org.kya-os/request-proof`); the earlier
 * draft key (the profile id verbatim) stays readable for one major version, canonical wins.
 */

import { describe, it, expect } from 'vitest';
import { readCardProof } from '../middleware.js';
import {
  KYA_OS_CARD_PROOF_META_KEY,
  LEGACY_CARD_PROOF_META_KEY,
  PROOF_PROFILE_V1,
} from '../proof/types.js';
import { LEGACY_PROOF_PROFILE_ID } from '../schema.js';

/** MCP `_meta` name-segment grammar: alnum ends, alnum/hyphen/underscore/dot interior. */
const META_KEY_NAME = /^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/;

describe('card-proof _meta carrier key', () => {
  it('the canonical key is legal under the MCP _meta key grammar', () => {
    const name = KYA_OS_CARD_PROOF_META_KEY.split('/')[1];
    expect(name).toBeDefined();
    expect(name).toMatch(META_KEY_NAME);
  });

  it('the legacy key is the legacy profile id verbatim (and is why it was replaced)', () => {
    expect(LEGACY_CARD_PROOF_META_KEY).toBe(LEGACY_PROOF_PROFILE_ID);
    expect(LEGACY_CARD_PROOF_META_KEY.split('/')[1]).not.toMatch(META_KEY_NAME);
  });

  it('the canonical profile id carries no @ and versions only itself', () => {
    expect(PROOF_PROFILE_V1).toBe('org.kya-os/proof.v1');
    expect(PROOF_PROFILE_V1).not.toContain('@');
  });

  it('readCardProof reads the canonical key', () => {
    expect(readCardProof({ [KYA_OS_CARD_PROOF_META_KEY]: 'proof' })).toBe('proof');
  });

  it('readCardProof falls back to the legacy key (one-major-version window)', () => {
    expect(readCardProof({ [LEGACY_CARD_PROOF_META_KEY]: 'legacy' })).toBe('legacy');
  });

  it('the canonical key wins when both are present', () => {
    const meta = {
      [KYA_OS_CARD_PROOF_META_KEY]: 'canonical',
      [LEGACY_CARD_PROOF_META_KEY]: 'legacy',
    };
    expect(readCardProof(meta)).toBe('canonical');
  });
});
