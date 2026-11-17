/**
 * The catalog of refusal codes an adopter branches on in place of reason text: one frozen object of
 * codes, the type of a code, and the two questions an adopter asks of one, whether it is a code and
 * whether it is transient. It is reachable from every entry point whose results carry a code.
 */

import { describe, expect, it } from 'vitest';
import * as root from '../index.js';
import * as card from '../card/index.js';
import * as delegation from '../delegation/index.js';
import { KYA_OS_ERROR_CODES } from '../errors.js';
import { REFUSAL_CODES, RefusalError, isRefusalCode, isTransientRefusal, type RefusalCode } from '../index.js';

/** The codes that say the verifier could not decide, because a dependency failed. */
const TRANSIENT: readonly RefusalCode[] = ['did_unavailable', 'status_unavailable', 'deadline_exceeded', 'runtime_error'];

describe('the refusal code catalog', () => {
  it('names each code by the string it is, and cannot be changed', () => {
    for (const [name, code] of Object.entries(REFUSAL_CODES)) expect(code).toBe(name);
    expect(Object.isFrozen(REFUSAL_CODES)).toBe(true);
    expect(() => {
      (REFUSAL_CODES as Record<string, string>).delegation_revoked = 'revoked';
    }).toThrow(TypeError);
  });

  it('takes the name of an error code wherever the meaning is the same', () => {
    const shared = Object.keys(REFUSAL_CODES).filter((code) => code in KYA_OS_ERROR_CODES);
    expect(shared.sort()).toEqual([
      'configuration_error',
      'delegation_expired',
      'delegation_invalid',
      'delegation_not_yet_valid',
      'delegation_revoked',
      'holder_binding_failed',
      'insufficient_scope',
      'invalid_proof',
      'needs_authorization',
      'runtime_error',
    ]);
  });

  it('holds transient exactly the codes where a dependency failed', () => {
    for (const code of Object.values(REFUSAL_CODES)) {
      expect([code, isTransientRefusal(code)]).toEqual([code, TRANSIENT.includes(code)]);
    }
  });

  it('answers false, and never throws, for a value that is no code', () => {
    for (const value of [undefined, null, '', 'revoked', 'DELEGATION_REVOKED', 42, {}, ['deadline_exceeded'], Symbol('x')]) {
      expect(isRefusalCode(value)).toBe(false);
      expect(isTransientRefusal(value)).toBe(false);
    }
    expect(isRefusalCode('untrusted_root')).toBe(true);
  });

  it('is exported from the package root, @kya-os/mcp/delegation and @kya-os/mcp/card', () => {
    for (const entry of [root, delegation, card] as Record<string, unknown>[]) {
      expect(entry['REFUSAL_CODES']).toBe(REFUSAL_CODES);
      expect(entry['isRefusalCode']).toBe(isRefusalCode);
      expect(entry['isTransientRefusal']).toBe(isTransientRefusal);
      expect(entry['RefusalError']).toBe(RefusalError);
    }
  });
});
