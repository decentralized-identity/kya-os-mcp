/**
 * The one check of a verification method's shape (W3C Controlled Identifiers v1.0 §2.2), shared by
 * the did:web and cheqd resolvers for a document's `verificationMethod` entries and by the
 * relationship retrieval for every method it retrieves. It checks that `id`, `type` and `controller`
 * are non-empty strings, and nothing else.
 */

import { describe, it, expect } from 'vitest';
import { hasIdTypeAndController } from '../verification-method-shape.js';

const method = {
  id: 'did:web:acme.example#key-1',
  type: 'Ed25519VerificationKey2020',
  controller: 'did:web:acme.example',
};

describe('hasIdTypeAndController', () => {
  it('accepts a map with a non-empty string id, type and controller, whatever else it carries', () => {
    expect(hasIdTypeAndController(method)).toBe(true);
    expect(hasIdTypeAndController({ ...method, publicKeyMultibase: 'z6Mk' })).toBe(true);
  });

  it.each(['id', 'type', 'controller'] as const)('refuses a method whose %s is missing, empty or not a string', (member) => {
    const { [member]: _member, ...without } = method;
    for (const value of [undefined, '', 7, null, ['did:web:acme.example']]) {
      expect(hasIdTypeAndController(value === undefined ? without : { ...method, [member]: value })).toBe(false);
    }
  });

  it('checks nothing else: an id or controller that is not a URL passes', () => {
    expect(hasIdTypeAndController({ ...method, id: 'key 1', controller: 'acme' })).toBe(true);
  });

  it('refuses anything that is not a map', () => {
    for (const value of [null, undefined, method.id, 7, [method]]) {
      expect(hasIdTypeAndController(value)).toBe(false);
    }
  });
});
