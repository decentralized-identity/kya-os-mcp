import { describe, expect, it } from 'vitest';
import { didKeyedJwks } from '../cimd.js';

const did = 'did:web:client.example';
const method = { id: `${did}#login`, type: 'JsonWebKey2020', controller: did,
  publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'public', d: 'private' } };

describe('CIMD client authentication key purpose', () => {
  it.each(['assertionMethod', 'unlisted'])('does not project an %s key for client authentication', (relationship) => {
    expect(didKeyedJwks({ id: did, verificationMethod: [method],
      ...(relationship === 'assertionMethod' ? { assertionMethod: [method.id] } : {}) })).toEqual({ keys: [] });
  });

  it('projects referenced and embedded authentication keys in relationship order, once each', () => {
    const second = { ...method, id: '#second' };
    const doc = { id: did, verificationMethod: [method], authentication: [second, method.id, '#login'] };
    expect(didKeyedJwks(doc)).toEqual({ keys: [
      { kty: 'OKP', crv: 'Ed25519', x: 'public', kid: '#second' },
      { kty: 'OKP', crv: 'Ed25519', x: 'public', kid: method.id },
    ] });
  });

  it.each(['duplicate', 'foreign id', 'foreign controller', 'no type', 'no controller', 'no document id'])
  ('omits a method with %s', (problem) => {
    const vm: Record<string, unknown> = { ...method };
    if (problem === 'foreign id') vm.id = 'did:web:other.example#login';
    if (problem === 'foreign controller') vm.controller = 'did:web:other.example';
    if (problem === 'no type') delete vm.type;
    if (problem === 'no controller') delete vm.controller;
    const doc = { ...(problem === 'no document id' ? {} : { id: did }), verificationMethod: [vm],
      authentication: problem === 'duplicate' ? [vm] : [vm.id] };
    expect(didKeyedJwks(doc)).toEqual({ keys: [] });
  });
});
