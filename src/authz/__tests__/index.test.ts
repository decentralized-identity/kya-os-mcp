import { describe, it, expect } from 'vitest';
import * as oauth from '../index.js';

/**
 * The ./oauth barrel is the package's public authorization surface. This test
 * pins the exported value identifiers so an accidental removal is caught.
 */
describe('@kya-os/mcp/authz public surface', () => {
  it('exports the seam, registry, reference adapter, and helpers', () => {
    expect(typeof oauth.AuthorizationServerRegistry).toBe('function');
    expect(typeof oauth.GenericOidcAdapter).toBe('function');
    expect(typeof oauth.requirementMatchesAdapter).toBe('function');
    expect(typeof oauth.buildAuthorizeUrl).toBe('function');
    expect(typeof oauth.verifyS256Challenge).toBe('function');
    expect(typeof oauth.buildAuthorizationServerMetadata).toBe('function');
    expect(typeof oauth.projectAccountability).toBe('function');
    expect(typeof oauth.AuthorizationRequirementSchema).toBe('object');
  });
});
