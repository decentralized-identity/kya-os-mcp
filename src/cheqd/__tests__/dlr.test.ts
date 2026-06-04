import { describe, it, expect, vi } from 'vitest';
import {
  buildCheqdDlrReference,
  prepareCheqdDlrResource,
  validateCheqdDlrArtifact,
} from '../dlr.js';
import type { CryptoProvider } from '../../providers/base.js';

const cryptoProvider: CryptoProvider = {
  sign: vi.fn(),
  verify: vi.fn(),
  generateKeyPair: vi.fn(),
  hash: vi.fn(async () => `sha256:${'a'.repeat(64)}`),
  randomBytes: vi.fn(),
};

describe('cheqd DLR helpers', () => {
  it('validates supported artifact shapes', () => {
    expect(
      validateCheqdDlrArtifact({
        type: 'CapabilityManifest',
        subjectDid: 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111',
        content: { tools: ['search'] },
      }).valid,
    ).toBe(true);
  });

  it('rejects missing required fields, unsupported types, bad hashes, and malformed ids', () => {
    expect(validateCheqdDlrArtifact({}).valid).toBe(false);
    expect(
      validateCheqdDlrArtifact({
        type: 'ReputationScore',
        subjectDid: 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111',
        content: {},
      }).reason,
    ).toContain('Unsupported');
    expect(
      validateCheqdDlrArtifact({
        type: 'CapabilityManifest',
        content: {},
      }).reason,
    ).toContain('subjectDid');
    expect(
      validateCheqdDlrArtifact({
        type: 'CapabilityManifest',
        subjectDid: 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111',
        content: {},
        contentHash: 'sha256:bad',
      }).reason,
    ).toContain('contentHash');
    expect(
      validateCheqdDlrArtifact({
        id: 'not-a-resource-id',
        type: 'CapabilityManifest',
        subjectDid: 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111',
        content: {},
      }).reason,
    ).toContain('id');
  });

  it('prepares deterministic registrar resource payloads and computes content hash', async () => {
    const prepared = await prepareCheqdDlrResource(
      {
        type: 'ConformanceManifest',
        subjectDid: 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111',
        version: '1.0.0',
        content: { level: 'L2', scopes: ['proofs'] },
      },
      cryptoProvider,
    );

    expect(prepared.contentHash).toBe(`sha256:${'a'.repeat(64)}`);
    expect(prepared.resource).toMatchObject({
      name: 'ConformanceManifest',
      type: 'ConformanceManifest',
      version: '1.0.0',
      mediaType: 'application/json',
    });
    expect(prepared.resource.data).toBe('eyJsZXZlbCI6IkwyIiwic2NvcGVzIjpbInByb29mcyJdfQ==');
  });

  it('keeps resource name and type stable across versions', async () => {
    const first = await prepareCheqdDlrResource(
      {
        type: 'TrustConfigManifest',
        subjectDid: 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111',
        name: 'trust-config',
        resourceType: 'application/vnd.kya-os.trust-config+json',
        version: '1',
        content: { allow: ['a'] },
      },
      cryptoProvider,
    );
    const second = await prepareCheqdDlrResource(
      {
        type: 'TrustConfigManifest',
        subjectDid: 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111',
        name: 'trust-config',
        resourceType: 'application/vnd.kya-os.trust-config+json',
        version: '2',
        content: { allow: ['a', 'b'] },
      },
      cryptoProvider,
    );

    expect(first.resource.name).toBe(second.resource.name);
    expect(first.resource.type).toBe(second.resource.type);
    expect(first.resource.version).toBe('1');
    expect(second.resource.version).toBe('2');
  });

  it('builds resolver references by resource id or name/type query', () => {
    const did = 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111';
    expect(
      buildCheqdDlrReference({
        did,
        resourceId: '33333333-3333-4333-8333-333333333333',
        resourceName: 'CapabilityManifest',
        resourceType: 'CapabilityManifest',
      }).url,
    ).toBe(`${'https://resolver.cheqd.net'}/1.0/identifiers/${did}/resources/33333333-3333-4333-8333-333333333333`);

    expect(
      buildCheqdDlrReference({
        did,
        resolverUrl: 'https://resolver.example/1.0/identifiers',
        resourceName: 'trust config',
        resourceType: 'application/vnd.kya-os.trust-config+json',
      }).url,
    ).toBe(`${'https://resolver.example'}/1.0/identifiers/${did}?resourceName=trust%20config&resourceType=application%2Fvnd.kya-os.trust-config%2Bjson`);

    expect(() =>
      buildCheqdDlrReference({
        did,
        resourceId: 'bad',
        resourceName: 'CapabilityManifest',
        resourceType: 'CapabilityManifest',
      }),
    ).toThrow(/resourceId/);
  });
});
