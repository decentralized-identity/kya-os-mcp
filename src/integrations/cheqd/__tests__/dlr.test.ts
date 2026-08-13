import { describe, it, expect, vi } from 'vitest';
import {
  buildCheqdDlrReference,
  prepareCheqdDlrResource,
  validateCheqdDlrArtifact,
} from '../dlr.js';
import type { CryptoProvider } from '../../../providers/base.js';
import { canonicalizeJSON } from '../../../delegation/utils.js';

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

  it('anchors a signed StatusListCredential as its exact canonical bytes (demo-publisher compatible)', async () => {
    const signedVc = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      id: 'https://status.example/1',
      type: ['VerifiableCredential', 'StatusList2021Credential'],
      issuer: 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111',
      issuanceDate: '2026-08-13T00:00:00Z',
      credentialSubject: {
        id: 'https://status.example/1#list',
        type: 'StatusList2021',
        statusPurpose: 'revocation',
        encodedList: 'uH4sIAAAAAAAA',
      },
      proof: { type: 'Ed25519Signature2020', proofValue: 'zsig' },
    };

    const prepared = await prepareCheqdDlrResource(
      {
        type: 'StatusListCredential',
        subjectDid: 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111',
        name: 'kya-statuslist',
        resourceType: 'StatusListCredential',
        version: '2026-08-13T00-00-00Z',
        content: signedVc,
      },
      cryptoProvider,
    );

    // Compatibility pin: content is the WHOLE SIGNED VC, so the canonical
    // bytes (and therefore the contentHash and on-chain resource body) equal
    // the hash-what-you-publish computation the vendored demo publisher used
    // — resources already anchored on cheqd testnet stay reproducible.
    expect(prepared.canonicalContent).toBe(canonicalizeJSON(signedVc));
    expect(prepared.resource.data).toBe(
      Buffer.from(new TextEncoder().encode(prepared.canonicalContent)).toString('base64'),
    );
    expect(prepared.resource.name).toBe('kya-statuslist');
    expect(prepared.resource.version).toBe('2026-08-13T00-00-00Z');
  });

  it('refuses an UNSIGNED StatusListCredential artifact', () => {
    expect(
      validateCheqdDlrArtifact({
        type: 'StatusListCredential',
        subjectDid: 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111',
        content: { credentialSubject: { encodedList: 'uH4sI' } },
      }).reason,
    ).toContain('UNSIGNED');
  });

  it('refuses a StatusListCredential without an encodedList', () => {
    expect(
      validateCheqdDlrArtifact({
        type: 'StatusListCredential',
        subjectDid: 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111',
        content: { proof: {}, credentialSubject: {} },
      }).reason,
    ).toContain('encodedList');
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
