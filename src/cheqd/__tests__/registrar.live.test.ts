import { randomUUID } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import {
  CheqdDidRegistrarClient,
  createLocalEd25519CheqdRegistrarSigner,
  type CheqdRegistrarResult,
} from '../registrar.js';
import { prepareCheqdDlrResource, type CheqdDlrArtifact } from '../dlr.js';
import { createDidCheqdResolver } from '../../delegation/did-cheqd-resolver.js';
import { updateCheqdAlsoKnownAs } from '../../delegation/did-linkage.js';
import type { DIDDocument } from '../../delegation/vc-verifier.js';
import type { FetchProvider } from '../../providers/base.js';
import { NodeCryptoProvider } from '../../providers/node-crypto.js';
import { generateDidKeyFromBase64 } from '../../utils/did-helpers.js';

const LIVE_E2E_ENABLED = process.env['KYA_OS_CHEQD_E2E'] === '1';
const TESTNET_REGISTRAR_URL =
  process.env['KYA_OS_CHEQD_TESTNET_REGISTRAR_URL'] ??
  'https://did-registrar-staging.cheqd.net/1.0';
const TESTNET_RESOLVER_URL =
  process.env['KYA_OS_CHEQD_TESTNET_RESOLVER_URL'] ??
  'https://resolver.cheqd.net';
const LIVE_TIMEOUT_MS = Number(process.env['KYA_OS_CHEQD_E2E_TIMEOUT_MS'] ?? 180_000);

const describeLive = LIVE_E2E_ENABLED ? describe : describe.skip;

const liveFetchProvider: FetchProvider = {
  resolveDID: async () => null,
  fetchStatusList: async () => null,
  fetchDelegationChain: async () => [],
  fetch: async (url, options) => fetch(url, options as RequestInit),
};

interface LiveDidFixture {
  did: string;
  didWeb: string;
  kid: string;
  privateKey: string;
  runId: string;
  didDocument: DIDDocument;
}

describeLive('Cheqd DID Registrar live testnet E2E', () => {
  it(
    'creates and links a testnet DID, then publishes realistic KYA DID-Linked Resources',
    async () => {
      const cryptoProvider = new NodeCryptoProvider();
      const fixture = await createTestnetDidFixture(cryptoProvider);
      const registrar = new CheqdDidRegistrarClient({
        registrarUrl: TESTNET_REGISTRAR_URL,
        fetchProvider: liveFetchProvider,
      });
      const signer = createLocalEd25519CheqdRegistrarSigner({
        cryptoProvider,
        privateKey: fixture.privateKey,
        verificationMethodId: fixture.kid,
        signatureEncoding: 'base64url',
      });

      const createResult = await registrar.createDid({
        didDocument: fixture.didDocument,
        signer,
        verificationMethodId: fixture.kid,
      });
      expectSuccessfulRegistrarResult(createResult);

      const resolver = createDidCheqdResolver(liveFetchProvider, {
        resolverUrl: TESTNET_RESOLVER_URL,
        cacheTtl: 0,
      });
      await waitForDidDocument(
        () => resolver.resolve(fixture.did),
        fixture.did,
      );

      const updateResult = await updateCheqdAlsoKnownAs({
        didCheqd: fixture.did,
        didWeb: fixture.didWeb,
        resolver,
        registrar,
        signer,
        verificationMethodId: fixture.kid,
      });
      expect(updateResult.changed, updateResult.reason).toBe(true);
      expectSuccessfulRegistrarResult(updateResult.registrarResult!);

      const resolvedUpdatedDocument = await waitForDidDocument(
        async () => {
          const document = await resolver.resolve(fixture.did);
          return document?.alsoKnownAs?.includes(fixture.didWeb)
            ? document
            : null;
        },
        fixture.did,
      );
      expect(resolvedUpdatedDocument.alsoKnownAs).toContain(fixture.didWeb);

      const publishedResources: Array<{
        artifactType: CheqdDlrArtifact['type'];
        contentHash: string;
        resourceId: string;
      }> = [];
      for (const artifact of await buildLiveKyaDlrArtifacts(fixture, cryptoProvider)) {
        const preparedResource = await prepareCheqdDlrResource(artifact, cryptoProvider);
        const resourceResult = await registrar.createResource({
          did: fixture.did,
          resource: preparedResource.resource,
          signer,
          verificationMethodId: fixture.kid,
        });
        expectSuccessfulRegistrarResult(resourceResult);

        const resourceId = findStringByKey(resourceResult.response, 'resourceId');
        expect(resourceId).toMatch(/^[a-z0-9-]{36}$/);
        if (!resourceId) {
          throw new Error(`Registrar did not return a resourceId for ${artifact.type}`);
        }
        publishedResources.push({
          artifactType: artifact.type,
          contentHash: preparedResource.contentHash,
          resourceId,
        });
      }

      expect(publishedResources.map((resource) => resource.artifactType)).toEqual([
        'CapabilityManifest',
        'ConformanceManifest',
        'AccessHashManifest',
        'TrustConfigManifest',
      ]);
      expect(new Set(publishedResources.map((resource) => resource.resourceId)).size).toBe(
        publishedResources.length,
      );
      expect(
        publishedResources.every((resource) => /^sha256:[a-f0-9]{64}$/.test(resource.contentHash)),
      ).toBe(true);
    },
    LIVE_TIMEOUT_MS,
  );
});

describe('Cheqd DID Registrar live fixture builders', () => {
  it('builds one realistic KYA DLR artifact for each supported type', async () => {
    const cryptoProvider = new NodeCryptoProvider();
    const fixture = await createTestnetDidFixture(cryptoProvider);
    const artifacts = await buildLiveKyaDlrArtifacts(fixture, cryptoProvider);

    expect(artifacts.map((artifact) => artifact.type)).toEqual([
      'CapabilityManifest',
      'ConformanceManifest',
      'AccessHashManifest',
      'TrustConfigManifest',
    ]);

    for (const artifact of artifacts) {
      const preparedResource = await prepareCheqdDlrResource(artifact, cryptoProvider);
      expect(preparedResource.resource.name).toContain(fixture.runId);
      expect(preparedResource.resource.version).toBe(fixture.runId);
      expect(preparedResource.contentHash).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(preparedResource.canonicalContent).toContain(fixture.did);
    }
  });
});

async function createTestnetDidFixture(cryptoProvider: NodeCryptoProvider): Promise<LiveDidFixture> {
  const { privateKey, publicKey } = await cryptoProvider.generateKeyPair();
  const runId = randomUUID();
  const did = `did:cheqd:testnet:${runId}`;
  const didWeb = `did:web:kya-os-e2e.example.com:agents:${runId}`;
  const kid = `${did}#key-1`;
  const publicKeyMultibase = generateDidKeyFromBase64(publicKey).replace('did:key:', '');

  return {
    did,
    didWeb,
    kid,
    privateKey,
    runId,
    didDocument: {
      id: did,
      controller: [did],
      verificationMethod: [
        {
          id: kid,
          type: 'Ed25519VerificationKey2020',
          controller: did,
          publicKeyMultibase,
        },
      ],
      authentication: [kid],
    } as DIDDocument,
  };
}

async function buildLiveKyaDlrArtifacts(
  fixture: LiveDidFixture,
  cryptoProvider: NodeCryptoProvider,
): Promise<CheqdDlrArtifact[]> {
  const createdAt = new Date().toISOString();
  const policyHash = await cryptoProvider.hash(
    new TextEncoder().encode(
      JSON.stringify({
        did: fixture.did,
        didWeb: fixture.didWeb,
        runId: fixture.runId,
        policy: 'allow:kya-os-live-e2e',
      }),
    ),
  );
  const baseMetadata = {
    runId: fixture.runId,
    environment: 'cheqd-testnet-staging',
    purpose: 'kya-os-live-e2e',
  };

  return [
    {
      type: 'CapabilityManifest',
      subjectDid: fixture.did,
      createdAt,
      name: `kya-os-capabilities-${fixture.runId}`,
      resourceType: 'CapabilityManifest',
      version: fixture.runId,
      metadata: baseMetadata,
      content: {
        schema: 'https://kya-os.example.com/schemas/capability-manifest/v1',
        subjectDid: fixture.did,
        linkedDidWeb: fixture.didWeb,
        agent: {
          name: 'KYA OS live E2E agent',
          controller: fixture.did,
        },
        capabilities: [
          {
            id: 'kya.proof.issue',
            description: 'Issue KYA proof receipts for MCP tool calls',
            inputs: ['mcpToolCall', 'delegationChain'],
            outputs: ['kyaProofReceipt'],
          },
          {
            id: 'kya.dlr.publish',
            description: 'Publish durable KYA manifests as cheqd DID-Linked Resources',
            inputs: ['manifest'],
            outputs: ['didLinkedResourceReference'],
          },
        ],
      },
    },
    {
      type: 'ConformanceManifest',
      subjectDid: fixture.did,
      createdAt,
      name: `kya-os-conformance-${fixture.runId}`,
      resourceType: 'ConformanceManifest',
      version: fixture.runId,
      metadata: baseMetadata,
      content: {
        schema: 'https://kya-os.example.com/schemas/conformance-manifest/v1',
        subjectDid: fixture.did,
        profiles: ['kya-os-mcp/1.5', 'cheqd-dlr/testnet'],
        checks: [
          {
            id: 'did-cheqd-create',
            result: 'pass',
            evidence: fixture.did,
          },
          {
            id: 'did-linkage-alsoknownas',
            result: 'pass',
            evidence: fixture.didWeb,
          },
          {
            id: 'dlr-client-managed-secret',
            result: 'pass',
            evidence: 'did-registrar-staging',
          },
        ],
      },
    },
    {
      type: 'AccessHashManifest',
      subjectDid: fixture.did,
      createdAt,
      name: `kya-os-access-hashes-${fixture.runId}`,
      resourceType: 'AccessHashManifest',
      version: fixture.runId,
      metadata: baseMetadata,
      content: {
        schema: 'https://kya-os.example.com/schemas/access-hash-manifest/v1',
        subjectDid: fixture.did,
        protectedArtifacts: [
          {
            id: 'mcp-tool-policy',
            algorithm: 'sha256',
            hash: policyHash,
            canonicalization: 'json-canonicalize',
          },
        ],
      },
    },
    {
      type: 'TrustConfigManifest',
      subjectDid: fixture.did,
      createdAt,
      name: `kya-os-trust-config-${fixture.runId}`,
      resourceType: 'TrustConfigManifest',
      version: fixture.runId,
      metadata: baseMetadata,
      content: {
        schema: 'https://kya-os.example.com/schemas/trust-config-manifest/v1',
        subjectDid: fixture.did,
        linkedDidWeb: fixture.didWeb,
        acceptedDidMethods: ['did:web', 'did:key', 'did:cheqd'],
        requiredLinkage: {
          type: 'alsoKnownAs',
          bidirectional: true,
        },
        trustedIssuers: [fixture.did],
        trustedResources: [
          'CapabilityManifest',
          'ConformanceManifest',
          'AccessHashManifest',
        ],
      },
    },
  ];
}

function expectSuccessfulRegistrarResult(result: CheqdRegistrarResult): void {
  expect(result, JSON.stringify(result.response ?? result, null, 2)).toMatchObject({
    success: true,
    stage: 'complete',
  });
}

async function waitForDidDocument(
  resolve: () => Promise<DIDDocument | null>,
  did: string,
): Promise<DIDDocument> {
  const deadline = Date.now() + LIVE_TIMEOUT_MS;

  while (Date.now() < deadline) {
    const document = await resolve();
    if (document?.id === did) {
      return document;
    }
    await delay(5_000);
  }

  throw new Error(`Timed out waiting for ${did} to resolve on cheqd testnet`);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function findStringByKey(value: unknown, key: string): string | undefined {
  if (Array.isArray(value)) {
    for (const entry of value) {
      const found = findStringByKey(entry, key);
      if (found) {
        return found;
      }
    }
    return undefined;
  }

  if (!isRecord(value)) {
    return undefined;
  }

  const directValue = value[key];
  if (typeof directValue === 'string') {
    return directValue;
  }

  for (const nested of Object.values(value)) {
    const found = findStringByKey(nested, key);
    if (found) {
      return found;
    }
  }

  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
