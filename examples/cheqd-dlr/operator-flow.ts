#!/usr/bin/env npx tsx
import {
  RuntimeFetchProvider,
  NodeCryptoProvider,
} from '@kya-os/mcp';
import {
  CheqdDidRegistrarClient,
  cheqdResolver,
  createLocalEd25519CheqdRegistrarSigner,
  prepareCheqdDlrResource,
  updateCheqdAlsoKnownAs,
  type CheqdDlrArtifact,
} from '@kya-os/mcp/cheqd';

const did = requiredEnv('CHEQD_DID');
const didWeb = requiredEnv('CHEQD_DID_WEB');
const kid = requiredEnv('CHEQD_KID');
const privateKey = requiredEnv('CHEQD_PRIVATE_KEY_BASE64');
const registrarUrl =
  process.env['CHEQD_REGISTRAR_URL'] ?? 'https://did-registrar-staging.cheqd.net/1.0';
const resolverUrl = process.env['CHEQD_RESOLVER_URL'] ?? 'https://resolver.cheqd.net';

const cryptoProvider = new NodeCryptoProvider();
const fetchProvider = new RuntimeFetchProvider({
  didResolvers: {
    cheqd: cheqdResolver({ resolverUrl }),
  },
});
const resolver = { resolve: (value: string) => fetchProvider.resolveDID(value) };
const registrar = new CheqdDidRegistrarClient({
  registrarUrl,
  fetchProvider,
});
const signer = createLocalEd25519CheqdRegistrarSigner({
  cryptoProvider,
  privateKey,
  verificationMethodId: kid,
  signatureEncoding: 'base64url',
});

const runId = new Date().toISOString().replace(/[:.]/g, '-');

console.log(`Resolving ${did}`);
const existingDocument = await resolver.resolve(did);
if (!existingDocument) {
  throw new Error(`Could not resolve ${did}`);
}

const linkageResult = await updateCheqdAlsoKnownAs({
  didWeb,
  didCheqd: did,
  resolver,
  registrar,
  signer,
  verificationMethodId: kid,
});
if (linkageResult.registrarResult && !linkageResult.registrarResult.success) {
  throw new Error(linkageResult.reason ?? 'alsoKnownAs update failed');
}
console.log(
  linkageResult.changed
    ? `Updated ${did} alsoKnownAs with ${didWeb}`
    : `${did} already references ${didWeb}`,
);

for (const artifact of await buildDlrArtifacts()) {
  const prepared = await prepareCheqdDlrResource(artifact, cryptoProvider);
  const result = await registrar.createResource({
    did,
    resource: prepared.resource,
    signer,
    verificationMethodId: kid,
  });

  if (!result.success) {
    throw new Error(`${artifact.type} publish failed: ${result.reason}`);
  }

  console.log(JSON.stringify({
    artifactType: artifact.type,
    resourceId: findStringByKey(result.response, 'resourceId'),
    contentHash: prepared.contentHash,
  }));
}

async function buildDlrArtifacts(): Promise<CheqdDlrArtifact[]> {
  const createdAt = new Date().toISOString();
  const policyHash = await cryptoProvider.hash(
    new TextEncoder().encode(
      JSON.stringify({
        did,
        didWeb,
        policy: 'allow:operator-example',
      }),
    ),
  );
  const metadata = {
    runId,
    purpose: 'operator-example',
  };

  return [
    {
      type: 'CapabilityManifest',
      subjectDid: did,
      createdAt,
      name: `kya-os-capabilities-${runId}`,
      resourceType: 'CapabilityManifest',
      version: runId,
      metadata,
      content: {
        subjectDid: did,
        linkedDidWeb: didWeb,
        capabilities: [
          {
            id: 'kya.proof.issue',
            inputs: ['mcpToolCall', 'delegationChain'],
            outputs: ['kyaProofReceipt'],
          },
        ],
      },
    },
    {
      type: 'ConformanceManifest',
      subjectDid: did,
      createdAt,
      name: `kya-os-conformance-${runId}`,
      resourceType: 'ConformanceManifest',
      version: runId,
      metadata,
      content: {
        subjectDid: did,
        profiles: ['kya-os-mcp', 'cheqd-dlr'],
        checks: [
          { id: 'did-linkage-alsoknownas', result: 'pass', evidence: didWeb },
          { id: 'registrar-client-managed-secret', result: 'pass' },
        ],
      },
    },
    {
      type: 'AccessHashManifest',
      subjectDid: did,
      createdAt,
      name: `kya-os-access-hashes-${runId}`,
      resourceType: 'AccessHashManifest',
      version: runId,
      metadata,
      content: {
        subjectDid: did,
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
      subjectDid: did,
      createdAt,
      name: `kya-os-trust-config-${runId}`,
      resourceType: 'TrustConfigManifest',
      version: runId,
      metadata,
      content: {
        subjectDid: did,
        linkedDidWeb: didWeb,
        acceptedDidMethods: ['did:web', 'did:key', 'did:cheqd'],
        requiredLinkage: {
          type: 'alsoKnownAs',
          bidirectional: true,
        },
        trustedIssuers: [did],
      },
    },
  ];
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
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

  if (typeof value !== 'object' || value === null) {
    return undefined;
  }

  const record = value as Record<string, unknown>;
  if (typeof record[key] === 'string') {
    return record[key];
  }

  for (const nested of Object.values(record)) {
    const found = findStringByKey(nested, key);
    if (found) {
      return found;
    }
  }

  return undefined;
}
