import { generateKeyPair } from 'jose';
import { NodeCryptoProvider } from '../../src/providers/node-crypto.js';
import {
  AuditCheckpointBuilder,
  AuditProjectionWorker,
  CompactJwsAuditSigner,
  CryptoProviderAuditHasher,
  MemoryAuditCheckpointStore,
  MemoryAuditJournal,
  MemoryAuditProjectionProvider,
  createAuditTrail,
  createLocalAuditRecorder,
  type PartyRef,
} from '../../src/audit/index.js';

const crypto = new NodeCryptoProvider();
const hasher = new CryptoProviderAuditHasher(crypto);
const { privateKey } = await generateKeyPair('EdDSA');
const signer = new CompactJwsAuditSigner({
  did: 'did:web:audit.example',
  kid: 'did:web:audit.example#recorder-1',
  alg: 'EdDSA',
}, privateKey);
const ledger = {
  ledgerId: 'kya:tenant-opaque:dev:primary',
  ledgerEpochId: 'epoch-local-1',
};
const tenantRef: PartyRef = {
  kind: 'keyed_commitment',
  value: `sha256:${'0'.repeat(64)}`,
  keyId: 'tenant-index-key-v1',
};
const journal = new MemoryAuditJournal();
const recorder = createLocalAuditRecorder({
  ...ledger,
  tenantRef,
  binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
  sourceId: 'local-recorder',
  journal,
  signer,
  hasher,
  clock: Date,
}, () => ({
  producerAuthority: 'did:web:mcp.example',
  tenantAuthority: 'tenant-opaque',
}));
const trail = createAuditTrail({
  recorder,
  delivery: 'required',
  hasher,
  ledgerId: ledger.ledgerId,
  expectedLedgerEpochId: ledger.ledgerEpochId,
  tenantRef,
  producer: { kind: 'pairwise_did', did: 'did:key:zLocalProducer' },
  sourceId: 'mcp-server-1',
  binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
  privacy: { classification: 'internal', retentionClass: 'audit-30d' },
  clock: Date,
});

await trail.record({
  eventType: 'tool.call.started',
  correlationId: 'example-call-1',
  action: { category: 'tool.call' },
  outcome: 'unknown',
  evidence: [],
  details: { family: 'tool', phase: 'started', attempt: '1' },
});
await trail.record({
  eventType: 'tool.call.completed',
  correlationId: 'example-call-1',
  action: { category: 'tool.call' },
  outcome: 'succeeded',
  evidence: [],
  details: { family: 'tool', phase: 'completed', attempt: '1' },
});
await trail.recordSourceHighWater();

const checkpoint = await new AuditCheckpointBuilder({
  journal,
  store: new MemoryAuditCheckpointStore(),
  signer,
  hasher,
  clock: Date,
}).createCheckpoint(ledger);
const projections = new MemoryAuditProjectionProvider();
const projection = new AuditProjectionWorker({
  projectionId: 'example-timeline-v1',
  journal,
  projections,
});
await projection.rebuild(ledger);

console.log(JSON.stringify({
  checkpoint: {
    treeSize: checkpoint.core.treeSize,
    rootDigest: checkpoint.core.rootDigest,
    checkpointDigest: checkpoint.checkpointDigest,
  },
  projection: await projections.read('example-timeline-v1', ledger),
  source: await trail.getSourceState(),
}, null, 2));
