/**
 * An adopter's operator keeps its delegation graph and status list as the library recommends: it
 * allocates each delegation's status list entry with `allocateStatusEntry('revocation',
 * { delegationId })`, builds its `DelegationGraphManager` with that `StatusList2021Manager` as
 * `statusEntryOwners`, and revokes through a `CascadingRevocationManager` over both. An agent that
 * submits a re-delegation carrying another delegation's entry is refused when it is registered,
 * and a delegation the graph held from before the upgrade, carrying another's entry, is revoked in
 * the graph while that entry is left alone, which the operator reads from the
 * `StatusEntryUnchangedError` it catches. A removed delegation's entry stays retired, even for its
 * own id, and one removed while it read as revoked keeps its id revoked.
 */
import assert from 'node:assert/strict';
import {
  CascadingRevocationManager,
  DelegationGraphManager,
  MemoryDelegationGraphStorage,
  MemoryStatusListStorage,
  RefusalError,
  StatusEntryUnchangedError,
  createStatusListManager,
  statusListGzipCodec,
  type CredentialStatus,
} from '@kya-os/mcp';
import { runCases } from './shared/cases.js';
import { crypto, didWebParty } from './shared/keys.js';

const operator = await didWebParty('did:web:operator.example');
const statusList = createStatusListManager(
  new MemoryStatusListStorage(),
  { getDid: () => operator.did, getKeyId: () => operator.kid },
  async (canonicalVC, _issuerDid, kid) => ({
    type: 'Ed25519Signature2020',
    created: new Date().toISOString(),
    verificationMethod: kid,
    proofPurpose: 'assertionMethod',
    proofValue: Buffer.from(await crypto.sign(new TextEncoder().encode(canonicalVC), operator.privateKey)).toString('base64'),
  }),
  statusListGzipCodec,
  statusListGzipCodec,
  { statusListBaseUrl: 'https://status.operator.example' },
);
const graphStorage = new MemoryDelegationGraphStorage();
const graph = new DelegationGraphManager(graphStorage, { statusEntryOwners: statusList });
const revocation = new CascadingRevocationManager(graph, statusList);

/** Allocate `id`'s entry for it, and register it under `parentId` with that entry. */
async function issue(id: string, parentId: string | null): Promise<CredentialStatus> {
  const credentialStatus = await statusList.allocateStatusEntry('revocation', { delegationId: id });
  await graph.registerDelegation({
    id,
    parentId,
    issuerDid: parentId === null ? operator.did : `did:web:${parentId}.example`,
    subjectDid: `did:web:${id}.example`,
    credentialStatus,
  });
  return credentialStatus;
}

const rootEntry = await issue('root', null);
const teamEntry = await issue('team', 'root');
const agentEntry = await issue('agent', 'team');

await runCases('status-entry-owners', "each delegation's status entry is registered, set and cleared for it alone", [
  {
    name: 'control: revoking a delegation sets its own entry and leaves its parent live',
    run: async () => {
      await revocation.revokeDelegation('agent');
      assert.equal(await statusList.checkStatus(agentEntry), true);
      assert.equal(await statusList.checkStatus(teamEntry), false);
      await revocation.restoreDelegation('agent');
      assert.equal(await statusList.checkStatus(agentEntry), false);
    },
  },
  {
    name: "a re-delegation that carries its root's entry is refused when it is registered",
    run: async () => {
      const refused = await graph
        .registerDelegation({
          id: 'sub-agent',
          parentId: 'team',
          issuerDid: 'did:web:team.example',
          subjectDid: 'did:web:sub-agent.example',
          credentialStatus: { ...rootEntry },
        })
        .then(() => undefined, (error: unknown) => error);
      assert.ok(refused instanceof RefusalError, `expected a RefusalError, got ${String(refused)}`);
      assert.equal(refused.code, 'delegation_malformed');
      assert.equal(await graph.getNode('sub-agent'), null);
    },
  },
  {
    name: "a delegation held from before the upgrade with its root's entry is revoked in the graph alone",
    run: async () => {
      // A row the operator's store held before entries were checked.
      await graphStorage.registerNodeAtomic({
        id: 'legacy',
        parentId: 'team',
        children: [],
        issuerDid: 'did:web:team.example',
        subjectDid: 'did:web:legacy.example',
        credentialStatus: { ...rootEntry },
      });

      const error = await revocation.revokeDelegation('team').then(() => undefined, (thrown: unknown) => thrown);

      assert.ok(error instanceof StatusEntryUnchangedError, `expected a StatusEntryUnchangedError, got ${String(error)}`);
      assert.ok(!(error instanceof RefusalError));
      assert.deepEqual(
        error.unchanged.map(({ delegationId, reason }) => ({ delegationId, reason })),
        [{ delegationId: 'legacy', reason: 'allocated-to-another' }],
      );
      assert.deepEqual(error.events.map((event) => event.delegationId), ['team', 'agent', 'legacy']);
      assert.equal((await revocation.isRevoked('legacy')).revoked, true);
      assert.equal(await statusList.checkStatus(teamEntry), true);
      assert.equal(await statusList.checkStatus(rootEntry), false);
    },
  },
  {
    name: 'a removed delegation leaves its entry retired, even for its own id',
    run: async () => {
      const liveEntry = await issue('live', 'root');
      await graph.removeDelegation('legacy');
      await graph.removeDelegation('agent');
      await graph.removeDelegation('live');
      assert.deepEqual(await statusList.getStatusEntryOwner(rootEntry), { delegationId: 'root', retired: false });
      assert.deepEqual(await statusList.getStatusEntryOwner(agentEntry), { delegationId: 'agent', retired: true });
      assert.deepEqual(await statusList.getStatusEntryOwner(liveEntry), { delegationId: 'live', retired: true });
      // A delegation removed while live leaves no record, so its id registers again, but not with its entry.
      const refused = await graph
        .registerDelegation({
          id: 'live',
          parentId: 'root',
          issuerDid: 'did:web:root.example',
          subjectDid: 'did:web:live.example',
          credentialStatus: { ...liveEntry },
        })
        .then(() => undefined, (error: unknown) => error);
      assert.ok(refused instanceof RefusalError, `expected a RefusalError, got ${String(refused)}`);
      assert.equal(refused.code, 'delegation_malformed');
    },
  },
  {
    name: 'a delegation removed while revoked keeps its id revoked',
    run: async () => {
      // 'agent' was revoked with 'team', and removed above: its id is refused before its entry is read.
      const refused = await graph
        .registerDelegation({
          id: 'agent',
          parentId: 'team',
          issuerDid: 'did:web:team.example',
          subjectDid: 'did:web:agent.example',
          credentialStatus: { ...agentEntry },
        })
        .then(() => undefined, (error: unknown) => error);
      assert.ok(refused instanceof Error, `expected an Error, got ${String(refused)}`);
      assert.match(refused.message, /^Delegation agent was removed while revoked, and its id stays revoked/);
      assert.equal((await revocation.isRevoked('agent')).revoked, true);
    },
  },
]);
