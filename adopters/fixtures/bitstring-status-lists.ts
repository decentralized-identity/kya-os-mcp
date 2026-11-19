/**
 * An adopter's issuer moves its status lists to W3C Bitstring Status List v1.0. It builds its
 * `StatusList2021Manager` with `format: 'BitstringStatusList'`, a `validityPeriodMs` and a `ttl`,
 * under a base URL of its own, signs each list `eddsa-jcs-2022` through the manager's signing
 * function, and serves each list from its store. The entry the manager allocates goes on an Entity
 * Card delegation hop as written, and `requireDelegation` reads the list with
 * `createRevocationChecker` and `createStatusListProofVerifier`: the call passes, and is refused as
 * `delegation_revoked` once the issuer revokes. The StatusList2021 list the issuer published before
 * stays in the store, and the issuer goes on revoking on it through the same manager, which signs
 * it again as the format it was created in.
 */
import assert from 'node:assert/strict';
import {
  MemoryStatusListStorage,
  StatusList2021Manager,
  createDidWebResolver,
  statusListGzipCodec,
  type StatusList2021ManagerOptions,
  type StatusListCredential,
  type StatusListFormat,
  type VCSigningFunction,
} from '@kya-os/mcp';
import {
  createDelegationProofVerifier,
  createRevocationChecker,
  createStatusListProofVerifier,
  requireDelegation,
  signStatusListCredential,
  toDelegationChainMeta,
  type DelegationGateResult,
  type SafeFetch,
} from '@kya-os/mcp/card';
import { runCases } from './shared/cases.js';
import { signCardHop } from './shared/credentials.js';
import { didDocumentOf, didKeyParty, didWebParty } from './shared/keys.js';
import { MemoryWeb } from './shared/web.js';

/** The verifier's own DID: the resource the chain is for. */
const RESOURCE = 'did:web:orders.example';
const ACTION = 'orders.place';
/** Where the issuer's StatusList2021 lists are, from before the move, and where its W3C lists are. */
const BEFORE_URL = 'https://status.issuer.example';
const W3C_URL = 'https://status.issuer.example/w3c';
const DAY_MS = 24 * 60 * 60 * 1000;
const TTL_MS = 5 * 60 * 1000;

const issuer = await didWebParty('did:web:issuer.example');
const agent = await didKeyParty();
const web = new MemoryWeb();
web.serveDidDocument(didDocumentOf(issuer));
const didResolver = createDidWebResolver(web.fetchProvider());

/** The issuer's one store, typed for what it holds: lists of both formats. */
const storage = new MemoryStatusListStorage<StatusListCredential>();
/** The manager's signing function: each list signed `eddsa-jcs-2022` with the issuer's key. */
const signList: VCSigningFunction = async (canonicalList) =>
  (await signStatusListCredential(JSON.parse(canonicalList) as Record<string, unknown>, issuer.signer)).proof;

/** The issuer's manager over its one store, built with `options`. */
function managerWith<F extends StatusListFormat>(options: StatusList2021ManagerOptions & { format?: F }) {
  return new StatusList2021Manager(
    storage,
    { getDid: () => issuer.did, getKeyId: () => issuer.kid },
    signList,
    statusListGzipCodec,
    statusListGzipCodec,
    options,
  );
}

/** The entry of a credential issued before the move, on a `StatusList2021Credential`. */
const entryBefore = await managerWith({ statusListBaseUrl: BEFORE_URL }).allocateStatusEntry('revocation');
const lists = managerWith({
  format: 'BitstringStatusList',
  statusListBaseUrl: W3C_URL,
  validityPeriodMs: DAY_MS,
  ttl: TTL_MS,
});
const entry = await lists.allocateStatusEntry('revocation');

/** The issuer's status endpoint: each list as the store holds it now, as the JSON a server sends. */
const statusEndpoint: SafeFetch = async (url) => {
  const list = await storage.getStatusList(url);
  return {
    ok: list !== null,
    status: list === null ? 404 : 200,
    json: async () => JSON.parse(JSON.stringify(list)) as unknown,
  };
};
/** The list served at `url`, as a reader receives it. */
const servedAt = async (url: string) => (await (await statusEndpoint(url)).json()) as Record<string, unknown>;

// The entry goes on the hop as the manager wrote it: no cast, and no member changed.
const hop = await signCardHop(issuer, {
  id: 'urn:example:issuer-to-agent',
  invoker: agent.did,
  invocationTarget: RESOURCE,
  parentCapability: RESOURCE,
  allowedAction: [ACTION],
  credentialStatus: entry,
});
const guard = requireDelegation({
  resource: RESOURCE,
  trustedRootIssuers: [issuer.did],
  verifyHopProof: createDelegationProofVerifier({ didResolver }),
  checkRevocation: createRevocationChecker({
    fetch: statusEndpoint,
    verifyStatusList: createStatusListProofVerifier({ didResolver }),
  }),
});
const call = (): Promise<DelegationGateResult> =>
  guard({ meta: toDelegationChainMeta([hop]), proofDid: agent.did, action: ACTION });

await runCases('bitstring-status-lists', "a manager built with format 'BitstringStatusList' issues lists and entries the Entity Card guard reads, and goes on revoking on the StatusList2021 lists published before", [
  {
    name: 'control: the entry is a BitstringStatusListEntry of the W3C list, and the call passes, fresh',
    run: async () => {
      assert.equal(entry.type, 'BitstringStatusListEntry');
      assert.equal(entry.statusListCredential, `${W3C_URL}/revocation/v1`);
      assert.notEqual(entry.id, entry.statusListCredential);
      const result = await call();
      assert.ok(result.ok, result.ok ? '' : `refused as ${result.refusalCode}: ${result.error.reasons.join('; ')}`);
      assert.equal(result.fresh, true);
    },
  },
  {
    name: 'the list served is a BitstringStatusListCredential that states validFrom, validUntil and its ttl',
    run: async () => {
      const list = await servedAt(entry.statusListCredential);
      const subject = list.credentialSubject as Record<string, unknown>;
      assert.deepEqual(list['@context'], ['https://www.w3.org/ns/credentials/v2']);
      assert.deepEqual(list.type, ['VerifiableCredential', 'BitstringStatusListCredential']);
      assert.deepEqual([subject.type, subject.statusPurpose, subject.ttl], ['BitstringStatusList', 'revocation', TTL_MS]);
      assert.deepEqual([list.issuanceDate, list.expirationDate], [undefined, undefined]);
      const [from, until] = [Date.parse(String(list.validFrom)), Date.parse(String(list.validUntil))];
      assert.ok(from <= Date.now() && until > Date.now() + DAY_MS - 60_000 && until <= Date.now() + DAY_MS, `the window is ${String(list.validFrom)} to ${String(list.validUntil)}`);
      assert.equal((list.proof as Record<string, unknown>).cryptosuite, 'eddsa-jcs-2022');
    },
  },
  {
    name: 'once the issuer revokes the entry, the call is refused as delegation_revoked',
    run: async () => {
      await lists.updateStatus(entry, true);
      const result = await call();
      assert.equal(result.ok, false, 'the call was let through');
      assert.equal(!result.ok && result.refusalCode, 'delegation_revoked');
    },
  },
  {
    name: 'the same manager revokes on the StatusList2021 list published before, signed again as a StatusList2021Credential',
    run: async () => {
      assert.equal(entryBefore.statusListCredential, `${BEFORE_URL}/revocation/v1`);
      assert.equal(await lists.checkStatus(entryBefore), false);
      await lists.updateStatus(entryBefore, true);
      assert.equal(await lists.checkStatus(entryBefore), true);
      const list = await servedAt(entryBefore.statusListCredential);
      const subject = list.credentialSubject as Record<string, unknown>;
      assert.deepEqual(list.type, ['VerifiableCredential', 'StatusList2021Credential']);
      assert.deepEqual([subject.type, subject.ttl, list.validUntil], ['StatusList2021', undefined, undefined]);
      assert.ok(Date.parse(String(list.expirationDate)) > Date.now(), `the list ends at ${String(list.expirationDate)}`);
    },
  },
  {
    name: 'a manager allocates no entry on a list of the other format, and says what to set',
    run: async () => {
      const refused = await managerWith({ format: 'BitstringStatusList', statusListBaseUrl: BEFORE_URL })
        .allocateStatusEntry('revocation')
        .then(() => undefined, (error: unknown) => error);
      assert.ok(refused instanceof TypeError, `expected a TypeError, got ${String(refused)}`);
      assert.match(refused.message, /is a StatusList2021, and this manager allocates the entries of a BitstringStatusList: set format to "StatusList2021", or give the manager a statusListBaseUrl of its own$/);
    },
  },
  {
    name: 'a ttl is refused where the manager is built unless its format is BitstringStatusList',
    run: () => {
      assert.throws(() => managerWith({ statusListBaseUrl: BEFORE_URL, ttl: TTL_MS }), TypeError);
      assert.throws(() => managerWith({ format: 'StatusList2021', ttl: TTL_MS }), /ttl is a member of a BitstringStatusList/);
    },
  },
]);
