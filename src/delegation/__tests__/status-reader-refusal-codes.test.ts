/**
 * The status-list resolvers the library ships refuse a status they cannot prove clear by throwing,
 * and the delegation verifier codes the refusal by the step that threw, never by its words: an entry
 * the resolver does not read, a host it refuses, a list that may not answer or whose proof fails,
 * an issuer DID it could not resolve, and a list it could not read. The resolvers are the cheqd
 * resolver and the StatusList2021Manager, each over a real signed list, read through the public
 * `DelegationCredentialVerifier` as an adopter wires them.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import {
  DelegationCredentialVerifier,
  isTransientRefusal,
  type CredentialStatus,
  type DIDResolver,
  type RefusalCode,
  type StatusListResolver,
} from '../../index.js';
import { CheqdStatusListResolver, type CheqdStatusListResolverOptions } from '../../integrations/cheqd/index.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
  createRealStatusListManager,
} from '../../__tests__/audit/helpers/crypto-helpers.js';
import { keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { createDidKeyResolver } from '../index.js';
import type { AgentIdentity, FetchProvider } from '../../providers/base.js';
import type { StatusList2021Manager } from '../statuslist-manager.js';
import { statusListGzipCodec } from '../../utils/statuslist-gzip.js';

const BASE = 'https://status.example';
const REVOKED = 7;
const CLEAR = 3;

let issuer: AgentIdentity;
let pinned: AgentIdentity;
let manager: StatusList2021Manager;
let entries: CredentialStatus[];
let fetchProvider: FetchProvider;
const crypto = createRealCryptoProvider();

beforeAll(async () => {
  issuer = await keyOf('did:web:acme.example', 'assert-1');
  pinned = await createRealIdentity(crypto);
  const setup = createRealStatusListManager(crypto, pinned, { statusListBaseUrl: BASE });
  manager = setup.manager;
  entries = [];
  for (let index = 0; index < 8; index += 1) entries.push(await manager.allocateStatusEntry('revocation'));
  await manager.updateStatus(entries[REVOKED]!, true);
  fetchProvider = {
    async fetch(url: string) {
      const body = await setup.storage.getStatusList(url);
      return new Response(JSON.stringify(body ?? null), { status: body == null ? 404 : 200 });
    },
  } as unknown as FetchProvider;
});

/** A cheqd resolver pinned to the list's issuer, with `options` over its defaults. */
const cheqd = (options: Partial<CheqdStatusListResolverOptions> = {}): StatusListResolver =>
  new CheqdStatusListResolver({
    fetchProvider,
    didResolver: createDidKeyResolver(),
    cryptoProvider: crypto,
    expectedIssuerDid: pinned.did,
    decompressor: statusListGzipCodec,
    cacheTtlMs: 0,
    ...options,
  });

/** The code the verifier refuses a credential with `status` with, read through `resolver`. */
async function refusedWith(resolver: StatusListResolver, status: CredentialStatus): Promise<unknown> {
  const credential = await signedCredential(issuer, { credentialStatus: status });
  const result = await new DelegationCredentialVerifier({ statusListResolver: resolver }).verifyDelegationCredential(
    credential,
    { skipSignature: true, skipCache: true },
  );
  expect(result.stage, result.reason).toBe('status');
  return { code: result.code, transient: result.transient, statusOutcome: result.statusOutcome };
}

/** What a refusal with `code` reads as. */
const coded = (code: RefusalCode, statusOutcome = 'status_unresolvable') => ({ code, transient: isTransientRefusal(code), statusOutcome });

describe('the cheqd status list resolver', () => {
  it.each<[string, () => StatusListResolver, () => CredentialStatus, RefusalCode]>([
    ['a set bit', () => cheqd(), () => entries[REVOKED]!, 'delegation_revoked'],
    ['an entry whose list is not at an https URL', () => cheqd(), () => ({ ...entries[CLEAR]!, statusListCredential: 'http://status.example/revocation/v1' }), 'host_refused'],
    ['an entry two bits wide', () => cheqd(), () => ({ ...entries[CLEAR]!, statusSize: 2 }), 'delegation_malformed'],
    ['an entry whose index is not a decimal string', () => cheqd(), () => ({ ...entries[CLEAR]!, statusListIndex: '+3' }), 'delegation_malformed'],
    ['a list that is not served', () => cheqd(), () => ({ ...entries[CLEAR]!, statusListCredential: `${BASE}/missing` }), 'status_unavailable'],
    ['a list another DID issued', () => cheqd({ expectedIssuerDid: 'did:web:other.example' }), () => entries[CLEAR]!, 'status_signer_untrusted'],
    ['a list whose signature does not verify', () => cheqd({ cryptoProvider: { ...crypto, verify: async () => false } as never }), () => entries[CLEAR]!, 'status_signer_untrusted'],
    [
      "a list whose issuer's DID is not resolved",
      () => cheqd({ didResolver: { resolve: async () => null } satisfies DIDResolver }),
      () => entries[CLEAR]!,
      'did_unavailable',
    ],
  ])('codes %s', async (_name, resolver, status, code) => {
    expect(await refusedWith(resolver(), status())).toEqual(coded(code, code === 'delegation_revoked' ? 'revoked' : 'status_unresolvable'));
  });
});

describe('the StatusList2021Manager as a status list resolver', () => {
  it.each<[string, () => CredentialStatus, RefusalCode]>([
    ['an entry two bits wide', () => ({ ...entries[CLEAR]!, statusSize: 2 }), 'delegation_malformed'],
    ['an entry of another purpose than its list', () => ({ ...entries[CLEAR]!, statusPurpose: 'suspension' }), 'status_signer_untrusted'],
    ['an entry whose list it does not hold', () => ({ ...entries[CLEAR]!, statusListCredential: `${BASE}/missing` }), 'status_unavailable'],
  ])('codes %s', async (_name, status, code) => {
    expect(await refusedWith(manager, status())).toEqual(coded(code));
  });
});
