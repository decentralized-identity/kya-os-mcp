/**
 * The delegation side's status-list readers hold a list to the validity window it states, as the
 * Card's checker does (`utils/statuslist-validity.ts`): the cheqd resolver and the
 * StatusList2021Manager each refuse a list past its `expirationDate` or before its `issuanceDate` as
 * `status_unavailable`, saying when, and read one inside its window or stating no end. Each reads a
 * real signed list, through the public `DelegationCredentialVerifier` as an adopter wires them.
 */

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  DelegationCredentialVerifier,
  type CredentialStatus,
  type StatusList2021Credential,
  type StatusListResolver,
} from '../../index.js';
import { CheqdStatusListResolver } from '../../integrations/cheqd/index.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
  createRealStatusListManager,
  type RealStatusListSetup,
} from '../../__tests__/audit/helpers/crypto-helpers.js';
import { keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { createDidKeyResolver } from '../index.js';
import { canonicalizeJSON } from '../utils.js';
import { base64urlEncodeFromBytes } from '../../utils/base64.js';
import { statusListGzipCodec } from '../../utils/statuslist-gzip.js';
import type { AgentIdentity, FetchProvider } from '../../providers/base.js';

const BASE = 'https://status.example';
const HOUR = 60 * 60 * 1000;
const PAST = new Date(Date.now() - HOUR).toISOString();
const FUTURE = new Date(Date.now() + HOUR).toISOString();

const crypto = createRealCryptoProvider();
let issuer: AgentIdentity;
let pinned: AgentIdentity;
let setup: RealStatusListSetup;
let entry: CredentialStatus;
let listUrl: string;
let current: StatusList2021Credential;
/** What the list's URL serves, and how many times it was fetched. */
let served: unknown;
let fetches = 0;

const fetchProvider = {
  async fetch() {
    fetches += 1;
    return new Response(JSON.stringify(served), { status: 200 });
  },
} as unknown as FetchProvider;

beforeAll(async () => {
  issuer = await keyOf('did:web:acme.example', 'assert-1');
  pinned = await createRealIdentity(crypto);
  setup = createRealStatusListManager(crypto, pinned, { statusListBaseUrl: BASE });
  entry = await setup.manager.allocateStatusEntry('revocation');
  listUrl = entry.statusListCredential;
  const stored = await setup.storage.getStatusList(listUrl);
  if (!stored) throw new Error('fixture: status list not stored');
  current = stored;
});

afterEach(() => {
  vi.useRealTimers();
  fetches = 0;
});

/** The pinned issuer's list with `dates` over its own, signed again by its key. */
async function listStating(dates: Record<string, string>): Promise<StatusList2021Credential> {
  const { proof, ...unsigned } = current as StatusList2021Credential & { proof: Record<string, unknown> };
  const changed = { ...unsigned, ...dates };
  const signature = await crypto.sign(new TextEncoder().encode(canonicalizeJSON(changed)), pinned.privateKey);
  return { ...changed, proof: { ...proof, proofValue: base64urlEncodeFromBytes(signature) } } as StatusList2021Credential;
}

/** A cheqd resolver pinned to the list's issuer, keeping a verified list for `cacheTtlMs`. */
const cheqd = (cacheTtlMs = 0): StatusListResolver =>
  new CheqdStatusListResolver({
    fetchProvider,
    didResolver: createDidKeyResolver(),
    cryptoProvider: crypto,
    expectedIssuerDid: pinned.did,
    decompressor: statusListGzipCodec,
    cacheTtlMs,
  });

/** The verifier's verdict on a credential whose status `resolver` reads. */
async function verdictOf(resolver: StatusListResolver) {
  const credential = await signedCredential(issuer, { credentialStatus: entry });
  return new DelegationCredentialVerifier({ statusListResolver: resolver }).verifyDelegationCredential(credential, {
    skipSignature: true,
    skipCache: true,
  });
}

describe('the cheqd status list resolver holds a list to its validity window', () => {
  it('reads a list inside its window', async () => {
    served = await listStating({ expirationDate: FUTURE });
    expect((await verdictOf(cheqd())).valid).toBe(true);
  });

  it.each([
    ['past its expirationDate', { expirationDate: PAST }, `status list expired at "${PAST}" (its expirationDate)`],
    ['before its issuanceDate', { issuanceDate: FUTURE }, `status list is not valid until "${FUTURE}" (its issuanceDate)`],
  ])('refuses a list %s as status_unavailable, saying when', async (_label, dates, words) => {
    served = await listStating(dates);
    const result = await verdictOf(cheqd());
    expect(result).toMatchObject({ valid: false, stage: 'status', code: 'status_unavailable', transient: true });
    expect(result.reason).toContain(words);
  });

  it('reads again, rather than from its cache, a list whose window ended while it was kept', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const resolver = cheqd(10 * HOUR);
    served = await listStating({ expirationDate: FUTURE });
    expect((await verdictOf(resolver)).valid).toBe(true);
    // The issuer republishes before the kept list's window ends, and the clock passes its end.
    served = await listStating({ expirationDate: new Date(Date.now() + 4 * HOUR).toISOString() });
    vi.setSystemTime(Date.now() + 2 * HOUR);
    expect((await verdictOf(resolver)).valid).toBe(true);
    expect(fetches).toBe(2);
  });
});

describe('the StatusList2021Manager holds a list it keeps to its validity window', () => {
  it('reads its own list, which states no end, as before', async () => {
    expect((await verdictOf(setup.manager)).valid).toBe(true);
  });

  it('refuses a list it keeps past its expirationDate as status_unavailable, saying when', async () => {
    await setup.storage.setStatusList(listUrl, await listStating({ expirationDate: PAST }));
    try {
      const result = await verdictOf(setup.manager);
      expect(result).toMatchObject({ valid: false, stage: 'status', code: 'status_unavailable', transient: true });
      expect(result.reason).toContain(`status list expired at "${PAST}" (its expirationDate)`);
    } finally {
      await setup.storage.setStatusList(listUrl, current);
    }
  });
});
