/**
 * StatusList2021Manager reads and writes one bit per entry, so it refuses an entry whose
 * `statusSize` is not 1 before it reads its storage. Bitstring Status List v1.0 has an entry of two
 * bits at index 7 keep its value at bits 14 and 15; bit 7 belongs to entry 3. Reading bit 7 for it
 * would pass a credential whose value is set and refuse one on another entry's status. The
 * delegation verifier denies such a credential as `status_unresolvable`, with the reason, and
 * `withStatusCache` never answers one entry from the verdict it keeps for an entry of another size.
 */
import { describe, expect, it } from 'vitest';
import { createRealSignatureVerifier } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { realStatusListManager } from '../../__tests__/utils/status-list-manager.js';
import {
  MALFORMED_STATUS_SIZES,
  malformedSizeReason,
  TWO_BIT_MESSAGES,
  wideSizeReason,
} from '../../__tests__/utils/status-sizes.js';
import type { CredentialStatus } from '../../types/protocol.js';
import { withStatusCache } from '../status-cache.js';
import { DelegationCredentialVerifier, type StatusListResolver } from '../vc-verifier.js';

/** A manager with 16 entries allocated, `revoked` of them set, its entry 7, and a count of its storage reads. */
async function managerWith(revoked: number[]) {
  const { manager, storage } = await realStatusListManager();
  const entries: CredentialStatus[] = [];
  for (let index = 0; index < 16; index += 1) entries.push(await manager.allocateStatusEntry('revocation'));
  for (const index of revoked) await manager.updateStatus(entries[index]!, true);
  let reads = 0;
  const read = storage.getStatusList.bind(storage);
  storage.getStatusList = (id) => {
    reads += 1;
    return read(id);
  };
  return { manager, storage, entry: entries[7]!, reads: () => reads };
}
const twoBits = (entry: CredentialStatus): CredentialStatus => ({ ...entry, statusSize: 2, statusMessage: TWO_BIT_MESSAGES });

/** How the delegation verifier reads a credential whose status is `entry`, through `statusListResolver`. */
async function verified(entry: CredentialStatus, statusListResolver: StatusListResolver) {
  const issuer = await keyOf('did:web:root.example', 'key');
  const verifier = new DelegationCredentialVerifier({
    didResolver: { resolve: async (did) => (did === issuer.did ? issuerDidDocument(methodOf(issuer)) : null) },
    signatureVerifier: createRealSignatureVerifier(new NodeCryptoProvider()),
    statusListResolver,
  });
  const credential = await signedCredential(issuer, { record: delegationRecord(issuer.did), credentialStatus: entry });
  return verifier.verifyDelegationCredential(credential, { skipCache: true });
}

describe('StatusList2021Manager.checkStatus and an entry of two bits', () => {
  it.each([
    ['its value is set at bits 14 and 15 and bit 7 is clear', [14, 15]],
    ['only bit 7, which is entry 3 of two bits, is set', [7]],
    ['its list is clear', []],
  ])('refuses the entry, and reads no list, when %s', async (_label, revoked) => {
    const { manager, entry, reads } = await managerWith(revoked);
    await expect(manager.checkStatus(twoBits(entry))).rejects.toThrow(new Error(wideSizeReason(2)));
    expect(reads()).toBe(0);
    expect(await verified(twoBits(entry), manager)).toMatchObject({
      valid: false,
      stage: 'status',
      statusOutcome: 'status_unresolvable',
      reason: `Status check error: ${wideSizeReason(2)}`,
    });
    expect(reads()).toBe(0);
  });

  it.each([
    ['states a statusSize of 1', { statusSize: 1 }],
    ['states no statusSize', {}],
  ])('reads the bit at the index of an entry that %s', async (_label, members) => {
    const clear = await managerWith([6, 8, 14, 15]);
    expect(await clear.manager.checkStatus({ ...clear.entry, ...members })).toBe(false);
    expect(await verified({ ...clear.entry, ...members }, clear.manager)).toMatchObject({ valid: true });
    const set = await managerWith([7]);
    expect(await set.manager.checkStatus({ ...set.entry, ...members })).toBe(true);
    expect(await verified({ ...set.entry, ...members }, set.manager)).toMatchObject({ valid: false, statusOutcome: 'revoked' });
  });

  it.each(MALFORMED_STATUS_SIZES)('refuses an entry whose statusSize is %s, and reads no list', async (_label, statusSize, named) => {
    const { manager, entry, reads } = await managerWith([]);
    await expect(manager.checkStatus({ ...entry, statusSize })).rejects.toThrow(new Error(malformedSizeReason(named)));
    expect(reads()).toBe(0);
  });
});

describe('StatusList2021Manager.updateStatus and an entry that is not one bit wide', () => {
  it('sets no bit for it, since the bit at its index is another entry\'s', async () => {
    const { manager, storage, entry, reads } = await managerWith([]);
    const before = await storage.getStatusList(entry.statusListCredential);
    const readsBefore = reads();
    await expect(manager.updateStatus(twoBits(entry), true)).rejects.toThrow(new Error(wideSizeReason(2)));
    await expect(manager.updateStatus({ ...entry, statusSize: 0 }, true)).rejects.toThrow(new Error(malformedSizeReason('0')));
    expect(reads()).toBe(readsBefore);
    expect(await storage.getStatusList(entry.statusListCredential)).toEqual(before);
    await manager.updateStatus({ ...entry, statusSize: 1 }, true);
    expect(await manager.checkStatus(entry)).toBe(true);
  });
});

describe('withStatusCache and entries of different sizes at one index', () => {
  it('asks its resolver about each, and never answers one from the other\'s verdict', async () => {
    const asked: unknown[] = [];
    const resolver: StatusListResolver = {
      checkStatus: async (status) => {
        asked.push(status.statusSize);
        return status.statusSize === 2;
      },
    };
    const cached = withStatusCache(resolver, { maxStalenessMs: 60_000 });
    const { entry } = await managerWith([]);
    expect(await cached.checkStatus(entry)).toBe(false);
    expect(await cached.checkStatus(twoBits(entry))).toBe(true);
    expect(await cached.checkStatus({ ...entry, statusSize: 1 })).toBe(false);
    expect(await cached.checkStatus(entry)).toBe(false);
    expect(await cached.checkStatus(twoBits(entry))).toBe(true);
    expect(asked).toEqual([undefined, 2, 1]);
  });

  it('passes the refusal of an entry of two bits on from the manager, uncached', async () => {
    const { manager, entry } = await managerWith([14, 15]);
    const cached = withStatusCache(manager, { maxStalenessMs: 60_000 });
    expect(await cached.checkStatus(entry)).toBe(false);
    await expect(cached.checkStatus(twoBits(entry))).rejects.toThrow(new Error(wideSizeReason(2)));
  });
});
