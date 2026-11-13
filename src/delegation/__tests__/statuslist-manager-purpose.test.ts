/**
 * StatusList2021Manager.checkStatus holds the list it stored to the entry's `statusPurpose` with the
 * shared acceptance rule: a suspension entry reads its suspension list, and a list of another purpose
 * is refused. Only a list typed as a W3C Bitstring Status List v1.0 list in both places its §2.2
 * names may declare more than one purpose; the StatusList2021 lists the manager writes declare one,
 * as Verifiable Credentials Status List v2021 §2.2 requires.
 */

import { describe, it, expect } from 'vitest';
import {
  createRealCryptoProvider,
  createRealIdentity,
  createRealStatusListManager,
  type RealStatusListSetup,
} from '../../__tests__/audit/helpers/crypto-helpers.js';
import type { CredentialStatus, StatusList2021Credential } from '../../types/protocol.js';

async function realManager(): Promise<RealStatusListSetup> {
  const crypto = createRealCryptoProvider();
  return createRealStatusListManager(crypto, await createRealIdentity(crypto), {
    statusListBaseUrl: 'https://status.example',
  });
}

describe('StatusList2021Manager.checkStatus and the statusPurpose', () => {
  it('reads a suspension entry from its suspension list', async () => {
    const { manager } = await realManager();
    const suspended = await manager.allocateStatusEntry('suspension');
    const active = await manager.allocateStatusEntry('suspension');
    await manager.updateStatus(suspended, true);
    expect(await manager.checkStatus(suspended)).toBe(true);
    expect(await manager.checkStatus(active)).toBe(false);
  });

  /** A revoked entry, and a way to store its list again typed and stating a purpose as given. */
  async function revokedWithList() {
    const { manager, storage } = await realManager();
    const revoked = await manager.allocateStatusEntry('revocation');
    await manager.updateStatus(revoked, true);
    const stored = await storage.getStatusList(revoked.statusListCredential);
    if (!stored) throw new Error('fixture: status list not stored');
    const store = (type: string[], subjectType: string, statusPurpose: unknown) =>
      storage.setStatusList(revoked.statusListCredential, {
        ...stored,
        type,
        credentialSubject: { ...stored.credentialSubject, type: subjectType, statusPurpose },
      } as unknown as StatusList2021Credential);
    return { manager, revoked, store };
  }

  const BITSTRING = ['VerifiableCredential', 'BitstringStatusListCredential'];
  const STATUS_LIST_2021 = ['VerifiableCredential', 'StatusList2021Credential'];

  it("reads a list typed as a Bitstring Status List in both places whose purposes include the entry's", async () => {
    const { manager, revoked, store } = await revokedWithList();
    for (const statusPurpose of [['suspension', 'revocation'], ['revocation']]) {
      await store(BITSTRING, 'BitstringStatusList', statusPurpose);
      expect(await manager.checkStatus(revoked)).toBe(true);
    }
  });

  it('refuses a purpose array on its own StatusList2021 list, and on a list typed as a Bitstring Status List in one place only', async () => {
    const { manager, revoked, store } = await revokedWithList();
    const typings: [string[], string][] = [
      [STATUS_LIST_2021, 'StatusList2021'],
      [BITSTRING, 'StatusList2021'],
      [STATUS_LIST_2021, 'BitstringStatusList'],
    ];
    for (const [type, subjectType] of typings) {
      await store(type, subjectType, ['suspension', 'revocation']);
      await expect(manager.checkStatus(revoked)).rejects.toThrow(
        'status list statusPurpose is an array, which only a BitstringStatusListCredential with a BitstringStatusList ' +
          `subject may state (the entry's is "revocation")`,
      );
      await store(type, subjectType, 'revocation');
      expect(await manager.checkStatus(revoked)).toBe(true);
    }
  });

  it('refuses a list of another purpose', async () => {
    const { manager } = await realManager();
    const entry = await manager.allocateStatusEntry('revocation');
    await expect(manager.checkStatus({ ...entry, statusPurpose: 'suspension' })).rejects.toThrow(
      `status list statusPurpose mismatch: the list's is "revocation" and the entry's is "suspension"`,
    );
  });

  it("quotes at most 64 characters of the entry's purpose and of the list's, naming one that is not a string by its type", async () => {
    const { manager, storage } = await realManager();
    const entry = await manager.allocateStatusEntry('revocation');
    const stored = await storage.getStatusList(entry.statusListCredential);
    if (!stored) throw new Error('fixture: status list not stored');
    const storeWithPurpose = (statusPurpose?: unknown) =>
      storage.setStatusList(entry.statusListCredential, {
        ...stored,
        credentialSubject: { ...stored.credentialSubject, statusPurpose },
      } as unknown as StatusList2021Credential);
    const named: [unknown, string][] = [
      ['p'.repeat(100_000), `"${'p'.repeat(64)}"...`],
      [JSON.parse('{"toString":"revocation"}'), 'of type object'],
    ];
    for (const [statusPurpose, as] of named) {
      const stating = { ...entry, statusPurpose } as CredentialStatus;
      await storeWithPurpose('revocation');
      await expect(manager.checkStatus(stating)).rejects.toThrow(
        `status list statusPurpose mismatch: the list's is "revocation" and the entry's is ${as}`,
      );
      await storeWithPurpose(undefined);
      await expect(manager.checkStatus(stating)).rejects.toThrow(`status list has no statusPurpose (the entry's is ${as})`);
    }
    await storeWithPurpose('l'.repeat(100_000));
    await expect(manager.checkStatus(entry)).rejects.toThrow(
      `status list statusPurpose mismatch: the list's is "${'l'.repeat(64)}"... and the entry's is "revocation"`,
    );
  });
});
