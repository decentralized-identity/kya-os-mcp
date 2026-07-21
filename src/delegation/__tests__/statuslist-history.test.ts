import { describe, expect, it } from 'vitest';
import { MemoryStatusListStorage } from '../storage/memory-statuslist-storage.js';
import type { StatusList2021Credential } from '../../types/protocol.js';

function credential(encodedList: string): StatusList2021Credential {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    id: 'https://status.example/list',
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    issuer: 'did:key:zIssuer',
    issuanceDate: '2026-01-01T00:00:00Z',
    credentialSubject: {
      id: 'https://status.example/list#list', type: 'StatusList2021',
      statusPurpose: 'revocation', encodedList,
    },
  };
}

describe('historical status-list snapshots', () => {
  it('retains immutable signed versions instead of overwriting replay evidence', async () => {
    const storage = new MemoryStatusListStorage();
    await storage.setStatusList('list', credential('version-1'));
    await storage.setStatusList('list', credential('version-2'));
    expect(await storage.getStatusListVersionCount('list')).toBe(2);
    expect((await storage.getStatusListVersion('list', 1))?.credentialSubject.encodedList)
      .toBe('version-1');
    const historical = await storage.getStatusListVersion('list', 1);
    historical!.credentialSubject.encodedList = 'mutated-copy';
    expect((await storage.getStatusListVersion('list', 1))?.credentialSubject.encodedList)
      .toBe('version-1');
  });
});
