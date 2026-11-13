/**
 * The card checker reads a hop's `statusListIndex` only as a non-negative decimal string. A signed
 * entry is JSON, so its index may be a number or an array; the checker refuses either, never
 * converting it, so it never reads a bit the entry did not name in the form the data model gives.
 */

import { describe, it, expect } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { createRevocationChecker } from '../revocation.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import { NOW_MS, parties, serve, statusList, STATUS_URL } from './signed-chain-helpers.js';

const didResolver = createDidKeyResolver();

describe('the card checker and an index that is not a string', () => {
  it('refuses the number 7 and the array ["7"] on a list whose bit 7 is clear, and reads the string "7"', async () => {
    const p = parties();
    const check = createRevocationChecker({
      fetch: serve(statusList(p.acme)),
      now: () => NOW_MS,
      verifyStatusList: createStatusListProofVerifier({ didResolver }),
    });
    const context = { credentialIssuer: p.acme.did };
    expect(await check({ statusListCredential: STATUS_URL, statusListIndex: '7' }, context)).toEqual({ revoked: false, fresh: true });
    for (const statusListIndex of [7, ['7']]) {
      const entry = { statusListCredential: STATUS_URL, statusListIndex } as unknown as { statusListCredential: string; statusListIndex: string };
      expect(await check(entry, context)).toEqual({ revoked: true, fresh: false });
    }
  });
});
