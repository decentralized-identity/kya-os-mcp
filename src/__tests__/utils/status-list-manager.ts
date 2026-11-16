/**
 * A `StatusList2021Manager` over in-memory storage that signs its lists with a real Ed25519 key
 * and serves them under `https://status.example`, for the tests of what the manager reads and
 * writes.
 */
import {
  createRealCryptoProvider,
  createRealIdentity,
  createRealStatusListManager,
  type RealStatusListSetup,
} from '../audit/helpers/crypto-helpers.js';

export async function realStatusListManager(): Promise<RealStatusListSetup> {
  const crypto = createRealCryptoProvider();
  return createRealStatusListManager(crypto, await createRealIdentity(crypto), {
    statusListBaseUrl: 'https://status.example',
  });
}
