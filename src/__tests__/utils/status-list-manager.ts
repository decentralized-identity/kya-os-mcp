/**
 * A `StatusList2021Manager` over in-memory storage that signs its lists with a real Ed25519 key
 * and serves them under `https://status.example`, for the tests of what the manager reads and
 * writes.
 */
import {
  createRealCryptoProvider,
  createRealIdentity,
  createRealSigningFunction,
  type RealStatusListSetup,
} from '../audit/helpers/crypto-helpers.js';
import { StatusList2021Manager, type StatusList2021ManagerOptions } from '../../delegation/statuslist-manager.js';
import { MemoryStatusListStorage } from '../../delegation/storage/memory-statuslist-storage.js';
import type { VCSigningFunction } from '../../delegation/vc-issuer.js';
import type { AgentIdentity } from '../../providers/base.js';
import { statusListGzipCodec } from '../../utils/statuslist-gzip.js';

/** A manager, its store, and the identity that signs its lists. */
export interface StatusListIssuerSetup extends RealStatusListSetup {
  issuer: AgentIdentity;
}

/** What a manager is built over when a test does not leave it its own: a store, an identity, a signing function. */
export interface StatusListIssuerParts {
  storage?: MemoryStatusListStorage;
  issuer?: AgentIdentity;
  /** How the manager signs a list. Default: an `Ed25519Signature2020` proof by `issuer`'s key. */
  sign?: VCSigningFunction;
}

/**
 * A manager built with `options`, which may name another base URL, over `parts`, each of which it
 * makes for itself when not given: so a second manager over the first one's store and identity is
 * `statusListIssuer(options, first)`.
 */
export async function statusListIssuer(
  options: StatusList2021ManagerOptions = {},
  parts: StatusListIssuerParts = {},
): Promise<StatusListIssuerSetup> {
  const crypto = createRealCryptoProvider();
  const issuer = parts.issuer ?? (await createRealIdentity(crypto));
  const storage = parts.storage ?? new MemoryStatusListStorage();
  const manager = new StatusList2021Manager(
    storage,
    { getDid: () => issuer.did, getKeyId: () => issuer.kid },
    parts.sign ?? createRealSigningFunction(crypto, issuer),
    statusListGzipCodec,
    statusListGzipCodec,
    { statusListBaseUrl: 'https://status.example', ...options },
  );
  return { manager, storage, issuer };
}

export async function realStatusListManager(): Promise<RealStatusListSetup> {
  return statusListIssuer();
}
