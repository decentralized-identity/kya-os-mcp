/**
 * Replay admission shared by detached proofs, handshakes and card proofs.
 *
 * A provider's atomic `consume()` decides admission when it exists. Providers
 * written before `consume()` existed fall back to `has()` then `add()`, which
 * works for sequential requests but lets concurrent duplicates of one proof
 * through. The fallback keeps those providers working and warns once per
 * provider; `requireAtomicNonce` refuses it instead.
 */

import { logger } from '../logging/index.js';

/** The replay-store surface admission needs; both nonce cache contracts satisfy it. */
export interface NonceAdmissionStore {
  consume?(nonce: string, ttlSeconds: number, agentDid?: string): Promise<boolean>;
  has(nonce: string, agentDid?: string): Promise<boolean>;
  add(nonce: string, ttlSeconds: number, agentDid?: string): Promise<void>;
}

export interface NonceAdmissionOptions {
  /** Deny rather than fall back when the store has no atomic consume(). */
  requireAtomicNonce?: boolean;
}

const warnedStores = new WeakSet<object>();

/**
 * Check a store when a verifier is built: accept an atomic store, refuse a
 * non-atomic one under `requireAtomicNonce`, and otherwise warn once per store
 * about the has()/add() fallback. Repeat calls stay silent.
 */
export function checkNonceStore(
  store: NonceAdmissionStore,
  options: NonceAdmissionOptions = {},
): void {
  if (typeof store.consume === 'function') return;
  if (options.requireAtomicNonce) {
    throw new TypeError('requireAtomicNonce is set but the nonce cache has no consume()');
  }
  if (warnedStores.has(store)) return;
  warnedStores.add(store);
  logger.warn(
    '[kya-os] Nonce cache has no atomic consume(); falling back to has() then add(). ' +
      'Concurrent duplicates of one signed request can both be admitted. ' +
      'Implement consume() with a conditional insert in the shared store, and set ' +
      'requireAtomicNonce to refuse this fallback.',
  );
}

/**
 * Admit a nonce that has already passed every other check. Returns true only
 * for the call that admits it. Storage failures, and a missing consume() under
 * `requireAtomicNonce`, reject so callers deny the request.
 */
export async function admitNonce(
  store: NonceAdmissionStore,
  nonce: string,
  ttlSeconds: number,
  agentDid?: string,
  options: NonceAdmissionOptions = {},
): Promise<boolean> {
  const consume = store.consume;
  if (typeof consume === 'function') {
    return (await consume.call(store, nonce, ttlSeconds, agentDid)) === true;
  }
  checkNonceStore(store, options);
  if (await store.has(nonce, agentDid)) return false;
  await store.add(nonce, ttlSeconds, agentDid);
  return true;
}
