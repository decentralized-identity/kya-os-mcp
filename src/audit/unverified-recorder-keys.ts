/**
 * The warnings a recorder or a checkpoint builder gives when it builds on
 * journal entries it does not verify: a builder whose derived verifier cannot
 * check entries recorded under another key than its signer's, and either one
 * when no verifier is passed and its signer derives none.
 */
import { logger } from '../logging/index.js';
import { canonicalizeJson } from '../utils/canonical-json.js';
import { sanitizeForMessage } from '../utils/message-text.js';
import { warnOncePerProcess } from '../utils/warn-once.js';
import type { SignerRef } from './types.js';

/**
 * The most recorder keys a process names in a warning. A writer of the
 * journal store chooses the keys its entries name, so the warnings, and the
 * record of which keys were named, are bounded.
 */
export const MAX_WARNED_RECORDER_KEYS = 32;

/** Where every copy of this package records the keys it has warned of. */
const WARNED = Symbol.for('@kya-os/mcp/audit-unverified-recorder-keys');

/** Where every copy of this package records that it warned of a journal trusted as written. */
const TRUSTED_AS_WRITTEN_WARNED = Symbol.for('@kya-os/mcp/audit-journal-trusted-as-written-warned');

/** Fixed words: nothing a writer of the journal store chose is in them. */
const TRUSTED_AS_WRITTEN_WARNING =
  '[kya-os] An audit recorder or checkpoint builder trusts its journal as written: it was given no signatures, ' +
  'and its signer yields no public key and names no Ed25519 did:key that it signs with, so the stored entries it ' +
  'builds on are not verified. Pass signatures that resolve the recorder key, or give the signer a verifier().';

/**
 * Warns, once per process, that a recorder or a checkpoint builder trusts its
 * journal as written, for want of any verifier of its signer's signatures.
 */
export function warnJournalTrustedAsWritten(): void {
  warnOncePerProcess(TRUSTED_AS_WRITTEN_WARNED, TRUSTED_AS_WRITTEN_WARNING);
}

/** Where every copy of this package records that it stopped naming keys. */
const MORE_WARNED = Symbol.for('@kya-os/mcp/audit-unverified-recorder-keys-more');

/** Fixed words, for the keys past the bound. */
const MORE_KEYS_WARNING =
  '[kya-os] An audit checkpoint builder trusted as written journal entries recorded under more keys than ' +
  'this process names. Pass signatures that resolve the recorder keys to verify them.';

/**
 * Warns, once per process for each key reference `ref`, that a checkpoint
 * builder trusted as written the entries recorded under it. The reference is
 * quoted as JSON with every character that does not print replaced, since a
 * writer of the journal store may have written it.
 */
export function warnUnverifiedRecorderKey(ref: SignerRef): void {
  const registry = globalThis as { [key: symbol]: Set<string> | undefined };
  const warned = (registry[WARNED] ??= new Set<string>());
  const key = canonicalizeJson({ did: ref.did, kid: ref.kid, alg: ref.alg });
  if (warned.has(key)) return;
  if (warned.size >= MAX_WARNED_RECORDER_KEYS) {
    warnOncePerProcess(MORE_WARNED, MORE_KEYS_WARNING);
    return;
  }
  warned.add(key);
  logger.warn(
    '[kya-os] An audit checkpoint builder trusted as written the journal entries recorded under the key ' +
      `${sanitizeForMessage(key, 1024)}: it verifies with a verifier derived from its own signer's key, ` +
      'which cannot check another key. Pass signatures that resolve that key to verify them.',
  );
}
