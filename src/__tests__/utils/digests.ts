/**
 * Digests as tests expect and recognise them.
 */
import { createHash } from 'node:crypto';
import { DELEGATION_CREDENTIAL_DIGEST_DOMAIN } from '../../delegation/chain-digest.js';

/**
 * `sha256:` and the hex SHA-256 of `text` as UTF-8, or of bytes: the
 * reference an id is recorded or signed by when it cannot be verbatim. Taken
 * with Node's own hash, not a provider of the library's, so what a test
 * expects does not come from the code it tests.
 */
export const sha256Of = (text: string | Uint8Array): string =>
  `sha256:${createHash('sha256').update(typeof text === 'string' ? Buffer.from(text, 'utf8') : text).digest('hex')}`;

const credentialDomain = new TextEncoder().encode(`${DELEGATION_CREDENTIAL_DIGEST_DOMAIN}\0`);

/**
 * Whether `bytes`, handed to a hash provider, are what a credential digest
 * hashes (SPEC.md §7.8): they begin with its domain. A test that fails or
 * counts those digests, and no other hash, tells them apart by this.
 */
export const isCredentialDigestInput = (bytes: Uint8Array): boolean =>
  credentialDomain.every((byte, index) => bytes[index] === byte);
