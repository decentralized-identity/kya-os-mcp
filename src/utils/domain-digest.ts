/**
 * The domain-separated digest the delegation layer takes of a value: `SHA-256(UTF8(domain) || 0x00
 * || bytes)`, written as `sha256:` and 64 lowercase hex digits. A credential digest and a chain
 * digest (SPEC.md §7.8) and the session anchor a forwarding server sends downstream (SPEC.md §8.1)
 * are each one, under a domain of its own, so a digest of one kind never stands for another.
 *
 * Pure but for {@link webCryptoSha256}: no transport, no framework, no key material.
 */

import type { Digest } from '../audit/types.js';
import { WebCryptoProvider } from '../providers/web-crypto.js';

/** Bytes to `sha256:<64 lowercase hex>`: bind a `CryptoProvider.hash`. */
export type Sha256 = (bytes: Uint8Array) => Promise<string>;

const webCrypto = new WebCryptoProvider();

/** {@link Sha256} through WebCrypto, for a digest the library takes where no `CryptoProvider` is handed to it. */
export const webCryptoSha256: Sha256 = (bytes) => webCrypto.hash(bytes);

const encoder = new TextEncoder();

/** `SHA-256(UTF8(domain) || 0x00 || bytes)` through `hash`, where `bytes` is a value's RFC 8785 bytes. */
export async function domainDigest(domain: string, bytes: Uint8Array, hash: Sha256): Promise<Digest> {
  const prefix = encoder.encode(`${domain}\0`);
  const input = new Uint8Array(prefix.length + bytes.length);
  input.set(prefix);
  input.set(bytes, prefix.length);
  return (await hash(input)) as Digest;
}
