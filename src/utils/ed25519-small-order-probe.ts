/**
 * Whether an Ed25519 public key that cannot be read back is a point of small order, told by what
 * it verifies rather than by its bytes.
 *
 * Under a key A of small order, the signature R = the identity, S = 0 satisfies the verification
 * equation [S]B = R + [k]A, with the cofactor or without it, whenever the challenge
 * k = SHA-512(R || A || M) mod L is a multiple of A's order. {@link SMALL_ORDER_PROBE_MESSAGE} is a
 * message M for which k is such a multiple for each of the fourteen small-order encodings
 * libsodium blocks (the seven `ed25519-public-key.ts` lists, under either sign bit), so every key
 * on a small-order point verifies the probe. Under any other key, which has a component of large
 * order, the probe verifies only if k is 0 mod L, a forgery nobody can arrange. So one WebCrypto
 * `verify` call tells the two apart for a key imported non-extractable, on any runtime.
 *
 * Internal: not re-exported from the package.
 */

/**
 * The first `org.kya-os.ed25519-small-order-probe.v1:<n>`, counting n from 0, whose challenge is a
 * multiple of the order of every small-order encoding; a test checks that it is.
 */
export const SMALL_ORDER_PROBE_MESSAGE = 'org.kya-os.ed25519-small-order-probe.v1:945740';

/** R = the identity's encoding, 1 then 31 zero bytes, and S = 0. */
export const SMALL_ORDER_PROBE_SIGNATURE: Uint8Array<ArrayBuffer> = Uint8Array.from({ length: 64 }, (_, i) => (i === 0 ? 1 : 0));

const PROBE_MESSAGE_BYTES = new TextEncoder().encode(SMALL_ORDER_PROBE_MESSAGE);

const verdicts = new WeakMap<CryptoKey, Promise<boolean>>();

/**
 * True if WebCrypto verifies the probe under `key`, an Ed25519 public key: the key is on a point
 * of small order. False for any other key, and for a key WebCrypto will not verify with, such as
 * one imported without the `verify` usage, which no verifier can use either. Asked once per key.
 */
export function verifiesSmallOrderProbe(key: CryptoKey): Promise<boolean> {
  let verdict = verdicts.get(key);
  if (verdict === undefined) {
    verdict = crypto.subtle
      .verify({ name: 'Ed25519' }, key, SMALL_ORDER_PROBE_SIGNATURE, PROBE_MESSAGE_BYTES)
      .catch(() => false);
    verdicts.set(key, verdict);
  }
  return verdict;
}
