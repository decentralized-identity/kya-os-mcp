/**
 * KYA-OS Entity Card proof — the default Ed25519 minting seam.
 *
 * `ed25519SignerFromJwk` wraps an Ed25519 private JWK into a {@link ProofSigner}: it produces a
 * DETACHED EdDSA JWS (`protectedHeader..signature`) over the JCS-canonical covered claims and
 * pre-computes the RFC 7638 thumbprint (`jkt`) of the public half for the `cnf` fusion. Uses
 * `jose` directly (already a dependency) — no `mcp-i-core` runtime dependency leaks in. Callers
 * with a KMS / HSM key can implement {@link ProofSigner} themselves; this is the batteries-included
 * path for in-process keys.
 */

import { FlattenedSign, calculateJwkThumbprint, importJWK } from 'jose';
import type { JWK } from 'jose';
import { base64urlEncodeFromBytes } from '../../utils/base64.js';
import { ed25519SignRaw, es256SignRaw } from './canonical.js';
import type { Ed25519PrivateJwk, P256PrivateJwk, ProofSigner } from './types.js';

/** Shared detached-JWS producer: `protectedHeader..signature` with the given `alg` + `kid` (DRY). */
function detachedJwsSign(
  key: Awaited<ReturnType<typeof importJWK>>,
  alg: 'EdDSA' | 'ES256',
  kid: string,
): (payload: Uint8Array) => Promise<string> {
  return async (payload) => {
    const flattened = await new FlattenedSign(payload).setProtectedHeader({ alg, kid }).sign(key);
    return `${flattened.protected ?? ''}..${flattened.signature}`;
  };
}

/**
 * Build a {@link ProofSigner} from an Ed25519 private JWK. The raw key is imported ONCE and never
 * serialized back out; `jkt` is the RFC 7638 thumbprint of the public half (`{kty,crv,x}`), which
 * is what `cnf.jkt` and the sender-constraint fusion compare against.
 */
export async function ed25519SignerFromJwk(opts: {
  did: string;
  kid: string;
  privateJwk: Ed25519PrivateJwk;
}): Promise<ProofSigner> {
  const key = await importJWK(opts.privateJwk as JWK, 'EdDSA');
  const publicJwk: JWK = { kty: 'OKP', crv: 'Ed25519', x: opts.privateJwk.x };
  const jkt = await calculateJwkThumbprint(publicJwk, 'sha256');
  const rawJwk = { kty: 'OKP', crv: 'Ed25519', x: opts.privateJwk.x, d: opts.privateJwk.d };
  return {
    did: opts.did,
    kid: opts.kid,
    jkt,
    alg: 'EdDSA',
    sign: detachedJwsSign(key, 'EdDSA', opts.kid),
    signRaw: (payload) => ed25519SignRaw(rawJwk, payload).then(base64urlEncodeFromBytes),
  };
}

/**
 * Build a {@link ProofSigner} from a P-256 private JWK — the ES256 (ECDSA, FIPS-eligible) path.
 * Same shape as {@link ed25519SignerFromJwk}: RFC 7638 `jkt` over the public half `{kty,crv,x,y}`,
 * a detached ES256 JWS, and the raw `ecdsa-p256-sha256` RFC 9421 sibling via {@link es256SignRaw}.
 */
export async function es256SignerFromJwk(opts: {
  did: string;
  kid: string;
  privateJwk: P256PrivateJwk;
}): Promise<ProofSigner> {
  const key = await importJWK(opts.privateJwk as JWK, 'ES256');
  const publicJwk: JWK = { kty: 'EC', crv: 'P-256', x: opts.privateJwk.x, y: opts.privateJwk.y };
  const jkt = await calculateJwkThumbprint(publicJwk, 'sha256');
  const rawJwk = { kty: 'EC', crv: 'P-256', x: opts.privateJwk.x, y: opts.privateJwk.y, d: opts.privateJwk.d };
  return {
    did: opts.did,
    kid: opts.kid,
    jkt,
    alg: 'ES256',
    sign: detachedJwsSign(key, 'ES256', opts.kid),
    signRaw: (payload) => es256SignRaw(rawJwk, payload).then(base64urlEncodeFromBytes),
  };
}
