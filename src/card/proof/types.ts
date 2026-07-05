/**
 * KYA-OS Entity Card — stateless per-request holder-of-key proof: shapes + seams.
 *
 * `org.kya-os/proof@1` is the STATELESS, sender-constrained proof profile. It rides its OWN
 * `_meta` key ({@link KYA_OS_CARD_PROOF_META_KEY} = `org.kya-os/proof@1`), DISTINCT from the legacy
 * session-bound `ProofMeta` (which carries `sessionId` + a handshake nonce under
 * `org.kya-os/proof`). Separate keys let the two regimes coexist on one server without either guard
 * seeing — or rejecting — the other's proof. Every request self-proves; there is no session state.
 *
 * All crypto is INJECTED via seams ({@link ProofSigner} for minting, {@link VerifyProofDeps}
 * for verifying) so no runtime (`mcp-i-core`) dependency leaks into `@kya-os/mcp`; the module
 * uses only `jose` + `json-canonicalize`, already direct dependencies.
 */

import { z } from 'zod';
import { Did, PROOF_PROFILE_ID, type ProofPublicJwk } from '../schema.js';

/** The stateless per-request proof profile tag (the `prf` discriminator). */
export const PROOF_PROFILE_V1 = PROOF_PROFILE_ID;

/**
 * The `_meta` key the STATELESS card proof rides under — DISTINCT from the legacy session proof's
 * `org.kya-os/proof` (`KYA_OS_PROOF_META_KEY`). Sharing one key made the two regimes mutually
 * exclusive on a server (a legacy proof failed the card schema and was 401'd; a card proof failed
 * the legacy structure check). With separate keys each guard reads its OWN key and simply does not
 * see the other's proof, so both can run on one server — genuinely additive, no legacy coupling. The
 * key equals the `prf` profile id, so it is self-describing and versioned.
 */
export const KYA_OS_CARD_PROOF_META_KEY = PROOF_PROFILE_V1;

/** Default proof lifetime in seconds (SPEC §8: short-lived, ≤ 60s). */
export const DEFAULT_TTL_SEC = 60;

/** Maximum accepted proof lifetime in seconds — a longer window fails closed. */
export const MAX_TTL_SEC = 60;

/** Default accepted clock skew in seconds (±) for the created/expires window. */
export const DEFAULT_SKEW_SEC = 5;

/**
 * Minimum time a consumed nonce MUST be retained by the replay cache: the FULL verifier
 * acceptance window, PLUS one second of rounding headroom. A proof is accepted while
 * `created - skew ≤ now ≤ expires + skew` (with `expires = created + ttl`) — a window `ttl + 2·skew`
 * wide. But the verifier compares at SECOND granularity and is inclusive at the top, so the last
 * accepting second is honoured in full (up to +999 ms), while a nonce first consumed at the very
 * start of the `created - skew` second is retained from there. Retaining for exactly `ttl + 2·skew`
 * therefore leaves a sub-second tail in which an evicted nonce lets a still-valid proof replay; the
 * `+ 1` closes it. Retention is measured from FIRST use. If a verifier widens `skewSec` beyond
 * {@link DEFAULT_SKEW_SEC}, widen the cache TTL to match.
 */
export const NONCE_RETENTION_SEC = MAX_TTL_SEC + 2 * DEFAULT_SKEW_SEC + 1;

/**
 * base64url charset (RFC 4648 §5, no padding). `nonce` and `cnf.jkt` are embedded VERBATIM into the
 * line-oriented RFC 9421 signature base (see `http-sig.ts`: `"kya-nonce": ${nonce}` / `"kya-cnf":
 * ${jkt}`), so a newline — or any non-base64url byte — would corrupt that base. RFC 7638 thumbprints
 * are base64url by definition, and a 128-bit nonce is CSPRNG base64url/hex, so we reject anything
 * else EARLY at build/parse rather than leaning on the downstream verifier's base reconstruction to
 * fail closed. (`did`/`audience` are DIDs, guarded by {@link Did}; `kid` is guarded below.)
 */
const BASE64URL = /^[A-Za-z0-9_-]+$/;

/** RFC 7638 confirmation key thumbprint (`cnf.jkt`) — the sender-constraint fusion anchor. */
export const CardProofCnfSchema = z.object({
  jkt: z.string().min(1).regex(BASE64URL, 'cnf.jkt must be a base64url RFC 7638 thumbprint'),
});

/**
 * The `org.kya-os/proof@1` payload. Every field except the two signatures (`jws`, `httpSig`) is a
 * COVERED claim: the detached EdDSA `jws` signs the RFC 8785 (JCS) canonicalization of the claims,
 * so tampering any of them fails the signature. `cnf.jkt` is OPTIONAL — present it degrades to
 * L3-minus rather than blocking when the authorization server does not emit an RFC 9449 `cnf`.
 *
 * `httpSig` is the OPTIONAL second signature of the DUAL carrier: a RAW EdDSA signature (base64url,
 * NOT JWS-framed) made by the SAME DID key over the RFC 9421 signature base the HTTP Message
 * Signature sibling exposes. Because it is a raw signature over the exact base a stock RFC 9421
 * verifier reconstructs, that sibling is genuinely cross-verifiable against the resolved DID key
 * (the `jws` framing prepends a protected header, so its bytes could never satisfy a 9421 verifier).
 * It degrades gracefully: a signer without a `signRaw` seam mints a JWS-only proof (no sibling).
 */
export const CardProofMetaSchema = z.object({
  prf: z.literal(PROOF_PROFILE_V1),
  alg: z.enum(['EdDSA', 'ES256']),
  did: Did,
  // The signing key reference MUST carry a `#fragment` (a verificationMethod id); the runtime also
  // binds `kid.split('#')[0] === did`. did:key is base58btc, so the fragment is case-SENSITIVE.
  kid: z.string().regex(/^did:(key|web):.+#.+$/, 'kid must be a DID with a #fragment (e.g. did:web:host#key-1)'),
  audience: Did,
  nonce: z.string().min(1).regex(BASE64URL, 'nonce must be base64url-safe (it is embedded verbatim in the RFC 9421 signature base)'),
  created: z.number().int().nonnegative(),
  expires: z.number().int().nonnegative(),
  requestHash: z.string().min(1),
  cnf: CardProofCnfSchema.optional(),
  jws: z.string().min(1),
  httpSig: z.string().min(1).optional(),
}).strict(); // no unknown fields: the covered-claims set IS the signed contract (matches schema.ts)

export type CardProofCnf = z.infer<typeof CardProofCnfSchema>;
export type CardProofMeta = z.infer<typeof CardProofMetaSchema>;

/** An Ed25519 private JWK (OKP, carries `d`) — the signer's key material, never serialized out. */
export interface Ed25519PrivateJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  d: string;
  kid?: string;
}

/** A P-256 private JWK (EC, carries `d`) — the ES256 signer's key material. */
export interface P256PrivateJwk {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
  d: string;
  kid?: string;
}

/** A proof-signing private JWK — Ed25519 (EdDSA) or P-256 (ES256). */
export type ProofPrivateJwk = Ed25519PrivateJwk | P256PrivateJwk;

/**
 * The minting seam. Holds the entity's identity coordinates + an opaque detached-JWS signer;
 * the module never touches raw key material. `jkt` is the RFC 7638 thumbprint of the signing
 * key, embedded as `cnf.jkt` unless the build context overrides it.
 */
export interface ProofSigner {
  readonly did: string;
  readonly kid: string;
  readonly jkt?: string;
  /** The signing algorithm this signer produces — `EdDSA` (Ed25519) or `ES256` (P-256). Default `EdDSA`. */
  readonly alg?: 'EdDSA' | 'ES256';
  /** Produce a DETACHED JWS (`protectedHeader..signature`) over `payload`, signed with {@link alg}. */
  sign(payload: Uint8Array): Promise<string>;
  /**
   * OPTIONAL: produce a RAW EdDSA signature (base64url, NOT JWS-framed) over `payload` with the
   * SAME key as {@link sign}. Enables the dual-carrier RFC 9421 sibling — the raw signature over
   * the 9421 base is what a stock 9421 verifier reconstructs and checks against the DID key. A
   * signer that omits this mints a JWS-only proof (the sibling degrades away, never breaks).
   */
  signRaw?(payload: Uint8Array): Promise<string>;
}

/** Per-request minting context: who the proof is for, its nonce, lifetime, and cnf override. */
export interface BuildProofContext {
  /** Recipient DID (anti-confused-deputy / anti-relay binding). */
  audience: string;
  /** 128-bit nonce (client-random or server-issued). */
  nonce: string;
  /** Proof lifetime in seconds (default {@link DEFAULT_TTL_SEC}). */
  ttlSec?: number;
  /** Explicit `cnf.jkt` (e.g. the token's RFC 9449 thumbprint); default: the signer's `jkt`. */
  cnfJkt?: string;
  /** Injectable clock returning epoch MILLISECONDS (deterministic tests). */
  now?: () => number;
}

/**
 * Resolve the Ed25519 public key registered for a `kid`.
 *
 * CONTRACT (this seam is a SECURITY BOUNDARY): the resolver MUST resolve the EXACT `did#fragment`
 * from the AUTHORITATIVE DID document and return ONLY the key genuinely published at that
 * verificationMethod — never a key that merely shares the DID prefix, and never a caller-supplied
 * key taken on trust. A secure verifier supplies {@link ResolveDidKeys} for an independent RFC 7638
 * membership proof; without it the verifier FAILS CLOSED unless you attest THIS resolver is
 * authoritative via `trustResolveKeyAuthority` (in which case this contract is the sole binding).
 *
 * Fail-closed: throw when the `kid` is unresolvable (the verifier records `key_unresolvable`).
 */
export type ResolveKey = (kid: string) => ProofPublicJwk | Promise<ProofPublicJwk>;

/** List the Ed25519 verification keys published by a DID document — the DID-membership seam. */
export type ResolveDidKeys = (did: string) => ProofPublicJwk[] | Promise<ProofPublicJwk[]>;

/**
 * Replay seam — the ATOMIC test-AND-set (SPEC §12.2). It MUST atomically RECORD `nonce` for `did`
 * and return `true` iff the nonce was NOT already recorded (still unexpired); on a replay it MUST
 * return `false` and leave the prior record intact. The record-AND-check MUST be one atomic step:
 * the verifier treats a `true` return as proof the nonce is single-use, so a pure read that never
 * persists the nonce (e.g. `(n) => !seen.has(n)` where `seen` is never written) is a replay HOLE —
 * it compiles and provides ZERO protection. Scope the record by `did` to prevent cross-DID replay.
 * Reach for the batteries-included {@link InMemoryNonceCache} (race-free) or
 * {@link consumeFromNonceCacheProvider} rather than hand-rolling this.
 */
export type ConsumeNonceIfFresh = (nonce: string, did: string) => boolean | Promise<boolean>;

/**
 * The verification seams. `resolveKey` resolves the signing key by `kid`. `resolveDidKeys` is the
 * INDEPENDENT RFC 7638 DID-membership proof (the signing key MUST be a verificationMethod the proof's
 * `did` publishes) — it closes the forgeable-principal gap and is what a secure verifier binds on.
 * `tokenCnfJkt` is the OAuth token's RFC 9449 sender-constraint for the cnf fusion; omit for L3-minus.
 */
export interface VerifyProofDeps {
  resolveKey: ResolveKey;
  /**
   * The DID-membership seam: returns every Ed25519 verificationMethod the proof's `did` publishes,
   * so the verifier can PROVE (RFC 7638 thumbprint) the signing key really belongs to that principal.
   * SUPPLY THIS for any production verifier — it is the only independent binding of key → principal.
   */
  resolveDidKeys?: ResolveDidKeys;
  /**
   * INSECURE escape hatch — default `false` (secure). With no {@link ResolveDidKeys} seam there is no
   * independent membership proof, so the verifier FAILS CLOSED (`did_membership_unverifiable`) by
   * default rather than trust an unbound key. Set `true` ONLY when you attest that your
   * {@link ResolveKey} is itself AUTHORITATIVE — it resolves the exact `did#fragment` from the DID
   * document and returns ONLY that published key (dev/test, or a trusted internal resolver). In that
   * mode binding rests on the `kid`-prefix check plus your resolveKey contract. Prefer `resolveDidKeys`.
   */
  trustResolveKeyAuthority?: boolean;
  /** The verifier's own DID — the proof's `audience` MUST equal this (anti-relay). */
  expectedAudience: string;
  /** The access token's RFC 9449 `cnf.jkt` (enables L3 fusion); omit for L3-minus. */
  tokenCnfJkt?: string;
  /**
   * Replay defense — the ATOMIC test-AND-set that records the nonce and returns `false` on a replay
   * (SPEC §12.2). Wire {@link InMemoryNonceCache}'s `consume` (single-process, race-free) or
   * {@link consumeFromNonceCacheProvider} (over a shared store). When it is omitted the verifier
   * FAILS CLOSED (`nonce_seam_missing`) rather than skipping replay defense.
   */
  consumeNonceIfFresh?: ConsumeNonceIfFresh;
  /** Injectable clock returning epoch MILLISECONDS (deterministic tests). */
  now?: () => number;
  /** Accepted clock skew in seconds (default {@link DEFAULT_SKEW_SEC}). */
  skewSec?: number;
}

/** Assurance a valid proof carries: L3 on full cnf fusion, L3-minus without an AS `cnf`. */
export type ProofAssurance = 'L3' | 'L3-minus';

/** The result of {@link verifyCardProof} — `ok` iff there are no `reasons` (fail-closed). */
export interface ProofVerifyResult {
  ok: boolean;
  reasons: string[];
  /** Present only when `ok`: the derived assurance and the accountable principal DID. */
  level?: ProofAssurance;
  did?: string;
}
