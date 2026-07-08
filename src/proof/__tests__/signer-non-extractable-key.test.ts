/**
 * Non-extractable signing keys for ProofGenerator.
 *
 * `ProofAgentIdentity.privateKey` accepts a `CryptoKey` handle — including a
 * NON-EXTRACTABLE WebCrypto key (passkey-PRF-derived, HSM/KMS-fronted) — as an
 * alternative to a base64 private-key string, so secret key material never has
 * to leave the caller's trust boundary to produce a proof. This realizes the
 * signer model the spec already names:
 *   §4.5  "Implementations that generate or hold agent secret keys … are
 *          non-conformant."
 *   §     "Signing MAY be delegated to a KMS/HSM-backed signer hook. Local
 *          Ed25519 helpers MUST keep key material inside the caller's trust
 *          boundary and send only signatures."
 *
 * Proven here with real crypto:
 *   1. a non-extractable Ed25519 key genuinely can't be exported to the base64
 *      string the string path requires (so it was previously unusable);
 *   2. `ProofGenerator` signs with that non-extractable key and the UNMODIFIED
 *      `ProofVerifier` accepts the proof; and
 *   3. the string and CryptoKey forms of the SAME key are interchangeable —
 *      both produce proofs the verifier accepts — so the change is
 *      backward-compatible; and
 *   4. the kid↔key binding still constrains the new path: a CryptoKey that
 *      doesn't correspond to the declared kid yields a proof the verifier
 *      rejects (a stolen/mismatched handle can't mint an accepted proof).
 *
 * jose owns the JWS signing-input construction, so canonicalization stays
 * inside the library; the caller only ever supplies a key handle.
 */
import { describe, it, expect } from "vitest";
import { exportJWK } from "jose";
import { ProofGenerator } from "../generator.js";
import { ProofVerifier } from "../verifier.js";
import type { SessionContext } from "../../types/protocol.js";
import type {
  ProofAgentIdentity,
  ToolRequest,
} from "../generator.js";
import { NodeCryptoProvider } from "../../__tests__/utils/node-crypto-provider.js";
import { SystemClockProvider } from "../../providers/system-clock.js";
import { MemoryNonceCacheProvider } from "../../providers/memory.js";

const DID = "did:key:z6MkSignerHookExample";
const KID = `${DID}#${DID.slice("did:key:".length)}`;
const REQUEST: ToolRequest = { method: "vault/read", params: { fileId: "f1" } };

/** Ed25519 PKCS#8 DER prefixes the 32-byte seed with a 16-byte header. */
const PKCS8_HEADER_LEN = 16;

function makeSession(nonce: string): SessionContext {
  return {
    sessionId: "sess_signer_hook",
    audience: "verifier.example.com",
    nonce,
    timestamp: Math.floor(Date.now() / 1000),
    createdAt: Date.now(),
    lastActivity: Date.now(),
    ttlMinutes: 10,
    identityState: "anonymous",
  };
}

/** A fresh proof verifier wired with in-memory providers. */
function buildVerifier(cryptoProvider: NodeCryptoProvider): ProofVerifier {
  return new ProofVerifier({
    cryptoProvider,
    clockProvider: new SystemClockProvider(),
    nonceCacheProvider: new MemoryNonceCacheProvider(),
    fetchProvider: { fetch: async () => new Response(null) } as never,
  });
}

/** Generate a proof for `identity`, then verify it against `publicJwk`. */
async function generateAndVerify(
  identity: ProofAgentIdentity,
  publicJwk: Record<string, unknown>,
  nonce: string
): Promise<boolean> {
  const cryptoProvider = new NodeCryptoProvider();
  const proof = await new ProofGenerator(identity, cryptoProvider).generateProof(
    REQUEST,
    undefined,
    makeSession(nonce),
    { scopeId: "vault:read" }
  );
  const result = await buildVerifier(cryptoProvider).verifyProof(
    proof,
    publicJwk as never,
    { request: REQUEST }
  );
  return result.valid;
}

describe("ProofGenerator — non-extractable / CryptoKey signing keys", () => {
  it("a non-extractable Ed25519 private key cannot be exported to a string", async () => {
    const { privateKey } = (await crypto.subtle.generateKey(
      { name: "Ed25519" },
      /* extractable */ false,
      ["sign", "verify"]
    )) as CryptoKeyPair;

    expect(privateKey.extractable).toBe(false);
    // The string path does importPKCS8(identity.privateKey). There is no such
    // string to give it — export is refused — so this key was previously unusable.
    await expect(crypto.subtle.exportKey("pkcs8", privateKey)).rejects.toThrow();
  });

  it("signs with a non-extractable CryptoKey; the unmodified verifier accepts the proof", async () => {
    const { privateKey, publicKey } = (await crypto.subtle.generateKey(
      { name: "Ed25519" },
      false,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    expect(privateKey.extractable).toBe(false);

    // The public half is always exportable — it's what a verifier resolves from
    // the DID document. Tag it with the kid the verifier matches on.
    const publicJwk = { ...(await exportJWK(publicKey)), kid: KID };

    const identity: ProofAgentIdentity = {
      did: DID,
      kid: KID,
      privateKey, // a non-extractable CryptoKey, not a base64 string
      publicKey: "", // unused on the generation path
    };

    expect(await generateAndVerify(identity, publicJwk, "nonce-crypto-key")).toBe(
      true
    );
  });

  it("the string and CryptoKey forms of the SAME key are interchangeable (backward-compatible)", async () => {
    // One key, two forms. Generate it extractable so we can express it both as
    // the base64 seed (the historical string path) and as a CryptoKey handle.
    const { privateKey, publicKey } = (await crypto.subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const pkcs8 = new Uint8Array(
      await crypto.subtle.exportKey("pkcs8", privateKey)
    );
    // The base64 seed is exactly what NodeCryptoProvider.generateKeyPair emits.
    const seedB64 = Buffer.from(pkcs8.subarray(PKCS8_HEADER_LEN)).toString(
      "base64"
    );
    const publicJwk = { ...(await exportJWK(publicKey)), kid: KID };

    const base = { did: DID, kid: KID, publicKey: "" };
    const viaString: ProofAgentIdentity = { ...base, privateKey: seedB64 };
    const viaCryptoKey: ProofAgentIdentity = { ...base, privateKey };

    // Both forms of the same key produce proofs the same verifier accepts.
    expect(await generateAndVerify(viaString, publicJwk, "nonce-string")).toBe(
      true
    );
    expect(
      await generateAndVerify(viaCryptoKey, publicJwk, "nonce-handle")
    ).toBe(true);
  });

  it("rejects a proof whose CryptoKey doesn't match the declared kid (binding holds)", async () => {
    // The device signs with its own non-extractable key...
    const { privateKey } = (await crypto.subtle.generateKey(
      { name: "Ed25519" },
      false,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    // ...but the verifier resolves a DIFFERENT public key for that kid (i.e. the
    // handle doesn't correspond to the identity it claims).
    const { publicKey: otherPublic } = (await crypto.subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const mismatchedJwk = { ...(await exportJWK(otherPublic)), kid: KID };

    const identity: ProofAgentIdentity = {
      did: DID,
      kid: KID,
      privateKey,
      publicKey: "",
    };
    // The new CryptoKey path doesn't self-verify at generation (same trust model
    // as the string path); the mismatch is caught — fail-closed — at the verifier.
    expect(
      await generateAndVerify(identity, mismatchedJwk, "nonce-mismatch")
    ).toBe(false);
  });
});
