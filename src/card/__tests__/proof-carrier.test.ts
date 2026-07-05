import { describe, it, expect } from 'vitest';
import {
  buildCardProof,
  computeRequestHash,
  httpSignatureBase,
  toHttpMessageSignature,
  verifyHttpSignature,
  type CardProofMeta,
  type HttpMessageSignature,
  type ProofSigner,
} from '../index.js';
import type { Ed25519PublicJwk } from '../schema.js';
import { AUD, KID, NONCE, PROOF_KEY, REQ, clock, keypair } from './proof-helpers.js';

/** Mint a proof with the shared clock; returns the flat CardProofMeta. */
async function mint(signer: ProofSigner): Promise<CardProofMeta> {
  return (await buildCardProof(REQ, signer, { audience: AUD, nonce: NONCE, now: clock }))[PROOF_KEY];
}

/** Verify a raw Ed25519 signature the way a STOCK RFC 9421 verifier would — no KYA-OS code. */
async function stockVerify(base: string, signatureBytes: Uint8Array, pub: Ed25519PublicJwk): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: pub.kty, crv: pub.crv, x: pub.x },
    { name: 'Ed25519' },
    false,
    ['verify'],
  );
  return crypto.subtle.verify({ name: 'Ed25519' }, key, signatureBytes, new TextEncoder().encode(base));
}

/** The base64-encoded raw signature bytes a stock verifier pulls out of the emitted `Signature`. */
function carriedSignatureBytes(headers: HttpMessageSignature): Uint8Array {
  return new Uint8Array(Buffer.from(headers.Signature.match(/^kyaos=:(.+):$/)![1]!, 'base64'));
}

/** `content-digest` → `Content-Digest`, `kya-audience` → `Kya-Audience` (RFC 9421 field ↔ header). */
function componentToHeaderName(component: string): string {
  return component.split('-').map((seg) => seg[0]!.toUpperCase() + seg.slice(1)).join('-');
}

/**
 * Reconstruct the RFC 9421 signature base with ZERO access to the proof object — the way a party
 * holding ONLY the emitted message would. Parses the covered-component list out of `Signature-Input`,
 * resolves each NON-`@` component from its emitted header field alone, and THROWS if any named
 * component has no corresponding header (a stock verifier MUST abort). This is the property the
 * sibling exists to provide: message-only base reconstruction.
 */
function reconstructBaseFromWire(headers: HttpMessageSignature): string {
  const input = headers['Signature-Input'];
  const parsed = input.match(/^kyaos=(\((?:"[^"]+"\s*)+\));(.+)$/);
  if (!parsed) throw new Error(`unparseable Signature-Input: ${input}`);
  const [, componentList, params] = parsed;
  const fields = headers as unknown as Record<string, string | undefined>;
  const lines = componentList!.match(/"[^"]+"/g)!.map((quoted) => {
    const component = quoted.slice(1, -1);
    const headerName = componentToHeaderName(component);
    const value = fields[headerName];
    if (value === undefined) throw new Error(`covered component "${component}" has no emitted header ${headerName}`);
    return `"${component}": ${value}`;
  });
  lines.push(`"@signature-params": ${componentList};${params}`);
  return lines.join('\n');
}

describe('computeRequestHash', () => {
  it('emits an RFC 9421 Content-Digest structured field over JCS(method+params)', async () => {
    const hash = await computeRequestHash(REQ);
    expect(hash).toMatch(/^sha-256=:[A-Za-z0-9+/]+=*:$/);
  });

  it('is canonical: key order in params does not change the hash', async () => {
    const a = await computeRequestHash({ method: 'm', params: { x: 1, y: 2 } });
    const b = await computeRequestHash({ method: 'm', params: { y: 2, x: 1 } });
    expect(a).toBe(b);
  });

  it('differs when the method or params differ', async () => {
    const base = await computeRequestHash(REQ);
    expect(await computeRequestHash({ method: 'other', params: REQ.params })).not.toBe(base);
  });
});

describe('toHttpMessageSignature — the RFC 9421 sibling carrier (dual signature)', () => {
  it('projects the proof into Content-Digest / Signature-Input / Signature', async () => {
    const { signer } = await keypair();
    const proof = await mint(signer);
    const headers = toHttpMessageSignature(proof);

    // Content-Digest carries the proof's requestHash verbatim (already a 9421 structured field).
    expect(headers['Content-Digest']).toBe(proof.requestHash);

    // Every NON-@ covered component is emitted as its own header, byte-identical to the base line,
    // so a stock verifier resolves "kya-audience"/"kya-nonce"/"kya-cnf" from the message (finding 9).
    expect(headers['Kya-Audience']).toBe(proof.audience);
    expect(headers['Kya-Nonce']).toBe(proof.nonce);
    expect(headers['Kya-Cnf']).toBe(proof.cnf!.jkt);

    // Signature-Input names the covered components (kya-cnf included: the signer set a cnf.jkt)
    // and round-trips created/expires/keyid.
    expect(headers['Signature-Input']).toContain('("content-digest" "kya-audience" "kya-nonce" "kya-cnf")');
    expect(headers['Signature-Input']).toContain(`created=${proof.created}`);
    expect(headers['Signature-Input']).toContain(`expires=${proof.expires}`);
    expect(headers['Signature-Input']).toContain(`keyid="${KID}"`);

    // Signature IS the RAW httpSig (64-byte Ed25519 sig) — NOT the JWS signature, which also
    // covers the JWS protected header and so could never satisfy a stock 9421 verifier.
    const match = headers.Signature.match(/^kyaos=:(.+):$/);
    expect(match).not.toBeNull();
    const carried = Buffer.from(match![1]!, 'base64');
    expect(carried.length).toBe(64);
    expect(Buffer.compare(carried, Buffer.from(proof.httpSig!, 'base64url'))).toBe(0);
    const jwsSig = Buffer.from(proof.jws.split('.')[2]!, 'base64url');
    expect(Buffer.compare(carried, jwsSig)).not.toBe(0);
  });

  it('RECONSTRUCTS the 9421 base and verifies the carried signature against the DID key', async () => {
    const { signer, publicJwk } = await keypair();
    const proof = await mint(signer);
    const headers = toHttpMessageSignature(proof);

    // A stock verifier: rebuild the signature base + read the carried Signature, verify vs DID key.
    const base = httpSignatureBase(proof);
    const carried = Buffer.from(headers.Signature.match(/^kyaos=:(.+):$/)![1]!, 'base64');
    expect(await stockVerify(base, new Uint8Array(carried), publicJwk)).toBe(true);

    // …and the module's own helper agrees (reconstructs the base internally).
    expect(await verifyHttpSignature(proof, publicJwk)).toBe(true);
  });

  // ── Findings 9 + 10: the sibling MUST be reconstructable from the wire alone ────────
  it('reconstructs the 9421 base from the EMITTED WIRE ONLY and verifies against the DID key', async () => {
    const { signer, publicJwk } = await keypair();
    const proof = await mint(signer);
    const headers = toHttpMessageSignature(proof);

    // Rebuild the base with NO access to the proof object — resolve every covered component from
    // the emitted headers exactly as a stock 9421 verifier does. Pre-fix this THREW (the kya-*
    // covered headers were never emitted), so the "stock verifier" interop was impossible.
    const base = reconstructBaseFromWire(headers);
    expect(base).toBe(httpSignatureBase(proof));
    expect(await stockVerify(base, carriedSignatureBytes(headers), publicJwk)).toBe(true);
  });

  it('wire reconstruction ABORTS when a covered-component header is stripped (fail-closed gate)', async () => {
    const { signer } = await keypair();
    const proof = await mint(signer);
    const headers = toHttpMessageSignature(proof);

    // Simulate the pre-fix projection that omitted a kya-* covered header: a stock verifier that
    // reads the covered list from Signature-Input MUST abort before the Ed25519 check.
    const stripped: HttpMessageSignature = { ...headers };
    delete (stripped as { 'Kya-Audience'?: string })['Kya-Audience'];
    expect(() => reconstructBaseFromWire(stripped)).toThrow(/kya-audience/);
  });

  it('reconstructs from the wire without a cnf (L3-minus): Kya-Cnf absent, still verifies', async () => {
    const { signer, publicJwk } = await keypair();
    const noCnf: ProofSigner = { did: signer.did, kid: signer.kid, sign: signer.sign, signRaw: signer.signRaw };
    const proof = await mint(noCnf);
    const headers = toHttpMessageSignature(proof);

    expect(headers['Kya-Cnf']).toBeUndefined();
    expect(headers['Signature-Input']).not.toContain('kya-cnf');
    const base = reconstructBaseFromWire(headers);
    expect(base).toBe(httpSignatureBase(proof));
    expect(await stockVerify(base, carriedSignatureBytes(headers), publicJwk)).toBe(true);
  });

  it('fails cross-verification when a covered field is tampered (base no longer matches)', async () => {
    const { signer, publicJwk } = await keypair();
    const proof = await mint(signer);
    expect(await verifyHttpSignature({ ...proof, audience: 'did:web:relay.evil' }, publicJwk)).toBe(false);
    expect(await verifyHttpSignature({ ...proof, nonce: 'n-replayed' }, publicJwk)).toBe(false);
  });

  it('binds cross-verification to the DID key: a stranger key does not verify', async () => {
    const { signer } = await keypair();
    const { publicJwk: stranger } = await keypair();
    expect(await verifyHttpSignature(await mint(signer), stranger)).toBe(false);
  });

  it('carries kya-cnf only when a cnf is present (L3-minus proof omits it, still verifiable)', async () => {
    const { signer, publicJwk } = await keypair();
    const noCnf: ProofSigner = { did: signer.did, kid: signer.kid, sign: signer.sign, signRaw: signer.signRaw };
    const proof = await mint(noCnf);
    expect(proof.cnf).toBeUndefined();
    expect(httpSignatureBase(proof)).not.toContain('kya-cnf');
    expect(toHttpMessageSignature(proof)['Signature-Input']).toContain('("content-digest" "kya-audience" "kya-nonce")');
    expect(await verifyHttpSignature(proof, publicJwk)).toBe(true);
  });

  it('degrades to no sibling when the signer lacks a signRaw seam (throws on projection)', async () => {
    const { signer, publicJwk } = await keypair();
    const jwsOnly: ProofSigner = { did: signer.did, kid: signer.kid, jkt: signer.jkt, sign: signer.sign };
    const proof = await mint(jwsOnly);
    expect(proof.httpSig).toBeUndefined();
    expect(() => toHttpMessageSignature(proof)).toThrow(/no httpSig/);
    expect(await verifyHttpSignature(proof, publicJwk)).toBe(false);
  });

  it('builds a stable 9421 signature base carrying the covered components', async () => {
    const { signer } = await keypair();
    const proof = await mint(signer);
    const base = httpSignatureBase(proof);
    expect(base).toContain(`"content-digest": ${proof.requestHash}`);
    expect(base).toContain(`"kya-audience": ${AUD}`);
    expect(base).toContain(`"kya-nonce": ${NONCE}`);
    expect(base).toContain(`"kya-cnf": ${proof.cnf!.jkt}`);
    expect(base).toContain(`keyid="${KID}"`);
    expect(httpSignatureBase(proof)).toBe(base); // deterministic
  });
});
