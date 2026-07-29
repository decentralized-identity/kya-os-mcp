/**
 * Regression tests for the PR #110 security review. Each test exercises the REAL code path
 * (the real address classifier, the real default transport, real time progression, the real bit
 * readers, distinct real `_meta` keys) and would FAIL before its fix. They exist because the
 * original suite passed while these defects shipped — it injected mocked seams AROUND them.
 */
import { describe, it, expect } from 'vitest';
import { gzipSync, gunzipSync } from 'node:zlib';
import {
  isBlockedAddress,
  createSafeFetch,
  InMemoryNonceCache,
  NONCE_RETENTION_SEC,
  createRevocationChecker,
  evaluateRevocationChain,
  validateDelegationChain,
  DelegationCredentialSchema,
  readCardProof,
  KYA_OS_CARD_PROOF_META_KEY,
  withKyaOsCard,
  parseCard,
  type DelegationCredential,
} from '../index.js';
import { BitstringManager, isIndexSet } from '../../delegation/bitstring.js';
import { KYA_OS_PROOF_META_KEY } from '../../proof/generator.js';
import { CardProofMetaSchema } from '../proof/types.js';

const gzList = (bytes: Uint8Array): string => `u${Buffer.from(gzipSync(Buffer.from(bytes))).toString('base64url')}`;
const GZ = { compress: async (d: Uint8Array) => new Uint8Array(gzipSync(Buffer.from(d))) };
const GUNZ = { decompress: async (d: Uint8Array) => new Uint8Array(gunzipSync(Buffer.from(d))) };

describe('PR #110 review — real-path regressions', () => {
  it('#3 blocks IPv6 loopback/unspecified/ULA in ANY textual form (not just compressed ::1)', () => {
    for (const a of [
      '::1', '0:0:0:0:0:0:0:1', '0000:0000:0000:0000:0000:0000:0000:0001', '::', '0:0:0:0:0:0:0:0',
      'fe80::1', 'fc00::1', 'fd00::1', 'ff02::1', '::ffff:127.0.0.1', '::ffff:169.254.169.254', '::ffff:10.0.0.1',
    ]) {
      expect(isBlockedAddress(a)).toBe(true);
    }
    for (const a of ['8.8.8.8', '2606:4700:4700::1111', '::ffff:8.8.8.8']) {
      expect(isBlockedAddress(a)).toBe(false);
    }
  });

  it('#1 the DEFAULT transport parses the pinned address (no "Invalid IP address: undefined")', async () => {
    // 203.0.113.1 (TEST-NET-3) is public but unroutable, so the connection fails — the point is
    // the address PARSES. The pre-fix scalar lookup callback threw "Invalid IP address: undefined"
    // under Node ≥20's autoSelectFamily BEFORE any connection was attempted.
    const fetch = createSafeFetch({ lookup: async () => [{ address: '203.0.113.1', family: 4 }], timeoutMs: 400 });
    let error: unknown;
    try {
      await fetch('https://example.test/');
    } catch (e) {
      error = e;
    }
    expect(error).toBeDefined();
    expect(String((error as Error).message)).not.toMatch(/invalid ip address/i);
  });

  it('#2 the default nonce cache rejects a replay across the WHOLE verifier window', () => {
    expect(NONCE_RETENTION_SEC).toBeGreaterThanOrEqual(70); // ttl(60) + 2·skew(5)
    const base = 1_700_000_000_000;
    let t = base;
    const cache = new InMemoryNonceCache({ now: () => t }); // DEFAULT ttl — the shipped behaviour
    expect(cache.consume('n', 'did:web:example.com:a')).toBe(true);
    for (const dt of [1, 30, 62, 69]) {
      t = base + dt * 1000; // past the old 60s eviction, still inside the ~70s acceptance window
      expect(cache.consume('n', 'did:web:example.com:a')).toBe(false);
    }
  });

  it('#4 the card revocation reader and the legacy BitstringManager agree (W3C MSB) on one list', async () => {
    const gz = { compress: async (d: Uint8Array) => new Uint8Array(gzipSync(Buffer.from(d))) };
    const gunz = { decompress: async (d: Uint8Array) => new Uint8Array(gunzipSync(Buffer.from(d))) };
    const mgr = BitstringManager.fromSetBits(1024, [42], gz, gunz); // index 42 revoked
    const encodedList = await mgr.encode(); // encode() now emits the W3C `u` multibase prefix itself
    const list = { credentialSubject: { statusPurpose: 'revocation', encodedList } };
    const checker = createRevocationChecker({ fetch: async () => ({ ok: true, status: 200, json: async () => list }) });
    // Card reader:
    expect((await checker({ statusListCredential: 'x', statusListIndex: '42' })).revoked).toBe(true);
    expect((await checker({ statusListCredential: 'x', statusListIndex: '7' })).revoked).toBe(false);
    // Legacy reader agrees on the SAME encoded bytes:
    expect(mgr.getBit(42)).toBe(true);
    expect(mgr.getBit(7)).toBe(false);
  });

  it('#5 revocation fails CLOSED when the status list omits statusPurpose (bit is clear)', async () => {
    const list = { credentialSubject: { encodedList: gzList(new Uint8Array(16)) } }; // all-clear, NO statusPurpose
    const checker = createRevocationChecker({ fetch: async () => ({ ok: true, status: 200, json: async () => list }) });
    expect((await checker({ statusListCredential: 'x', statusListIndex: '5' })).revoked).toBe(true);
  });

  it('#6 an attenuating-but-EXPIRED delegation chain is rejected on the wall clock', () => {
    const root: DelegationCredential = DelegationCredentialSchema.parse({
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://w3id.org/security/zcap/v1',
        'https://kya-os.org/ns/delegation/v1',
      ],
      type: ['VerifiableCredential', 'DelegationCredential'],
      issuer: 'did:web:example.com:org',
      validUntil: '2020-01-01T00:00:00Z',
      credentialSubject: {
        id: 'urn:cap:root', invoker: 'did:web:example.com:agent',
        parentCapability: 'https://api.example.com/r', invocationTarget: 'https://api.example.com/r',
        allowedAction: ['read'],
      },
    });
    expect(validateDelegationChain([root], { now: () => Date.parse('2026-01-01T00:00:00Z') }).ok).toBe(false);
    expect(validateDelegationChain([root], { now: () => Date.parse('2019-06-01T00:00:00Z') }).ok).toBe(true);
  });

  it('#7 a delegation/status chain with NO status entries is ok but NOT fresh (no live check)', async () => {
    expect(await evaluateRevocationChain([], async () => ({ revoked: false, fresh: true }))).toEqual({
      ok: true, fresh: false, reasons: [],
    });
  });

  it('#8 the card proof and the legacy proof occupy DISTINCT _meta keys (they coexist)', () => {
    expect(KYA_OS_CARD_PROOF_META_KEY).not.toBe(KYA_OS_PROOF_META_KEY);
    const cardProof = { prf: 'org.kya-os/proof.v1', jws: 'x' };
    const legacyProof = { sessionId: 's-1', ts: 1 };
    // Both present on one server's request _meta:
    const meta = { [KYA_OS_CARD_PROOF_META_KEY]: cardProof, [KYA_OS_PROOF_META_KEY]: legacyProof };
    expect(readCardProof(meta)).toEqual(cardProof); // the card guard reads its OWN key
    // A lone legacy proof is simply not seen by the card guard (no false 401 on structure):
    expect(readCardProof({ [KYA_OS_PROOF_META_KEY]: legacyProof })).toBeUndefined();
  });

  it('#10 withKyaOsCard does not throw for a did:key card (inline serverMeta still works)', () => {
    const card = parseCard({
      id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      entityType: 'agent',
      name: 'Dev Agent',
    });
    const mount = withKyaOsCard(card); // pre-fix: threw via didWebToCardUrl before returning
    expect(mount.didServiceEntry).toBeUndefined();
    expect(mount.serverMeta).toBeDefined();
    expect(() => mount.mountDidDocument({})).toThrow(/did:web/);
  });

  // ── Round 2 (adversarial re-verification of the review fixes) ──────────────────

  it('#2b nonce retention covers the full window + rounding headroom (no sub-second tail replay)', () => {
    expect(NONCE_RETENTION_SEC).toBe(71); // ttl(60) + 2*skew(10) + 1s rounding headroom
    const base = 1_700_000_000_000;
    let t = base;
    const cache = new InMemoryNonceCache({ now: () => t });
    expect(cache.consume('n', 'did:web:example.com:a')).toBe(true);
    t = base + 70_000; // exactly ttl+2*skew — pre-fix this was evicted, so a replay was accepted
    expect(cache.consume('n', 'did:web:example.com:a')).toBe(false);
    t = base + 71_500; // past retention (the proof itself is long expired here anyway)
    expect(cache.consume('n', 'did:web:example.com:a')).toBe(true);
  });

  it('#2c a non-decimal statusListIndex fails closed (never silently reads bit 0)', async () => {
    const mgr = BitstringManager.fromSetBits(1024, [42], GZ, GUNZ); // revoked ONLY at 42; bit 0 clear
    const list = { credentialSubject: { statusPurpose: 'revocation', encodedList: await mgr.encode() } };
    const checker = createRevocationChecker({ fetch: async () => ({ ok: true, status: 200, json: async () => list }) });
    for (const bad of [' ', '\t', '0x2A', '+42', '1e1', '']) {
      expect((await checker({ statusListCredential: 'x', statusListIndex: bad })).revoked).toBe(true); // fail-closed
    }
    expect((await checker({ statusListCredential: 'x', statusListIndex: '42' })).revoked).toBe(true); // valid, revoked
    expect((await checker({ statusListCredential: 'x', statusListIndex: '7' })).revoked).toBe(false); // valid, clear
  });

  it('#4b legacy getBit AND standalone isIndexSet throw (fail-closed) on NaN / out-of-range', async () => {
    const mgr = BitstringManager.fromSetBits(64, [3], GZ, GUNZ);
    expect(mgr.getBit(3)).toBe(true);
    expect(() => mgr.getBit(Number.NaN)).toThrow();
    expect(() => mgr.getBit(999)).toThrow();
    // isIndexSet is a SEPARATE reader; its `byteIndex >= length` guard is false for NaN, so it must
    // reject NaN explicitly (a whitespace/non-decimal index parsed to NaN would otherwise read live).
    const enc = await mgr.encode();
    expect(await isIndexSet(enc, 3, GUNZ)).toBe(true);
    await expect(isIndexSet(enc, Number.NaN, GUNZ)).rejects.toThrow();
    await expect(isIndexSet(enc, 9999, GUNZ)).rejects.toThrow();
  });

  it('#6b IPv6 transition addresses (NAT64 / 6to4-private / Teredo / site-local) are blocked', () => {
    for (const a of [
      '64:ff9b::10.0.0.1', // NAT64 well-known /96 → RFC1918
      '64:ff9b::a9fe:a9fe', // NAT64 well-known /96 → 169.254.169.254 metadata
      '64:ff9b:1::10.0.0.1', // NAT64 LOCAL-USE /48 (RFC 8215) → RFC1918
      '64:ff9b:1::a9fe:a9fe', // NAT64 local-use /48 → metadata
      '2002:0a00:0001::', // 6to4 embedding 10.0.0.1
      'fec0::1', // deprecated site-local
      '2001:0:0:0:0:0:0:1', // Teredo 2001:0000::/32
    ]) {
      expect(isBlockedAddress(a)).toBe(true);
    }
    expect(isBlockedAddress('2606:4700:4700::1111')).toBe(false); // genuine public v6 not over-blocked
    expect(isBlockedAddress('2002:0808:0808::')).toBe(false); // 6to4 to a public v4 (8.8.8.8) is fine
    expect(isBlockedAddress('64:ff9b:1::8.8.8.8')).toBe(false); // NAT64 local-use to a PUBLIC v4 is fine
  });

  // ── Round 3 (A+ review — schema hardening + fail-closed convention locks) ──────

  const validCardProof = (): Record<string, unknown> => ({
    prf: 'org.kya-os/proof.v1',
    alg: 'EdDSA',
    did: 'did:web:example.com:agents:acme-pay',
    kid: 'did:web:example.com:agents:acme-pay#key-1',
    audience: 'did:web:verifier.example.com',
    nonce: 'n-0123456789abcdef0123456789abcdef',
    created: 1_700_000_000,
    expires: 1_700_000_060,
    requestHash: 'req-hash-abc123',
    jws: 'eyJhbGciOiJFZERTQSJ9..detached-sig',
  });

  it('#A1 the covered-claims schema rejects a nonce that would corrupt the RFC 9421 base', () => {
    const good = validCardProof();
    expect(CardProofMetaSchema.safeParse(good).success).toBe(true);
    // base64url output of the shipped CSPRNG generator (with-kya-os.ts) still parses:
    expect(CardProofMetaSchema.safeParse({ ...good, nonce: 'AbC_1-x9Zq' }).success).toBe(true);
    // anything that would break the line-oriented signature base is rejected AT PARSE, not just at verify:
    for (const bad of ['n-1\nn-2', 'n 2', 'n+2', 'n/2', 'n=2', 'nönce', '']) {
      expect(CardProofMetaSchema.safeParse({ ...good, nonce: bad }).success).toBe(false);
    }
  });

  it('#A2 the schema rejects a non-base64url cnf.jkt (RFC 7638 thumbprints are base64url)', () => {
    const good = validCardProof();
    const okJkt = '0Z9PGGnrUbAvSHRWxKkBxjgrUrvu6ETEhOl2StPyW7c'; // a real thumbprint from the vectors
    expect(CardProofMetaSchema.safeParse({ ...good, cnf: { jkt: okJkt } }).success).toBe(true);
    for (const bad of ['has+plus', 'has/slash', 'has=pad', 'has space', 'a\nb', '']) {
      expect(CardProofMetaSchema.safeParse({ ...good, cnf: { jkt: bad } }).success).toBe(false);
    }
  });

  it('#A3 the schema requires kid to carry a #fragment — for did:web AND base58 did:key', () => {
    const good = validCardProof();
    for (const kid of [
      'did:web:example.com:agents:acme-pay#key-1',
      // did:key is base58btc → UPPERCASE letters MUST be accepted (a [a-z] regex would wrongly reject this):
      'did:key:z6MkiAEgJA1vxX2PJRhG7qwbEHBZkD6mvzEhmQ4VNMT3R2AS#z6MkiAEgJA1vxX2PJRhG7qwbEHBZkD6mvzEhmQ4VNMT3R2AS',
    ]) {
      expect(CardProofMetaSchema.safeParse({ ...good, kid, did: kid.split('#')[0] }).success).toBe(true);
    }
    // a fragment-less kid was only caught late as `key_unresolvable`; now it fails at the schema:
    for (const bad of ['did:web:example.com', 'did:key:z6Mki', 'not-a-did#k', 'did:web:example.com#']) {
      expect(CardProofMetaSchema.safeParse({ ...good, kid: bad }).success).toBe(false);
    }
  });

  it('#A5 validateDelegationChain accepts a credential with proof OMITTED (signature-verify is a separate seam)', () => {
    // The module validates STRUCTURE + attenuation; signature verification is delegated to an injected
    // seam (DelegationCredentialSchema marks `proof` optional). Lock that contract so a future reader
    // does not assume proofs are validated here.
    const root: DelegationCredential = DelegationCredentialSchema.parse({
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://w3id.org/security/zcap/v1',
        'https://kya-os.org/ns/delegation/v1',
      ],
      type: ['VerifiableCredential', 'DelegationCredential'],
      issuer: 'did:web:example.com:org',
      validUntil: '2999-01-01T00:00:00Z',
      credentialSubject: {
        id: 'urn:cap:root', invoker: 'did:web:example.com:agent',
        parentCapability: 'https://api.example.com/r', invocationTarget: 'https://api.example.com/r',
        allowedAction: ['read'],
      },
    });
    expect('proof' in root).toBe(false);
    expect(validateDelegationChain([root], { now: () => Date.parse('2026-01-01T00:00:00Z') }).ok).toBe(true);
  });
});
