/**
 * The merchant-side HTTP status-list resolver, fail-closed matrix — served by
 * an in-memory fetch stub, no sockets.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
  NodeCryptoProvider,
  buildDidWebDocument,
  base64urlEncodeFromBytes,
  type DIDDocument,
  type StatusList2021Credential,
  type CredentialStatus,
  type FetchProvider,
  type VCSigningFunction,
} from '@kya-os/mcp';
import { HttpStatusListResolver, ed25519PublicKeyBase64, parseIndex } from '../src/lib/http-statuslist-resolver.js';
import { buildInitialStatusList, resignWithBit } from '../src/rp/statuslist.js';
import { gzipCompressor, gzipDecompressor, type KeyedIdentity } from '../src/lib/wiring.js';

const crypto = new NodeCryptoProvider();
const RP_DID = 'did:web:rp.example';
const LIST_URL = 'https://rp.example/status-list';

class StubFetch implements FetchProvider {
  routes = new Map<string, () => unknown>();
  down = false;
  constructor(private didDoc: DIDDocument) {}
  async resolveDID(did: string) { return did === RP_DID ? this.didDoc : null; }
  async fetchStatusList() { return null; }
  async fetchDelegationChain() { return []; }
  async fetch(url: string): Promise<Response> {
    if (this.down) throw new Error('ECONNREFUSED');
    const r = this.routes.get(url);
    if (!r) return new Response('not found', { status: 404 });
    return new Response(JSON.stringify(r()), { status: 200, headers: { 'content-type': 'application/json' } });
  }
}

let identity: KeyedIdentity;
let signingFunction: VCSigningFunction;
let didDoc: DIDDocument;
let list: StatusList2021Credential;

const status = (index: number, purpose: 'revocation' | 'suspension' = 'revocation', url = LIST_URL): CredentialStatus =>
  ({ id: `${url}#${index}`, type: 'StatusList2021Entry', statusPurpose: purpose, statusListIndex: String(index), statusListCredential: url });

function resolver(fetchProvider: FetchProvider, expectedIssuerDid = RP_DID, extra: Partial<ConstructorParameters<typeof HttpStatusListResolver>[0]> = {}) {
  return new HttpStatusListResolver({
    fetchProvider,
    didResolver: { resolve: (d) => fetchProvider.resolveDID(d) },
    cryptoProvider: crypto,
    expectedIssuerDid,
    compressor: gzipCompressor,
    decompressor: gzipDecompressor,
    ...extra,
  });
}

beforeAll(async () => {
  const kp = await crypto.generateKeyPair();
  identity = { did: RP_DID, kid: `${RP_DID}#key-1`, privateKeyBase64: kp.privateKey, publicKeyBase64: kp.publicKey };
  signingFunction = async (canonical, _did, kid) => ({
    type: 'Ed25519Signature2020', created: new Date().toISOString(), verificationMethod: kid, proofPurpose: 'assertionMethod',
    proofValue: base64urlEncodeFromBytes(await crypto.sign(new TextEncoder().encode(canonical), kp.privateKey)),
  });
  didDoc = buildDidWebDocument({ did: RP_DID, kid: `${RP_DID}#key-1`, publicKey: kp.publicKey, createdAt: new Date().toISOString() });
  list = await buildInitialStatusList({ identity, signingFunction, url: LIST_URL, size: 1024 });
});

describe('HttpStatusListResolver', () => {
  it('reads a clear bit from a correctly signed list, then the set bit after a re-sign', async () => {
    const f = new StubFetch(didDoc);
    let current = list;
    f.routes.set(LIST_URL, () => current);
    const r = resolver(f);
    expect(await r.checkStatus(status(94))).toBe(false);
    expect(r.lastObservation?.verificationMethod).toBe(`${RP_DID}#key-1`);
    current = await resignWithBit({ credential: list, index: 94, revoked: true, identity, signingFunction });
    expect(await r.checkStatus(status(94))).toBe(true);
    expect(await r.checkStatus(status(95))).toBe(false);
  });

  it('a tampered list (bit flipped without re-signing) is refused', async () => {
    const f = new StubFetch(didDoc);
    const tampered = await resignWithBit({ credential: list, index: 94, revoked: true, identity, signingFunction });
    // keep the NEW encodedList but the OLD proof → signature must fail
    f.routes.set(LIST_URL, () => ({ ...tampered, proof: list.proof }));
    await expect(resolver(f).checkStatus(status(94))).rejects.toThrow(/signature verification FAILED/);
  });

  it('a list from the wrong issuer is refused even if well-formed', async () => {
    const f = new StubFetch(didDoc);
    f.routes.set(LIST_URL, () => list);
    await expect(resolver(f, 'did:web:someone.else').checkStatus(status(94))).rejects.toThrow(/not the expected issuer/);
  });

  it('purpose mismatch, unsigned list, missing list and network failure all fail closed', async () => {
    const f = new StubFetch(didDoc);
    f.routes.set(LIST_URL, () => list);
    await expect(resolver(f).checkStatus(status(94, 'suspension'))).rejects.toThrow(/purpose/);
    const unsigned = { ...list } as Record<string, unknown>; delete unsigned['proof'];
    f.routes.set(LIST_URL, () => unsigned);
    await expect(resolver(f).checkStatus(status(94))).rejects.toThrow(/unsigned/);
    f.routes.delete(LIST_URL);
    await expect(resolver(f).checkStatus(status(94))).rejects.toThrow(/HTTP 404/);
    f.down = true;
    await expect(resolver(f).checkStatus(status(94))).rejects.toThrow(/ECONNREFUSED/);
  });

  it('http:// is refused except for loopback when explicitly allowed', async () => {
    const f = new StubFetch(didDoc);
    f.routes.set('http://rp.example/status-list', () => list);
    f.routes.set('http://localhost:4950/status-list', () => list);
    await expect(resolver(f).checkStatus(status(94, 'revocation', 'http://rp.example/status-list'))).rejects.toThrow(/https/);
    await expect(resolver(f).checkStatus(status(94, 'revocation', 'http://localhost:4950/status-list'))).rejects.toThrow(/https/);
    const loop = resolver(f, RP_DID, { allowInsecureLocalhost: true });
    await expect(loop.checkStatus(status(94, 'revocation', 'http://rp.example/status-list'))).rejects.toThrow(/https/);
    expect(await loop.checkStatus(status(94, 'revocation', 'http://localhost:4950/status-list'))).toBe(false);
  });

  it('out-of-range and non-canonical indices are refused', async () => {
    const f = new StubFetch(didDoc);
    f.routes.set(LIST_URL, () => list);
    await expect(resolver(f).checkStatus(status(999999))).rejects.toThrow(/out of range/);
    expect(() => parseIndex('094')).toThrow();
    expect(() => parseIndex('-1')).toThrow();
    expect(parseIndex('0')).toBe(0);
  });

  it('extracts the Ed25519 key from JWK or multibase verification methods', () => {
    const vm = didDoc.verificationMethod![0]!;
    const fromJwk = ed25519PublicKeyBase64(vm);
    const fromMultibase = ed25519PublicKeyBase64({ ...vm, publicKeyJwk: undefined });
    expect(fromJwk).toBe(identity.publicKeyBase64);
    expect(fromMultibase).toBe(identity.publicKeyBase64);
  });
});
