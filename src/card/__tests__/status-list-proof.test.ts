import { describe, it, expect, vi } from 'vitest';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { readFileSync } from 'node:fs';
import { canonicalize } from 'json-canonicalize';
import { createRevocationChecker, evaluateRevocationChain } from '../revocation.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import { base58Encode } from '../../utils/base58.js';
import type { DIDDocument, DIDResolver } from '../../delegation/vc-verifier.types.js';
import type { SafeFetch } from '../../utils/safe-fetch.js';

// ── Fixtures ────────────────────────────────────────────────────────────────

const ISSUER = 'did:web:status.example';
const METHOD = `${ISSUER}#status-1`;
const STATUS_URL = 'https://status.example/lists/1';
const NOW = () => Date.parse('2026-06-30T00:00:00Z');

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const publicJwk = publicKey.export({ format: 'jwk' }) as { kty: string; crv: string; x: string };

function didDocument(method: Record<string, unknown> = { id: METHOD, publicKeyJwk: publicJwk }): DIDDocument {
  return {
    id: ISSUER,
    verificationMethod: [{ type: 'JsonWebKey2020', controller: ISSUER, ...method } as never],
    assertionMethod: [METHOD],
  };
}

function resolverFor(document: DIDDocument | null): DIDResolver {
  return { resolve: async (did) => (did === ISSUER ? document : null) };
}

/** A Bitstring Status List credential with the given indices set (16 KiB list, MSB-first). */
function statusList(revoked: number[], issuer: unknown = ISSUER): Record<string, unknown> {
  const bytes = new Uint8Array(16 * 1024);
  for (const i of revoked) bytes[i >>> 3] = (bytes[i >>> 3] ?? 0) | (0x80 >> (i & 7));
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: STATUS_URL,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer,
    validFrom: '2026-01-01T00:00:00Z',
    credentialSubject: {
      id: `${STATUS_URL}#list`,
      type: 'BitstringStatusList',
      statusPurpose: 'revocation',
      encodedList: `u${gzipSync(bytes).toString('base64url')}`,
    },
  };
}

/** eddsa-jcs-2022 written out independently of the module under test. */
function signEddsaJcs2022(
  document: Record<string, unknown>,
  options: Record<string, unknown> = {},
): Record<string, unknown> {
  const proof: Record<string, unknown> = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: '2026-01-01T00:00:00Z',
    verificationMethod: METHOD,
    proofPurpose: 'assertionMethod',
    ...options,
  };
  const config = { ...proof, '@context': document['@context'] };
  const hash = (value: unknown) => createHash('sha256').update(canonicalize(value)).digest();
  const signature = sign(null, Buffer.concat([hash(config), hash(document)]), privateKey);
  return { ...document, proof: { ...proof, proofValue: `z${base58Encode(new Uint8Array(signature))}` } };
}

function jsonFetch(body: unknown): SafeFetch {
  return async () => ({ ok: true, status: 200, json: () => Promise.resolve(body) });
}

const verify = (credential: Record<string, unknown>, document: DIDDocument | null = didDocument()) =>
  createStatusListProofVerifier({ didResolver: resolverFor(document) })(credential);

// ── createStatusListProofVerifier ────────────────────────────────────────────

describe('createStatusListProofVerifier (eddsa-jcs-2022)', () => {
  it('accepts a list signed by a key in its issuer DID document', async () => {
    expect(await verify(signEddsaJcs2022(statusList([5])))).toBe(true);
  });

  it('accepts a list signed by builders.kya-os.org, an independent signer', async () => {
    const fixture = JSON.parse(
      readFileSync(new URL('./__fixtures__/builders-status-list.json', import.meta.url), 'utf8'),
    ) as { didDocument: DIDDocument; statusListCredential: Record<string, unknown> };
    const didResolver: DIDResolver = {
      resolve: async (did) => (did === fixture.didDocument.id ? fixture.didDocument : null),
    };
    const verifyList = createStatusListProofVerifier({ didResolver });
    expect(await verifyList(fixture.statusListCredential)).toBe(true);

    const subject = fixture.statusListCredential.credentialSubject as Record<string, unknown>;
    const altered = { ...fixture.statusListCredential, credentialSubject: { ...subject, statusPurpose: 'suspension' } };
    expect(await verifyList(altered)).toBe(false);
  });

  it('rejects a list whose bits were changed after signing', async () => {
    const signed = signEddsaJcs2022(statusList([5]));
    const cleared = { ...signed, credentialSubject: statusList([]).credentialSubject };
    expect(await verify(cleared)).toBe(false);
  });

  it('rejects a changed proof option, since the options are signed too', async () => {
    const signed = signEddsaJcs2022(statusList([5]));
    const proof = signed.proof as Record<string, unknown>;
    expect(await verify({ ...signed, proof: { ...proof, created: '2027-01-01T00:00:00Z' } })).toBe(false);
  });

  it('rejects a method that does not belong to the list issuer', async () => {
    const signed = signEddsaJcs2022(statusList([5], 'did:web:other.example'));
    expect(await verify(signed)).toBe(false);
  });

  it('reads an { id } issuer and a relative method id', async () => {
    const signed = signEddsaJcs2022(statusList([5], { id: ISSUER, name: 'Status issuer' }));
    const relative = didDocument({ id: '#status-1', publicKeyJwk: publicJwk });
    expect(await verify(signed, relative)).toBe(true);
  });

  it('reads a publicKeyMultibase key', async () => {
    const raw = Buffer.from(publicJwk.x, 'base64url');
    const multibase = `z${base58Encode(new Uint8Array([0xed, 0x01, ...raw]))}`;
    const signed = signEddsaJcs2022(statusList([5]));
    expect(await verify(signed, didDocument({ id: METHOD, publicKeyMultibase: multibase }))).toBe(true);
  });

  it('rejects when the method is not in the DID document, or the DID does not resolve', async () => {
    const signed = signEddsaJcs2022(statusList([5]));
    expect(await verify(signed, didDocument({ id: `${ISSUER}#other`, publicKeyJwk: publicJwk }))).toBe(false);
    expect(await verify(signed, null)).toBe(false);
  });

  it('rejects a key from a different pair', async () => {
    const other = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
    const signed = signEddsaJcs2022(statusList([5]));
    expect(await verify(signed, didDocument({ id: METHOD, publicKeyJwk: other }))).toBe(false);
  });

  it.each([
    ['no proof', (s: Record<string, unknown>) => ({ ...s, proof: undefined })],
    ['a proof set', (s: Record<string, unknown>) => ({ ...s, proof: [s.proof] })],
    ['another cryptosuite', (s: Record<string, unknown>) => ({ ...s, proof: { ...(s.proof as object), cryptosuite: 'eddsa-rdfc-2022' } })],
    ['another proof type', (s: Record<string, unknown>) => ({ ...s, proof: { ...(s.proof as object), type: 'Ed25519Signature2020' } })],
    ['another purpose', (s: Record<string, unknown>) => ({ ...s, proof: { ...(s.proof as object), proofPurpose: 'authentication' } })],
    ['a non-multibase proofValue', (s: Record<string, unknown>) => ({ ...s, proof: { ...(s.proof as object), proofValue: 'not-base58' } })],
    ['an oversized proofValue', (s: Record<string, unknown>) => ({ ...s, proof: { ...(s.proof as object), proofValue: `z${'2'.repeat(5000)}` } })],
  ])('rejects %s', async (_label, mutate) => {
    expect(await verify(mutate(signEddsaJcs2022(statusList([5]))))).toBe(false);
  });

  it('honours a proof @context only as a prefix of the document @context', async () => {
    const list = statusList([5]);
    const context = list['@context'] as string[];
    expect(await verify(signEddsaJcs2022(list, { '@context': context }))).toBe(true);
    const foreign = signEddsaJcs2022(list, { '@context': ['https://example.com/other/v1'] });
    expect(await verify(foreign)).toBe(false);
  });

  it('returns false rather than throwing when the resolver throws', async () => {
    const didResolver: DIDResolver = { resolve: async () => { throw new Error('offline'); } };
    const verifyList = createStatusListProofVerifier({ didResolver });
    expect(await verifyList(signEddsaJcs2022(statusList([5])))).toBe(false);
  });
});

// ── createRevocationChecker with verifyStatusList ────────────────────────────

describe('createRevocationChecker with verifyStatusList', () => {
  const entry = (index: number) => ({ statusListCredential: STATUS_URL, statusListIndex: String(index) });
  const checker = (list: Record<string, unknown>, verifyStatusList: Parameters<typeof createRevocationChecker>[0]['verifyStatusList']) =>
    createRevocationChecker({ fetch: jsonFetch(list), now: NOW, verifyStatusList });

  it('reads the bits of a list whose proof verifies', async () => {
    const check = checker(signEddsaJcs2022(statusList([5])), createStatusListProofVerifier({ didResolver: resolverFor(didDocument()) }));
    expect(await check(entry(5))).toEqual({ revoked: true, fresh: true });
    expect(await check(entry(6))).toEqual({ revoked: false, fresh: true });
  });

  it('fails closed on a list altered after signing, though its bit reads clear', async () => {
    const signed = signEddsaJcs2022(statusList([5]));
    const cleared = { ...signed, credentialSubject: statusList([]).credentialSubject };
    const verifyStatusList = createStatusListProofVerifier({ didResolver: resolverFor(didDocument()) });
    expect(await checker(cleared, undefined)(entry(5))).toEqual({ revoked: false, fresh: true });
    expect(await checker(cleared, verifyStatusList)(entry(5))).toEqual({ revoked: true, fresh: false });
  });

  it('hands the verifier the fetched credential and fails closed on false, a throw, or a non-true value', async () => {
    const list = statusList([]);
    const seen = vi.fn(() => true);
    expect(await checker(list, seen)(entry(5))).toEqual({ revoked: false, fresh: true });
    expect(seen).toHaveBeenCalledWith(list);

    expect(await checker(list, () => false)(entry(5))).toEqual({ revoked: true, fresh: false });
    expect(await checker(list, () => { throw new Error('bad'); })(entry(5))).toEqual({ revoked: true, fresh: false });
    expect(await checker(list, async () => 'yes' as unknown as boolean)(entry(5))).toEqual({ revoked: true, fresh: false });
  });

  it('fails a chain whose list the verifier rejects', async () => {
    const result = await evaluateRevocationChain([entry(5)], checker(statusList([]), () => false));
    expect(result.ok).toBe(false);
  });
});
