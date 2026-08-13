/**
 * CheqdStatusListResolver — the DEF CON demo's 18-case fail-closed matrix,
 * ported onto upstream-native fixtures: a REAL signed status list minted by
 * `StatusList2021Manager` (real Ed25519, real gzip), served through a stub
 * `FetchProvider`, with the issuer's key published MULTIBASE-ONLY in the DID
 * document — the cheqd-realistic shape `verificationMethodJwk` exists for.
 */
import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import {
  CheqdStatusListResolver,
  createCheqdStatusListResolver,
} from '../statuslist-resolver.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
  createRealStatusListManager,
  nodeDecompressor,
  type RealStatusListSetup,
} from '../../../__tests__/audit/helpers/crypto-helpers.js';
import { createDidKeyResolver } from '../../../delegation/did-key-resolver.js';
import { base58Encode } from '../../../utils/base58.js';
import { base64urlDecodeToBytes } from '../../../utils/base64.js';
import type { AgentIdentity } from '../../../providers/base.js';
import type { FetchProvider } from '../../../providers/base.js';
import type { DIDResolver } from '../../../delegation/vc-verifier.types.js';
import type { NodeCryptoProvider } from '../../../__tests__/utils/node-crypto-provider.js';
import type {
  CredentialStatus,
  StatusList2021Credential,
} from '../../../types/protocol.js';

describe('CheqdStatusListResolver (real crypto, stubbed transport)', () => {
  let crypto: NodeCryptoProvider;
  let issuerIdentity: AgentIdentity;
  let setup: RealStatusListSetup;
  let clearEntry: CredentialStatus;
  let revokedEntry: CredentialStatus;
  let listUrl: string;
  let signedList: StatusList2021Credential;
  let didResolver: DIDResolver;

  let fetchLog: Array<{ url: string; headers: Record<string, string> }> = [];
  let serveOverride: (() => unknown) | null = null;
  let serveStatus = 200;

  const fetchProvider = {
    async fetch(url: string, init?: { headers?: Record<string, string> }) {
      fetchLog.push({ url, headers: init?.headers ?? {} });
      const body = serveOverride
        ? serveOverride()
        : await setup.storage.getStatusList(url);
      return {
        ok: serveStatus === 200 && body != null,
        status: body == null && serveStatus === 200 ? 404 : serveStatus,
        json: async () => body,
      } as unknown as Response;
    },
  } as unknown as FetchProvider;

  const makeResolver = (
    overrides?: Partial<ConstructorParameters<typeof CheqdStatusListResolver>[0]>,
  ) =>
    new CheqdStatusListResolver({
      fetchProvider,
      didResolver,
      cryptoProvider: crypto,
      expectedIssuerDid: issuerIdentity.did,
      decompressor: nodeDecompressor,
      cacheTtlMs: 0, // test isolation; caching cases opt in explicitly
      ...overrides,
    });

  beforeAll(async () => {
    crypto = createRealCryptoProvider();
    issuerIdentity = await createRealIdentity(crypto);
    setup = createRealStatusListManager(crypto, issuerIdentity, {
      statusListBaseUrl: 'https://status.example',
    });

    clearEntry = await setup.manager.allocateStatusEntry('revocation');
    revokedEntry = await setup.manager.allocateStatusEntry('revocation');
    await setup.manager.updateStatus(revokedEntry, true);

    listUrl = clearEntry.statusListCredential;
    const stored = await setup.storage.getStatusList(listUrl);
    if (!stored) throw new Error('fixture: status list not stored');
    signedList = stored;

    // Publish the issuer's key MULTIBASE-ONLY (cheqd DID documents publish
    // publicKeyMultibase, not JWKs) under the kid the signing function names.
    const didKeyDoc = await createDidKeyResolver().resolve(issuerIdentity.did);
    const jwk = didKeyDoc?.verificationMethod?.[0]?.publicKeyJwk as { x: string };
    const raw = base64urlDecodeToBytes(jwk.x);
    const multibase = `z${base58Encode(new Uint8Array([0xed, 0x01, ...raw]))}`;
    didResolver = {
      async resolve(did: string) {
        if (did !== issuerIdentity.did) return null;
        return {
          id: did,
          verificationMethod: [
            {
              id: issuerIdentity.kid,
              type: 'Ed25519VerificationKey2020',
              controller: did,
              publicKeyMultibase: multibase,
            },
          ],
        };
      },
    };
  });

  beforeEach(() => {
    fetchLog = [];
    serveOverride = null;
    serveStatus = 200;
  });

  // ── Verdicts ──────────────────────────────────────────────────

  it('returns false for a clear index', async () => {
    expect(await makeResolver().checkStatus(clearEntry)).toBe(false);
  });

  it('returns true for a revoked index', async () => {
    expect(await makeResolver().checkStatus(revokedEntry)).toBe(true);
  });

  it('factory returns a working instance', () => {
    expect(
      createCheqdStatusListResolver({
        fetchProvider,
        didResolver,
        cryptoProvider: crypto,
        expectedIssuerDid: issuerIdentity.did,
        decompressor: nodeDecompressor,
      }),
    ).toBeInstanceOf(CheqdStatusListResolver);
  });

  // ── Fail-closed matrix ────────────────────────────────────────

  it('rejects a non-https statusListCredential URL', async () => {
    await expect(
      makeResolver().checkStatus({ ...clearEntry, statusListCredential: 'http://x' }),
    ).rejects.toThrow(/https URL/);
  });

  it.each(['0x2A', ' 42', '+42', '1e1', '4.2', 'abc', ''])(
    'rejects non-canonical statusListIndex %j',
    async (bad) => {
      await expect(
        makeResolver().checkStatus({ ...clearEntry, statusListIndex: bad }),
      ).rejects.toThrow(/canonical non-negative decimal/);
    },
  );

  it('rejects an index beyond the safe integer range', async () => {
    await expect(
      makeResolver().checkStatus({ ...clearEntry, statusListIndex: '9007199254740992' }),
    ).rejects.toThrow(/safe integer range/);
  });

  it('fail-closes on an out-of-range index (beyond the bitstring)', async () => {
    await expect(
      makeResolver().checkStatus({ ...clearEntry, statusListIndex: '99999999' }),
    ).rejects.toThrow(/out of range/);
  });

  it('fail-closes on an HTTP error', async () => {
    serveStatus = 500;
    await expect(makeResolver().checkStatus(clearEntry)).rejects.toThrow(/HTTP 500/);
  });

  it('fail-closes when the resource is not a StatusList2021Credential', async () => {
    serveOverride = () => ({ ...signedList, type: ['VerifiableCredential'] });
    await expect(makeResolver().checkStatus(clearEntry)).rejects.toThrow(
      /not a StatusList2021Credential/,
    );
  });

  it('fail-closes on a malformed credentialSubject', async () => {
    serveOverride = () => ({
      ...signedList,
      credentialSubject: { ...signedList.credentialSubject, encodedList: '' },
    });
    await expect(makeResolver().checkStatus(clearEntry)).rejects.toThrow(/malformed/);
  });

  it('fail-closes on an UNSIGNED list', async () => {
    serveOverride = () => {
      const { proof: _proof, ...unsigned } = signedList as unknown as Record<string, unknown>;
      return unsigned;
    };
    await expect(makeResolver().checkStatus(clearEntry)).rejects.toThrow(/unsigned/);
  });

  it('fail-closes when the issuer is not the pinned issuer', async () => {
    await expect(
      makeResolver({ expectedIssuerDid: 'did:cheqd:testnet:attacker' })
        .checkStatus(clearEntry),
    ).rejects.toThrow(/not the expected issuer/);
  });

  it('fail-closes on a statusPurpose mismatch', async () => {
    await expect(
      makeResolver().checkStatus({ ...clearEntry, statusPurpose: 'suspension' }),
    ).rejects.toThrow(/statusPurpose mismatch/);
  });

  it('fail-closes when the proof is missing proofValue', async () => {
    serveOverride = () => ({ ...signedList, proof: { type: 'Ed25519Signature2020' } });
    await expect(makeResolver().checkStatus(clearEntry)).rejects.toThrow(
      /missing proofValue/,
    );
  });

  it('fail-closes when the issuer DID cannot be resolved', async () => {
    const noDoc: DIDResolver = { resolve: async () => null };
    await expect(
      makeResolver({ didResolver: noDoc }).checkStatus(clearEntry),
    ).rejects.toThrow(/Could not resolve issuer DID/);
  });

  it('fail-closes when no verification method matches the proof kid', async () => {
    const wrongKid: DIDResolver = {
      resolve: async () => ({
        id: issuerIdentity.did,
        verificationMethod: [
          {
            id: `${issuerIdentity.did}#other-key`,
            type: 'Ed25519VerificationKey2020',
            controller: issuerIdentity.did,
            publicKeyBase58: base58Encode(new Uint8Array(32)),
          },
        ],
      }),
    };
    await expect(
      makeResolver({ didResolver: wrongKid }).checkStatus(clearEntry),
    ).rejects.toThrow(/no verification method matching/);
  });

  it('fail-closes on a TAMPERED list (signature no longer covers the bytes)', async () => {
    serveOverride = () => ({
      ...signedList,
      credentialSubject: {
        ...signedList.credentialSubject,
        statusPurpose: 'suspension', // any post-signing mutation
      },
    });
    await expect(makeResolver().checkStatus(clearEntry)).rejects.toThrow(
      /signature verification FAILED/,
    );
  });

  // ── Caching + transport discipline ────────────────────────────

  it('serves from the verified-document cache within TTL, with clean URLs', async () => {
    const cachingResolver = makeResolver({ cacheTtlMs: 60_000 });
    await cachingResolver.checkStatus(clearEntry);
    await cachingResolver.checkStatus(revokedEntry);
    expect(fetchLog.length).toBe(1); // one list, two credentials, one fetch
    expect(fetchLog[0]!.url).toBe(listUrl);
    expect(fetchLog[0]!.url).not.toContain('?'); // cheqd 400s on query params
    expect(fetchLog[0]!.headers['Accept']).toBe('application/json');
    expect(fetchLog[0]!.headers['Cache-Control']).toBeUndefined();
  });

  it('invalidateCache() refetches with upstream cache-busting headers', async () => {
    const cachingResolver = makeResolver({ cacheTtlMs: 60_000 });
    await cachingResolver.checkStatus(clearEntry);
    cachingResolver.invalidateCache();
    await cachingResolver.checkStatus(clearEntry);
    expect(fetchLog.length).toBe(2);
    expect(fetchLog[1]!.headers['Cache-Control']).toBe('no-cache');
    expect(fetchLog[1]!.headers['Pragma']).toBe('no-cache');
  });

  it('cacheTtlMs: 0 disables document caching (every call fetches)', async () => {
    const uncached = makeResolver();
    await uncached.checkStatus(clearEntry);
    await uncached.checkStatus(clearEntry);
    expect(fetchLog.length).toBe(2);
  });
});
