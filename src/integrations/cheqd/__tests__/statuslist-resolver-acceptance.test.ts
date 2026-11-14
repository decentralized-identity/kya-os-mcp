/**
 * CheqdStatusListResolver applies the shared status-list acceptance rule with its `expectedIssuerDid`
 * pin as the one accepted issuer. The pin is the verifier's explicit trust in a status authority (W3C
 * Bitstring Status List v1.0 §3.2), so the pinned DID's list is read for any credential, whoever
 * issued it, and no other list is read. The list must also be of the entry's purpose, and must state,
 * as its `id`, the URL it was fetched from, byte for byte: the resolver does not know whose
 * credential it reads, and only the `id` binds a list to the URL it is served at. A real signed list,
 * served through a stub transport, as in `statuslist-resolver.test.ts`.
 */
import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { CheqdStatusListResolver } from '../statuslist-resolver.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
  createRealSignatureVerifier,
  createRealSigningFunction,
  createRealStatusListManager,
  type RealStatusListSetup,
} from '../../../__tests__/audit/helpers/crypto-helpers.js';
import { createDidKeyResolver } from '../../../delegation/did-key-resolver.js';
import { DelegationCredentialIssuer } from '../../../delegation/vc-issuer.js';
import { DelegationCredentialVerifier, type StatusListResolver } from '../../../delegation/vc-verifier.js';
import { canonicalizeJSON } from '../../../delegation/utils.js';
import { statusListGzipCodec } from '../../../utils/statuslist-gzip.js';
import type { AgentIdentity, FetchProvider } from '../../../providers/base.js';
import type { NodeCryptoProvider } from '../../../__tests__/utils/node-crypto-provider.js';
import type { CredentialStatus } from '../../../types/protocol.js';

describe('CheqdStatusListResolver and the status-list acceptance rule', () => {
  let crypto: NodeCryptoProvider;
  let pinned: AgentIdentity;
  let other: AgentIdentity;
  let setup: RealStatusListSetup;
  let otherSetup: RealStatusListSetup;
  let clearEntry: CredentialStatus;
  let revokedEntry: CredentialStatus;
  let served: unknown;

  const fetchProvider = {
    async fetch(url: string) {
      const body = served ?? (await setup.storage.getStatusList(url));
      return new Response(JSON.stringify(body ?? null), { status: body == null ? 404 : 200 });
    },
  } as unknown as FetchProvider;

  /** A fresh resolver, held as a verifier holds it: a `StatusListResolver`, called with each credential's context. */
  const makeResolver = (): StatusListResolver =>
    new CheqdStatusListResolver({
      fetchProvider,
      didResolver: createDidKeyResolver(),
      cryptoProvider: crypto,
      expectedIssuerDid: pinned.did,
      decompressor: statusListGzipCodec,
      cacheTtlMs: 0,
    });

  /** The pinned issuer's list with `change` applied, signed again by that issuer, so its proof verifies. */
  async function resignedList(change: (unsigned: Record<string, unknown>) => Record<string, unknown>) {
    const stored = await setup.storage.getStatusList(clearEntry.statusListCredential);
    const { proof: _proof, ...unsigned } = stored as unknown as Record<string, unknown>;
    const changed = change(unsigned);
    const sign = createRealSigningFunction(crypto, pinned);
    return { ...changed, proof: await sign(canonicalizeJSON(changed), pinned.did, pinned.kid) };
  }

  beforeAll(async () => {
    crypto = createRealCryptoProvider();
    pinned = await createRealIdentity(crypto);
    other = await createRealIdentity(crypto);
    setup = createRealStatusListManager(crypto, pinned, { statusListBaseUrl: 'https://status.example' });
    clearEntry = await setup.manager.allocateStatusEntry('revocation');
    revokedEntry = await setup.manager.allocateStatusEntry('revocation');
    await setup.manager.updateStatus(revokedEntry, true);
    otherSetup = createRealStatusListManager(crypto, other, { statusListBaseUrl: 'https://status.example' });
    await otherSetup.manager.allocateStatusEntry('revocation');
  });

  beforeEach(() => {
    served = undefined;
  });

  /** Indexes no reader takes, each with the refusal that quotes it: bounded, and well-formed text. */
  const REFUSED_INDEXES: [string, string][] = [
    [
      `${'7'.repeat(10)}x${'\u{1F600}'.repeat(5000)}\uD800`,
      `Invalid statusListIndex "${'7'.repeat(10)}x${'\u{1F600}'.repeat(53)}"...: must be a non-negative decimal string`,
    ],
    ['9'.repeat(20_000), `statusListIndex "${'9'.repeat(64)}"... exceeds the safe integer range`],
  ];
  const isWellFormed = (text: string): boolean => (text as string & { isWellFormed(): boolean }).isWellFormed();

  describe('the pin', () => {
    it("reads the pinned issuer's list, whichever credential issuer the caller names", async () => {
      const resolver = makeResolver();
      for (const context of [undefined, { credentialIssuer: pinned.did }, { credentialIssuer: other.did }]) {
        expect(await resolver.checkStatus(clearEntry, context)).toBe(false);
        expect(await resolver.checkStatus(revokedEntry, context)).toBe(true);
      }
    });

    it("reads the pinned issuer's list that names its issuer as an { id } object, checking its proof with the pinned DID's key", async () => {
      served = await resignedList((list) => ({ ...list, issuer: { id: pinned.did } }));
      expect(await makeResolver().checkStatus(clearEntry)).toBe(false);
      expect(await makeResolver().checkStatus(revokedEntry)).toBe(true);
    });

    it('rejects a list another DID issued and signed, even for that DID’s own credential', async () => {
      served = await otherSetup.storage.getStatusList(clearEntry.statusListCredential);
      expect(served).toMatchObject({ issuer: other.did });
      for (const context of [undefined, { credentialIssuer: other.did }]) {
        await expect(makeResolver().checkStatus(clearEntry, context)).rejects.toThrow(
          `status list issuer "${other.did}" is not the expected issuer ("${pinned.did}")`,
        );
      }
    });
  });

  describe('the stated id and the statusPurpose', () => {
    it('rejects a signed list whose id is not the URL it was fetched from', async () => {
      served = await resignedList((list) => ({ ...list, id: 'https://status.example/another-list' }));
      await expect(makeResolver().checkStatus(clearEntry)).rejects.toThrow(
        `status list id "https://status.example/another-list" is not the URL it was fetched from ("${clearEntry.statusListCredential}")`,
      );
    });

    it('rejects a signed list that states no id, for a credential of any issuer', async () => {
      served = await resignedList(({ id: _id, ...list }) => list);
      for (const context of [undefined, { credentialIssuer: pinned.did }, { credentialIssuer: other.did }]) {
        await expect(makeResolver().checkStatus(clearEntry, context)).rejects.toThrow(
          `status list states no id, but must state the URL it was fetched from ("${clearEntry.statusListCredential}")`,
        );
      }
    });

    it('rejects a signed list whose id is the same resource named another way, comparing byte for byte', async () => {
      const url = clearEntry.statusListCredential;
      const named = [url.toUpperCase(), `${url}/`, `did:cheqd:testnet:${pinned.did.slice(-8)}/resources/1`];
      // A cheqd resolver URL names its resource in the query, so an id that drops or changes it is another list.
      const near = [url.slice(0, url.lastIndexOf('/') + 1), `${url}?resourceName=another-list`];
      for (const id of [...named, ...near]) {
        served = await resignedList((list) => ({ ...list, id }));
        await expect(makeResolver().checkStatus(clearEntry)).rejects.toThrow(`status list id "${id}" is not the URL it was fetched from`);
      }
    });

    // Verifiable Credentials Status List v2021 §2.2 has a StatusList2021 list state one purpose; only a
    // list typed as a Bitstring Status List v1.0 list in both places its §2.2 names may state several.
    it("rejects a signed StatusList2021 list whose statusPurpose is an array, even one that includes the entry's", async () => {
      for (const statusPurpose of [['suspension', 'revocation'], ['revocation']]) {
        served = await resignedList((list) => ({
          ...list,
          credentialSubject: { ...(list.credentialSubject as object), statusPurpose },
        }));
        await expect(makeResolver().checkStatus(revokedEntry)).rejects.toThrow(
          'status list statusPurpose is an array, which only a BitstringStatusListCredential with a BitstringStatusList ' +
            `subject may state (the entry's is "revocation")`,
        );
      }
    });

    it('holds a list typed as a Bitstring Status List in its type alone to one string', async () => {
      const typed = (statusPurpose: unknown) =>
        resignedList((list) => ({
          ...list,
          type: [...(list.type as string[]), 'BitstringStatusListCredential'],
          credentialSubject: { ...(list.credentialSubject as object), statusPurpose },
        }));
      served = await typed(['suspension', 'revocation']);
      await expect(makeResolver().checkStatus(revokedEntry)).rejects.toThrow('status list statusPurpose is an array');
      served = await typed('revocation');
      expect(await makeResolver().checkStatus(revokedEntry)).toBe(true);
    });

    it('never reads a list typed as a Bitstring Status List in its subject, whatever purposes it states, since it reads StatusList2021 lists alone', async () => {
      const bitstringSubject = (list: Record<string, unknown>, statusPurpose: unknown) => ({
        ...list,
        credentialSubject: { ...(list.credentialSubject as object), type: 'BitstringStatusList', statusPurpose },
      });
      const shapes: [(list: Record<string, unknown>, statusPurpose: unknown) => Record<string, unknown>, string][] = [
        [
          (list, statusPurpose) => ({ ...bitstringSubject(list, statusPurpose), type: ['VerifiableCredential', 'BitstringStatusListCredential'] }),
          'Fetched resource is not a StatusList2021Credential',
        ],
        [bitstringSubject, 'Status list credentialSubject is malformed (missing StatusList2021 encodedList)'],
      ];
      for (const [shape, refusal] of shapes) {
        for (const statusPurpose of [['suspension', 'revocation'], 'revocation']) {
          served = await resignedList((list) => shape(list, statusPurpose));
          await expect(makeResolver().checkStatus(revokedEntry)).rejects.toThrow(refusal);
        }
      }
    });

    it('holds a cached list to each entry’s purpose', async () => {
      const resolver = new CheqdStatusListResolver({
        fetchProvider,
        didResolver: createDidKeyResolver(),
        cryptoProvider: crypto,
        expectedIssuerDid: pinned.did,
        decompressor: statusListGzipCodec,
      });
      expect(await resolver.checkStatus(revokedEntry)).toBe(true);
      await expect(resolver.checkStatus({ ...revokedEntry, statusPurpose: 'suspension' })).rejects.toThrow(
        `status list statusPurpose mismatch: the list's is "revocation" and the entry's is "suspension"`,
      );
    });
  });

  describe('the values a refusal quotes', () => {
    const LONG = 'v'.repeat(100_000);
    const LONG_QUOTED = `"${'v'.repeat(64)}"...`;
    const NAMED: unknown = JSON.parse('{"toString":"revocation"}');
    const FORMS: [unknown, string][] = [[LONG, LONG_QUOTED], [NAMED, 'of type object']];
    const stating = (statusPurpose: unknown) => ({ ...revokedEntry, statusPurpose }) as CredentialStatus;
    const withSubject = (list: Record<string, unknown>, fields: Record<string, unknown>) => ({
      ...list,
      credentialSubject: { ...(list.credentialSubject as object), ...fields },
    });

    it("quotes at most 64 characters of the list's id and names one that is not a string by its type", async () => {
      for (const [id, as] of FORMS) {
        served = await resignedList((list) => ({ ...list, id }));
        await expect(makeResolver().checkStatus(clearEntry)).rejects.toThrow(
          `status list id ${as} is not the URL it was fetched from ("${clearEntry.statusListCredential}")`,
        );
      }
    });

    it('says where the id and the URL first differ when both read the same once cut, as a reordered query does', async () => {
      const url = 'https://resolver.cheqd.net/1.0/identifiers/did:cheqd:testnet:abc?resourceName=s&resourceType=StatusList2021Revocation';
      served = await resignedList((list) => ({ ...list, id: url.replace('resourceName=s&resourceType=StatusList2021Revocation', 'resourceType=StatusList2021Revocation&resourceName=s') }));
      const cut = '"https://resolver.cheqd.net/1.0/identifiers/did:cheqd:testnet:abc"...';
      await expect(makeResolver().checkStatus({ ...clearEntry, statusListCredential: url })).rejects.toThrow(
        new Error(`status list id ${cut} is not the URL it was fetched from (${cut}); they first differ at character 74`),
      );
    });

    it("quotes at most 64 characters of the list's issuer and statusPurpose, and refuses either as absent when it is not a string", async () => {
      served = await resignedList((list) => ({ ...list, issuer: LONG }));
      await expect(makeResolver().checkStatus(clearEntry)).rejects.toThrow(
        `status list issuer ${LONG_QUOTED} is not the expected issuer ("${pinned.did}")`,
      );
      served = await resignedList((list) => withSubject(list, { statusPurpose: LONG }));
      await expect(makeResolver().checkStatus(clearEntry)).rejects.toThrow(
        `status list statusPurpose mismatch: the list's is ${LONG_QUOTED} and the entry's is "revocation"`,
      );
      served = await resignedList((list) => ({ ...list, issuer: NAMED }));
      await expect(makeResolver().checkStatus(clearEntry)).rejects.toThrow('status list names no issuer');
      served = await resignedList((list) => withSubject(list, { statusPurpose: NAMED }));
      await expect(makeResolver().checkStatus(clearEntry)).rejects.toThrow(
        `status list has no statusPurpose (the entry's is "revocation")`,
      );
    });

    it("quotes at most 64 characters of the entry's statusPurpose and names one that is not a string by its type", async () => {
      for (const [statusPurpose, as] of FORMS) {
        served = undefined;
        await expect(makeResolver().checkStatus(stating(statusPurpose))).rejects.toThrow(
          `status list statusPurpose mismatch: the list's is "revocation" and the entry's is ${as}`,
        );
        served = await resignedList(({ credentialSubject, ...list }) => {
          const { statusPurpose: _declared, ...subject } = credentialSubject as Record<string, unknown>;
          return { ...list, credentialSubject: subject };
        });
        await expect(makeResolver().checkStatus(stating(statusPurpose))).rejects.toThrow(
          `status list has no statusPurpose (the entry's is ${as})`,
        );
      }
    });

    it('quotes at most 64 characters of an index it refuses, as well-formed text', async () => {
      for (const [statusListIndex, refusal] of REFUSED_INDEXES) {
        const error = (await makeResolver().checkStatus({ ...clearEntry, statusListIndex }).catch((e: unknown) => e)) as Error;
        expect(error).toEqual(new Error(refusal));
        expect(isWellFormed(error.message)).toBe(true);
        expect(error.message.length).toBeLessThanOrEqual(200);
      }
    });

    it('quotes at most 64 characters of the URL, which only an https string reaches', async () => {
      served = await setup.storage.getStatusList(clearEntry.statusListCredential);
      const url = `https://status.example/${LONG}`;
      await expect(makeResolver().checkStatus({ ...clearEntry, statusListCredential: url })).rejects.toThrow(
        `status list id "${clearEntry.statusListCredential}" is not the URL it was fetched from ("${url.slice(0, 64)}"...)`,
      );
      await expect(makeResolver().checkStatus({ ...clearEntry, statusListCredential: NAMED as string })).rejects.toThrow(
        'credentialStatus.statusListCredential must be an https URL',
      );
    });
  });

  describe('the signature', () => {
    it('rejects, on every read, a list that names the pinned DID but carries another key’s signature, and caches none', async () => {
      let fetches = 0;
      const counting = {
        fetch(url: string) {
          fetches += 1;
          return fetchProvider.fetch(url);
        },
      } as unknown as FetchProvider;
      const resolver = new CheqdStatusListResolver({
        fetchProvider: counting,
        didResolver: createDidKeyResolver(),
        cryptoProvider: crypto,
        expectedIssuerDid: pinned.did,
        decompressor: statusListGzipCodec,
        cacheTtlMs: 60_000,
      });
      const stored = await setup.storage.getStatusList(clearEntry.statusListCredential);
      const { proof: _proof, ...unsigned } = stored as unknown as Record<string, unknown>;
      const signedByOther = createRealSigningFunction(crypto, other);
      served = { ...unsigned, proof: await signedByOther(canonicalizeJSON(unsigned), pinned.did, pinned.kid) };
      for (let read = 0; read < 2; read += 1) {
        await expect(resolver.checkStatus(clearEntry)).rejects.toThrow(
          'Status list signature verification FAILED against the issuer DID document',
        );
      }
      expect(fetches).toBe(2);
      served = undefined;
      expect(await resolver.checkStatus(revokedEntry)).toBe(true);
      expect(await resolver.checkStatus(clearEntry)).toBe(false);
      expect(fetches).toBe(3);
    });
  });

  describe('invalidateCache', () => {
    it('defeats upstream caches until a list is accepted, so a refused response does not end it', async () => {
      const cacheControl: unknown[] = [];
      const recording = {
        fetch(url: string, init?: { headers?: Record<string, string> }) {
          cacheControl.push(init?.headers?.['Cache-Control']);
          return fetchProvider.fetch(url);
        },
      } as unknown as FetchProvider;
      const resolver = new CheqdStatusListResolver({
        fetchProvider: recording,
        didResolver: createDidKeyResolver(),
        cryptoProvider: crypto,
        expectedIssuerDid: pinned.did,
        decompressor: statusListGzipCodec,
        cacheTtlMs: 0,
      });
      resolver.invalidateCache();
      served = await resignedList((list) => ({ ...list, id: 'https://status.example/another-list' }));
      await expect(resolver.checkStatus(revokedEntry)).rejects.toThrow(/is not the URL it was fetched from/);
      served = undefined;
      expect(await resolver.checkStatus(revokedEntry)).toBe(true);
      expect(await resolver.checkStatus(revokedEntry)).toBe(true);
      expect(cacheControl).toEqual(['no-cache', 'no-cache', undefined]);
    });
  });

  describe('through DelegationCredentialVerifier', () => {
    /** A delegation credential issued and signed by `by`, whose status is `status`. */
    const credentialOf = (by: AgentIdentity, status: CredentialStatus) =>
      new DelegationCredentialIssuer(
        { getDid: () => by.did, getKeyId: () => by.kid, getPrivateKey: () => by.privateKey },
        createRealSigningFunction(crypto, by),
      ).issueDelegationCredential(
        {
          id: 'del-status-pin',
          issuerDid: by.did,
          subjectDid: 'did:web:agent.example',
          vcId: 'urn:uuid:status-pin',
          constraints: { scopes: ['tools:read'] },
          signature: '',
          status: 'active',
          createdAt: Date.now(),
        },
        { credentialStatus: status },
      );

    const verify = async (by: AgentIdentity, status: CredentialStatus) =>
      new DelegationCredentialVerifier({
        didResolver: createDidKeyResolver(),
        signatureVerifier: createRealSignatureVerifier(crypto),
        statusListResolver: makeResolver(),
      }).verifyDelegationCredential(await credentialOf(by, status), { skipCache: true });

    it("reads the pinned issuer's list for its own credentials and for another issuer's", async () => {
      for (const by of [pinned, other]) {
        expect(await verify(by, clearEntry)).toMatchObject({ valid: true, stage: 'complete' });
        expect(await verify(by, revokedEntry)).toMatchObject({ valid: false, statusOutcome: 'revoked' });
      }
    });

    it('denies a credential whose list is not the pinned issuer’s as status_unresolvable', async () => {
      served = await otherSetup.storage.getStatusList(clearEntry.statusListCredential);
      const result = await verify(other, clearEntry);
      expect(result).toMatchObject({ valid: false, stage: 'status', statusOutcome: 'status_unresolvable' });
      expect(result.reason).toMatch(/is not the expected issuer/);
    });

    it('denies a credential whose index it refuses with a bounded, well-formed reason', async () => {
      // RFC 8785 refuses a lone surrogate, so no proof can cover such an index: the entry is changed
      // after signing, and only the signature check is skipped.
      const signed = await credentialOf(pinned, clearEntry);
      const verifier = new DelegationCredentialVerifier({ didResolver: createDidKeyResolver(), statusListResolver: makeResolver() });
      for (const [statusListIndex, refusal] of REFUSED_INDEXES) {
        const changed = { ...signed, credentialStatus: { ...clearEntry, statusListIndex } };
        const result = await verifier.verifyDelegationCredential(changed, { skipCache: true, skipSignature: true });
        expect(result).toMatchObject({ valid: false, stage: 'status', statusOutcome: 'status_unresolvable' });
        expect(result.reason).toBe(`Status check error: ${refusal}`);
        expect(isWellFormed(result.reason ?? '')).toBe(true);
      }
    });

    it('denies a credential whose statusPurpose is not a string with the reason the resolver gives', async () => {
      const named = JSON.parse('{"toString":"revocation"}') as CredentialStatus['statusPurpose'];
      const result = await verify(pinned, { ...revokedEntry, statusPurpose: named });
      expect(result).toMatchObject({ valid: false, stage: 'status', statusOutcome: 'status_unresolvable' });
      expect(result.reason).toBe(
        `Status check error: status list statusPurpose mismatch: the list's is "revocation" and the entry's is of type object`,
      );
    });
  });
});
