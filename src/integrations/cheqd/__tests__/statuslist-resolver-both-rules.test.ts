/**
 * CheqdStatusListResolver reads a status list only when both rules hold: the list's issuer is the
 * pinned DID, the one issuer it trusts for every credential (`acceptStatusList`), and the list's
 * proof verifies with a key that issuer's DID document lists under `assertionMethod` (SPEC.md §6.2).
 * Acme, the pinned issuer, keeps `#login-1` under `authentication` and `#key-1` under
 * `assertionMethod`; another DID keeps its own `#key-1` under its own `assertionMethod`. Every list
 * here states its URL as its `id` and has the entry's bit clear, so a list that is read reports the
 * credential active, and one that is refused throws.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { CheqdStatusListResolver } from '../statuslist-resolver.js';
import { createRealCryptoProvider, createRealStatusListManager } from '../../../__tests__/audit/helpers/crypto-helpers.js';
import { keyOf } from '../../../__tests__/utils/delegation-credentials.js';
import { documentOf, issuerDidDocument, methodOf } from '../../../__tests__/utils/did-documents.js';
import { statusListGzipCodec } from '../../../utils/statuslist-gzip.js';
import type { AgentIdentity, FetchProvider } from '../../../providers/base.js';
import type { DIDDocument } from '../../../delegation/vc-verifier.types.js';
import type { NodeCryptoProvider } from '../../../__tests__/utils/node-crypto-provider.js';
import type { CredentialStatus, StatusList2021Credential } from '../../../types/protocol.js';

const ACME = 'did:cheqd:testnet:acme-status';
const OTHER = 'did:cheqd:testnet:other-status';

describe("CheqdStatusListResolver holds a list to its trusted issuer and to that issuer's assertionMethod key", () => {
  let crypto: NodeCryptoProvider;
  let login: AgentIdentity;
  let assert: AgentIdentity;
  let otherAssert: AgentIdentity;
  const signedWith = new Map<AgentIdentity, { entry: CredentialStatus; list: StatusList2021Credential }>();
  let documents: Record<string, DIDDocument>;

  /** Check the entry of the list `key` signed, with the resolver pinned to `pinned`. */
  const check = (key: AgentIdentity, pinned = ACME) => {
    const { entry, list } = signedWith.get(key)!;
    const fetchProvider = {
      fetch: async () => new Response(JSON.stringify(list)),
    } as unknown as FetchProvider;
    return new CheqdStatusListResolver({
      fetchProvider,
      didResolver: { resolve: async (did) => documents[did] ?? null },
      cryptoProvider: crypto,
      expectedIssuerDid: pinned,
      decompressor: statusListGzipCodec,
      cacheTtlMs: 0,
    }).checkStatus(entry);
  };

  beforeAll(async () => {
    crypto = createRealCryptoProvider();
    login = await keyOf(ACME, 'login-1');
    assert = await keyOf(ACME, 'key-1');
    otherAssert = await keyOf(OTHER, 'key-1');
    // Each key is published as cheqd publishes one, as a multibase Ed25519 public key.
    const method = (key: AgentIdentity) => methodOf(key, { form: 'multibase' });
    documents = {
      [ACME]: documentOf({ verificationMethod: [method(login), method(assert)], authentication: [login.kid], assertionMethod: [assert.kid] }, ACME),
      [OTHER]: issuerDidDocument(method(otherAssert)),
    };
    for (const key of [login, assert, otherAssert]) {
      const setup = createRealStatusListManager(crypto, key, { statusListBaseUrl: 'https://status.example' });
      const entry = await setup.manager.allocateStatusEntry('revocation');
      signedWith.set(key, { entry, list: (await setup.storage.getStatusList(entry.statusListCredential))! });
    }
  });

  it('refuses a list of the pinned issuer signed with a key it lists only under authentication', async () => {
    expect(signedWith.get(login)!.list).toMatchObject({ issuer: ACME, id: signedWith.get(login)!.entry.statusListCredential });
    await expect(check(login)).rejects.toThrow(
      `Verification method "${login.kid}" not found under assertionMethod of "${ACME}"`,
    );
  });

  it('refuses a list signed with an assertionMethod key of an issuer the resolver does not trust', async () => {
    await expect(check(otherAssert)).rejects.toThrow(`status list issuer "${OTHER}" does not keep this list's URL: "${ACME}" does, as the issuer this resolver is configured with`);
    // The key is sound: pinned to its issuer, the same list is read.
    expect(await check(otherAssert, OTHER)).toBe(false);
  });

  it('reads a list of the pinned issuer signed with the key it lists under assertionMethod', async () => {
    expect(await check(assert)).toBe(false);
  });
});
