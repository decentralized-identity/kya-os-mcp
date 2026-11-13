/**
 * CheqdStatusListResolver checks a status list's signature only with a key the pinned issuer's DID
 * document lists under `assertionMethod`, and refuses a proof that states another purpose: a status
 * list is an assertion by its issuer (W3C Controlled Identifiers v1.0 §3.3). The issuer keeps
 * `#login-1` under `authentication` and `#key-1` under `assertionMethod`, both published
 * multibase-only as cheqd publishes them; some tests add `#key-2` under `assertionMethod` after
 * `#key-1`, one embeds there a method that carries no key, one names a method far longer than a
 * refusal reason quotes, and one publishes `#key-1` under another DID's control. A real signed
 * list, served through a stub transport, as in `statuslist-resolver.test.ts`.
 */
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { CheqdStatusListResolver } from '../statuslist-resolver.js';
import { createRealCryptoProvider, createRealStatusListManager } from '../../../__tests__/audit/helpers/crypto-helpers.js';
import { keyOf } from '../../../__tests__/utils/delegation-credentials.js';
import { statusListGzipCodec } from '../../../utils/statuslist-gzip.js';
import { anotherDidReason, methodOf } from '../../../__tests__/utils/did-documents.js';
import type { AgentIdentity, FetchProvider } from '../../../providers/base.js';
import type { DIDDocument } from '../../../delegation/vc-verifier.types.js';
import type { NodeCryptoProvider } from '../../../__tests__/utils/node-crypto-provider.js';
import type { CredentialStatus, StatusList2021Credential } from '../../../types/protocol.js';

const ISSUER = 'did:cheqd:testnet:acme-status';
const OTHER = 'did:cheqd:testnet:other-status';

describe('CheqdStatusListResolver and the verification relationship of the list key', () => {
  let crypto: NodeCryptoProvider;
  let login: AgentIdentity;
  let assert: AgentIdentity;
  let second: AgentIdentity;
  /** A key of another DID that signs a list in Acme's name. */
  let other: AgentIdentity;
  /** For each key, a revoked entry and the issuer's list for it, signed with that key. */
  const signedWith = new Map<AgentIdentity, { entry: CredentialStatus; list: StatusList2021Credential }>();
  let served: unknown;

  const fetchProvider = {
    async fetch() {
      return new Response(JSON.stringify(served));
    },
  } as unknown as FetchProvider;

  /** The method that publishes `key` multibase-only, as cheqd does, controlled by `controller` (default: the issuer). */
  const published = (key: AgentIdentity, controller = ISSUER) => methodOf(key, { controller, form: 'multibase' });

  /** The issuer's document: its keys published, the relationships as given. */
  const documentWith = (relationships: Record<string, unknown>): DIDDocument =>
    ({ id: ISSUER, verificationMethod: [published(login), published(assert), published(second)], ...relationships }) as DIDDocument;

  const listResolverFor = (document: DIDDocument) =>
    new CheqdStatusListResolver({
      fetchProvider,
      didResolver: { resolve: async (did) => (did === ISSUER ? document : null) },
      cryptoProvider: crypto,
      expectedIssuerDid: ISSUER,
      decompressor: statusListGzipCodec,
      cacheTtlMs: 0,
    });

  const issuerDocument = () => documentWith({ authentication: [login.kid], assertionMethod: [assert.kid] });

  beforeAll(async () => {
    crypto = createRealCryptoProvider();
    login = await keyOf(ISSUER, 'login-1');
    assert = await keyOf(ISSUER, 'key-1');
    second = await keyOf(ISSUER, 'key-2');
    // Its id is under another DID, and it signs its list as the issuer.
    other = { ...(await keyOf(OTHER, 'key-1')), did: ISSUER };
    for (const key of [login, assert, second, other]) {
      const setup = createRealStatusListManager(crypto, key, { statusListBaseUrl: 'https://status.example' });
      const entry = await setup.manager.allocateStatusEntry('revocation');
      await setup.manager.updateStatus(entry, true);
      signedWith.set(key, { entry, list: (await setup.storage.getStatusList(entry.statusListCredential))! });
    }
  });

  beforeEach(() => {
    served = undefined;
  });

  /** Serve the list signed with `key`, its proof changed by `proof`, and check its revoked entry. */
  const check = (document: DIDDocument, key: AgentIdentity, proof = (p: Record<string, unknown>) => p) => {
    const { entry, list } = signedWith.get(key)!;
    served = { ...list, proof: proof(list.proof as Record<string, unknown>) };
    return listResolverFor(document).checkStatus(entry);
  };
  const unnamed = ({ verificationMethod: _method, ...proof }: Record<string, unknown>) => proof;
  const emptied = (proof: Record<string, unknown>) => ({ ...proof, verificationMethod: '' });
  // A proof that names its key is refused by that name; one that names none, by the first entry alone.
  const refusalFor = (proof: unknown) => proof === undefined
    ? new RegExp(`^Verification method "[^"]+" not found under assertionMethod of "${ISSUER}"$`)
    : `Status list proof verificationMethod is absent, and assertionMethod of "${ISSUER}" has no usable first entry`;

  it('reads a list signed with the key the issuer lists under assertionMethod', async () => {
    expect(await check(issuerDocument(), assert)).toBe(true);
  });

  it("rejects a list when the issuer's document lists the key but is over 1 MiB", async () => {
    const padded = { ...issuerDocument(), padding: 'x'.repeat(1_048_576) } as DIDDocument;
    await expect(check(padded, assert)).rejects.toThrow(`Could not resolve issuer DID ${ISSUER}`);
  });

  it('rejects a list signed with the key the issuer lists only under authentication', async () => {
    await expect(check(issuerDocument(), login)).rejects.toThrow(
      `Verification method "${login.kid}" not found under assertionMethod of "${ISSUER}"`,
    );
  });

  it('tries only assertionMethod keys when the proof names no verification method', async () => {
    expect(await check(issuerDocument(), assert, unnamed)).toBe(true);
    await expect(check(issuerDocument(), login, unnamed)).rejects.toThrow(/signature verification FAILED/);
  });

  it('checks a proof that names no verification method with the first assertionMethod key alone', async () => {
    const document = documentWith({ assertionMethod: [assert.kid, second.kid] });
    expect(await check(document, assert, unnamed)).toBe(true);
    await expect(check(document, second, unnamed)).rejects.toThrow(/signature verification FAILED/);
    expect(await check(document, second)).toBe(true);
  });

  it('refuses a proof whose verification method is empty, as one that names no usable key, whatever the issuer lists', async () => {
    // The first entry under assertionMethod is the key that signed: an empty name is not read as no name.
    for (const document of [documentWith({ assertionMethod: [assert.kid, second.kid] }), issuerDocument()]) {
      await expect(check(document, assert, emptied)).rejects.toThrow(
        new Error('Status list proof verificationMethod "" is not a DID URL'),
      );
    }
  });

  it('does not skip a dangling or malformed first assertion entry for an unnamed proof', async () => {
    for (const entry of ['#gone', null, { id: '#bad' }]) {
      const document = documentWith({ assertionMethod: [entry, assert.kid] });
      await expect(check(document, assert, unnamed)).rejects.toThrow(refusalFor(unnamed));
      expect(await check(document, assert)).toBe(true);
    }
  });

  it('rejects a list whose proof states another purpose, and reads one that states none', async () => {
    const restated = (proof: Record<string, unknown>) => ({ ...proof, proofPurpose: 'authentication' });
    await expect(check(issuerDocument(), assert, restated)).rejects.toThrow(
      'Proof purpose "authentication" is not assertionMethod',
    );
    const unstated = ({ proofPurpose: _purpose, ...proof }: Record<string, unknown>) => proof;
    expect(await check(issuerDocument(), assert, unstated)).toBe(true);
  });

  it('names a stated purpose that is not a string by its JSON type, and quotes at most 64 characters of one', async () => {
    const stated: [unknown, string][] = [
      [['assertionMethod'], 'of type array'],
      [[], 'of type array'],
      [{ purpose: 'assertionMethod' }, 'of type object'],
      [JSON.parse('{"toString":"assertionMethod"}'), 'of type object'],
      ['x'.repeat(100_000), `"${'x'.repeat(64)}"...`],
    ];
    for (const [proofPurpose, named] of stated) {
      await expect(check(issuerDocument(), assert, (proof) => ({ ...proof, proofPurpose }))).rejects.toThrow(
        new Error(`Proof purpose ${named} is not assertionMethod`),
      );
    }
  });

  it('rejects a list whose listed method carries no key it can read, without a signature check', async () => {
    const keyless = { id: `${ISSUER}#key-3`, type: 'Ed25519VerificationKey2020', controller: ISSUER };
    const named = (proof: Record<string, unknown>) => ({ ...proof, verificationMethod: keyless.id });
    const verify = vi.spyOn(crypto, 'verify');
    try {
      for (const proof of [named, unnamed]) {
        await expect(check(documentWith({ assertionMethod: [keyless] }), assert, proof)).rejects.toThrow(
          'Status list signature verification FAILED against the issuer DID document',
        );
      }
      expect(verify).not.toHaveBeenCalled();
    } finally {
      verify.mockRestore();
    }
  });

  it("rejects a list when the resolver returns another DID's document, whatever it lists, saying so of a key it lists as the issuer's", async () => {
    // The other DID's own document, its key under its own DID and controlled by it: only the
    // document's id tells it from a document of the issuer.
    const othersOwn = { id: OTHER, verificationMethod: [published(other, OTHER)], assertionMethod: [other.kid] } as DIDDocument;
    for (const proof of [undefined, unnamed]) await expect(check(othersOwn, other, proof)).rejects.toThrow(refusalFor(proof));
    const listingIssuers = { id: OTHER, verificationMethod: [published(assert)], assertionMethod: [assert.kid] } as DIDDocument;
    for (const proof of [undefined, unnamed]) {
      await expect(check(listingIssuers, assert, proof)).rejects.toThrow(new Error(anotherDidReason(assert.kid, "document's id", { did: ISSUER, other: OTHER })));
    }
  });

  it('rejects every list when the issuer lists no key under assertionMethod', async () => {
    const document = documentWith({ authentication: [login.kid, assert.kid] });
    for (const proof of [undefined, unnamed]) await expect(check(document, assert, proof)).rejects.toThrow(refusalFor(proof));
  });

  it('quotes at most 64 characters of the verification method a proof names, and resolves nothing for one over 4,096', async () => {
    const verificationMethod = `${ISSUER}#${'k'.repeat(1_000)}`;
    await expect(check(issuerDocument(), assert, (proof) => ({ ...proof, verificationMethod }))).rejects.toThrow(
      new Error(
        `Verification method "${verificationMethod.slice(0, 64)}"... not found under assertionMethod of "${ISSUER}"`,
      ),
    );
    const over = `${ISSUER}#${'k'.repeat(100_000)}`;
    await expect(check(issuerDocument(), assert, (proof) => ({ ...proof, verificationMethod: over }))).rejects.toThrow(
      new Error(`Could not resolve issuer DID ${ISSUER}`),
    );
  });

  it('refuses a proof whose verification method is not a string, naming its JSON type, never converting it', async () => {
    const named: [unknown, string][] = [
      [JSON.parse(`{"toString":"${login.kid}"}`), 'object'],
      [[assert.kid], 'array'],
      [5, 'number'],
      [null, 'null'],
    ];
    for (const [verificationMethod, type] of named) {
      await expect(check(issuerDocument(), assert, (proof) => ({ ...proof, verificationMethod }))).rejects.toThrow(
        new Error(`Status list proof verificationMethod of type ${type} is not a DID URL`),
      );
    }
  });

  it('rejects a list signed with a key the issuer lists under assertionMethod that another DID controls, saying so', async () => {
    const document = { id: ISSUER, verificationMethod: [published(login), published(assert, OTHER)], assertionMethod: [assert.kid] };
    for (const proof of [undefined, unnamed]) {
      await expect(check(document as DIDDocument, assert, proof)).rejects.toThrow(new Error(anotherDidReason(assert.kid, 'controller', { did: ISSUER, other: OTHER })));
    }
  });
});
