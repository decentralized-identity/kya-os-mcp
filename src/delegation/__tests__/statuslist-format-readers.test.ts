/**
 * What a `StatusList2021Manager` issues with `format: 'BitstringStatusList'`, a
 * `BitstringStatusListCredential` that states `validFrom`, `validUntil` and `ttl`, with
 * `BitstringStatusListEntry` entries, is read by the status-list readers of the delegation and card
 * paths: the shared acceptance and validity rules, the manager as the delegation verifier's
 * resolver, and the card revocation checker with the list's Data Integrity proof verified. Each
 * reads the entry clear, and set once it is revoked. `RuntimeFetchProvider.fetchStatusList`, which
 * no reader here calls, answers a `StatusList2021Credential` alone, as its type says.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createRealSignatureVerifier } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { BIT_SET } from '../../__tests__/utils/refusal-coding.js';
import { PUBLIC_ADDRESS } from '../../__tests__/utils/runtime-network.js';
import { statusListIssuer, type StatusListIssuerSetup } from '../../__tests__/utils/status-list-manager.js';
import { DelegationCredentialStatusSchema } from '../../card/delegation.js';
import { ed25519SignerFromJwk } from '../../card/proof/signer.js';
import { createRevocationChecker } from '../../card/revocation.js';
import { createStatusListProofVerifier, signStatusListCredential } from '../../card/status-list-proof.js';
import type { AgentIdentity } from '../../providers/base.js';
import { RuntimeFetchProvider } from '../../providers/runtime-fetch.js';
import type { CredentialStatus, Proof } from '../../types/protocol.js';
import { acceptStatusList, statusListExpectationFor } from '../../utils/statuslist-acceptance.js';
import { acceptStatusListValidity } from '../../utils/statuslist-validity.js';
import type { VCSigningFunction } from '../vc-issuer.js';
import { DelegationCredentialVerifier, type DIDResolver } from '../vc-verifier.js';

const DAY_MS = 24 * 60 * 60 * 1000;
const TERMS = { format: 'BitstringStatusList', validityPeriodMs: 7 * DAY_MS, ttl: 300_000 } as const;
const crypto = new NodeCryptoProvider();

afterEach(() => {
  vi.unstubAllGlobals();
});

/** A resolver of `issuer`'s DID document alone, which lists its key under `assertionMethod`. */
const documentsOf = (issuer: AgentIdentity): DIDResolver => ({
  resolve: async (did) => (did === issuer.did ? issuerDidDocument(methodOf(issuer)) : null),
});

/** An issuer of Bitstring Status List lists with one entry allocated, and the list as its store serves it. */
async function issued(parts: Parameters<typeof statusListIssuer>[1] = {}) {
  const setup = await statusListIssuer(TERMS, parts);
  const entry = await setup.manager.allocateStatusEntry('revocation');
  const served = async (url: string) => Response.json(await setup.storage.getStatusList(url));
  return { ...setup, entry, served };
}

/** `read` before and after `entry` is revoked. */
async function clearThenSet<T>({ manager }: StatusListIssuerSetup, entry: CredentialStatus, read: () => Promise<T>): Promise<[T, T]> {
  const clear = await read();
  await manager.updateStatus(entry, true);
  return [clear, await read()];
}

describe('a BitstringStatusListCredential the manager issues', () => {
  it('passes the shared acceptance rule for its entry, and the validity rule until its validUntil', async () => {
    const { storage, issuer, entry } = await issued();
    const list = await storage.getStatusList(entry.statusListCredential);
    expect(acceptStatusList(list, statusListExpectationFor(entry, { credentialIssuer: issuer.did }))).toEqual({ valid: true });
    expect(acceptStatusListValidity(list, Date.now())).toEqual({ valid: true });
    expect(acceptStatusListValidity(list, Date.now() + 8 * DAY_MS)).toEqual({
      valid: false,
      reason: `status list expired at "${String(list!.validUntil)}" (its validUntil)`,
    });
  });

  it('gives entries a card delegation credential may state, which a StatusList2021Entry is not', async () => {
    const { entry } = await issued();
    expect(DelegationCredentialStatusSchema.safeParse(entry).success).toBe(true);
    const legacy = await (await statusListIssuer()).manager.allocateStatusEntry('revocation');
    expect(DelegationCredentialStatusSchema.safeParse(legacy).success).toBe(false);
  });

  it('is read by the delegation verifier through the manager', async () => {
    const issuer = await keyOf('did:web:root.example', 'key');
    const setup = await issued({ issuer });
    const verifier = new DelegationCredentialVerifier({
      didResolver: documentsOf(issuer),
      signatureVerifier: createRealSignatureVerifier(crypto),
      statusListResolver: setup.manager,
    });
    const credential = await signedCredential(issuer, { record: delegationRecord(issuer.did), credentialStatus: setup.entry });
    const [clear, set] = await clearThenSet(setup, setup.entry, () => verifier.verifyDelegationCredential(credential, { skipCache: true }));
    expect(clear).toMatchObject({ valid: true });
    expect(set).toMatchObject({ valid: false, statusOutcome: 'revoked' });
  });

  it('is read by the card revocation checker, its eddsa-jcs-2022 proof verified', async () => {
    const issuer = await keyOf('did:web:status.example', 'status-1');
    const base64url = (base64: string) => Buffer.from(base64, 'base64').toString('base64url');
    const signer = await ed25519SignerFromJwk({
      did: issuer.did,
      kid: issuer.kid,
      privateJwk: { kty: 'OKP', crv: 'Ed25519', x: base64url(issuer.publicKey), d: base64url(issuer.privateKey) },
    });
    // The manager hands its signing function the list as canonical JSON, which is the list itself.
    const sign: VCSigningFunction = async (canonicalList) =>
      (await signStatusListCredential(JSON.parse(canonicalList) as Record<string, unknown>, signer)).proof as unknown as Proof;
    const setup = await issued({ issuer, sign });
    const list = await setup.storage.getStatusList(setup.entry.statusListCredential);
    expect(list!.proof).toMatchObject({ type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', proofPurpose: 'assertionMethod' });

    const check = createRevocationChecker({
      fetch: setup.served as never,
      verifyStatusList: createStatusListProofVerifier({ didResolver: documentsOf(issuer) }),
    });
    const [clear, set] = await clearThenSet(setup, setup.entry, () => check(setup.entry as never, { credentialIssuer: issuer.did }));
    expect(clear).toEqual({ revoked: false, fresh: true });
    expect(set).toEqual({ revoked: true, fresh: true, ...BIT_SET });
  });

  it('is answered as null by RuntimeFetchProvider.fetchStatusList, which answers a StatusList2021Credential alone as on 1.25.0', async () => {
    const answered = async (setup: StatusListIssuerSetup) => {
      const entry = await setup.manager.allocateStatusEntry('revocation');
      const list = await setup.storage.getStatusList(entry.statusListCredential);
      const provider = new RuntimeFetchProvider({
        lookup: async () => [PUBLIC_ADDRESS],
        transport: async () => ({ status: 200, headers: { get: () => null }, text: async () => JSON.stringify(list) }),
      });
      return { list, answer: await provider.fetchStatusList(entry.statusListCredential) };
    };
    expect((await answered(await issued())).answer).toBeNull();
    const control = await answered(await statusListIssuer());
    expect(control.answer).toEqual(control.list);
    expect(control.answer).toMatchObject({ type: ['VerifiableCredential', 'StatusList2021Credential'] });
  });
});
