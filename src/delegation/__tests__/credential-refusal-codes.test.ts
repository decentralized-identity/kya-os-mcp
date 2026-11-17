/**
 * Each refusal of a delegation credential carries a stable code and whether it is transient, beside
 * its reason, on the Data Integrity path and the VC-JWT path alike: an adopter branches on the code
 * and retries only a transient one, whatever the reason's wording. Every case goes through the
 * public `DelegationCredentialVerifier`, with real Ed25519 keys, as an adopter's would.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import {
  DelegationCredentialVerifier,
  isTransientRefusal,
  type DelegationCredential,
  type DelegationVCVerificationResult,
  type DIDDocument,
  type DIDResolver,
  type DidResolutionFailureCause,
  type RefusalCode,
  type SignatureVerificationFunction,
  type StatusListResolver,
} from '../../index.js';
import { createRealCryptoProvider, createRealSignatureVerifier } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { ACME, OTHER, acmeDocument, documentOf, keylessMethod } from '../../__tests__/utils/did-documents.js';
import {
  credentialJwt,
  credentialNaming,
  delegationRecord,
  jwtClaiming,
  keyOf,
  resignedCredential,
  signedCredential,
  signedJwt,
} from '../../__tests__/utils/delegation-credentials.js';
import type { AgentIdentity } from '../../providers/base.js';
import type { CredentialStatus, DelegationRecord } from '../../types/protocol.js';

const LIST = 'https://status.example/list';
const credentialStatus: CredentialStatus = {
  id: `${LIST}#0`, type: 'StatusList2021Entry', statusPurpose: 'revocation', statusListIndex: '0', statusListCredential: LIST,
};
const HOUR = 3600;
const now = (): number => Math.floor(Date.now() / 1000);
/** A dependency that never answers. */
const never = <T>(): Promise<T> => new Promise<T>(() => undefined);

let login: AgentIdentity;
let assert: AgentIdentity;
let stray: AgentIdentity;

beforeAll(async () => {
  login = await keyOf(ACME, 'login-1');
  assert = await keyOf(ACME, 'assert-1');
  stray = await keyOf(ACME, 'stray-1');
});

/** Acme's document, from a resolver that knows no other DID. */
const acme: DIDResolver = { resolve: async (did) => (did === ACME ? acmeDocument(login, assert) : null) };

/** A resolver that finds nothing for any DID and reports `cause` as the reason why. */
const failingWith = (cause: DidResolutionFailureCause): DIDResolver => ({
  resolve: async () => null,
  lastFailure: () => ({ cause, detail: `the resolver says ${cause}` }),
});

/** What a verifier is built with in a case: Acme's resolver and real signatures unless it says otherwise. */
interface Setup {
  didResolver?: DIDResolver | null;
  signatureVerifier?: SignatureVerificationFunction | null;
  statusListResolver?: StatusListResolver;
}

function verifier({ didResolver = acme, signatureVerifier, statusListResolver }: Setup = {}): DelegationCredentialVerifier {
  return new DelegationCredentialVerifier({
    ...(didResolver === null ? {} : { didResolver }),
    ...(signatureVerifier === null ? {} : { signatureVerifier: signatureVerifier ?? createRealSignatureVerifier(createRealCryptoProvider()) }),
    ...(statusListResolver ? { statusListResolver } : {}),
    dependencyTimeoutMs: 50,
  });
}

/** A delegation by Acme, with `overrides`. */
const record = (overrides: Partial<DelegationRecord> = {}): DelegationRecord => delegationRecord(ACME, overrides);

/** Acme's credential, signed with its assertion key, for `overrides`. */
const credential = (overrides: Partial<DelegationRecord> = {}, status?: CredentialStatus): Promise<DelegationCredential> =>
  signedCredential(assert, { record: record(overrides), ...(status ? { credentialStatus: status } : {}) });

/** `vc` with its proof changed by `change`. */
const withProof = (vc: DelegationCredential, change: Record<string, unknown>): DelegationCredential =>
  ({ ...vc, proof: { ...vc.proof, ...change } }) as DelegationCredential;

/** The case's result, through the Data Integrity path. */
async function embedded(vc: DelegationCredential | Promise<DelegationCredential>, setup?: Setup): Promise<DelegationVCVerificationResult> {
  return verifier(setup).verifyDelegationCredential(await vc, { skipCache: true });
}

/** The case's result, through the VC-JWT path. */
async function jwt(token: string | Promise<string>, setup?: Setup): Promise<DelegationVCVerificationResult> {
  return verifier(setup).verifyDelegationJwt(await token, { skipCache: true });
}

/** Expect `result` refused with `code`, transient exactly when the code is. */
function expectRefused(result: DelegationVCVerificationResult, code: RefusalCode, transient: boolean): void {
  expect({ valid: result.valid, code: result.code, transient: result.transient }, result.reason).toEqual({ valid: false, code, transient });
  expect(isTransientRefusal(code)).toBe(transient);
}

describe('a Data Integrity credential refused at the basic stage', () => {
  it.each<[string, () => Promise<DelegationCredential>, RefusalCode]>([
    ['one that fails the schema', async () => ({ ...(await credential()), '@context': [] }) as unknown as DelegationCredential, 'delegation_malformed'],
    ['one whose issuer is not a URL', () => credentialNaming(assert, 'acme'), 'delegation_malformed'],
    ['one past its notAfter', () => credential({ constraints: { scopes: ['orders:place'], notAfter: now() - HOUR } }), 'delegation_expired'],
    ['one before its notBefore', () => credential({ constraints: { scopes: ['orders:place'], notBefore: now() + HOUR } }), 'delegation_not_yet_valid'],
    ['one whose delegation status is "revoked"', () => credential({ status: 'revoked' }), 'delegation_revoked'],
    ['one whose delegation status is "expired"', () => credential({ status: 'expired' }), 'delegation_expired'],
    [
      'one whose delegation states no status',
      async () =>
        resignedCredential(await credential(), (unsigned) => {
          const subject = (unsigned as unknown as DelegationCredential).credentialSubject;
          const { status: _status, ...statusless } = subject.delegation;
          return { ...unsigned, credentialSubject: { ...subject, delegation: statusless } };
        }, assert),
      'delegation_malformed',
    ],
    ['one whose delegation names no subject', () => credential({ subjectDid: '' }), 'delegation_malformed'],
    ['one with no proof', async () => ({ ...(await credential()), proof: undefined }) as DelegationCredential, 'delegation_malformed'],
    [
      'one whose subject carries a claim',
      async () => resignedCredential(await credential(), (vc) => ({ ...vc, credentialSubject: { ...(vc.credentialSubject as object), role: 'admin' } }), assert),
      'delegation_malformed',
    ],
  ])('%s', async (_name, make, code) => {
    const result = await embedded(make());
    expect(result.stage).toBe('basic');
    expectRefused(result, code, false);
  });
});

describe('a Data Integrity credential refused at the signature', () => {
  it.each<[string, () => Promise<DelegationCredential>, Setup, RefusalCode, boolean]>([
    ['with no DID resolver configured', () => credential(), { didResolver: null }, 'configuration_error', false],
    ['with no signature verifier configured', () => credential(), { signatureVerifier: null }, 'configuration_error', false],
    ['whose proof type no verifier checks', async () => withProof(await credential(), { type: 'RsaSignature2018' }), {}, 'invalid_proof', false],
    ['whose proof states another purpose', async () => withProof(await credential(), { proofPurpose: 'authentication' }), {}, 'key_not_authorized', false],
    ['whose proof names no key', async () => withProof(await credential(), { verificationMethod: undefined }), {}, 'key_not_authorized', false],
    ['signed with a key listed only under authentication', () => signedCredential(login, { record: record() }), {}, 'key_not_authorized', false],
    ['whose signature does not hold under the key it names', () => signedCredential(stray, { record: record(), kid: assert.kid }), {}, 'invalid_proof', false],
    [
      'whose signature verifier refuses it',
      () => credential(),
      { signatureVerifier: async () => ({ valid: false, reason: 'no' }) },
      'invalid_proof',
      false,
    ],
    [
      'whose signature verifier refuses it with a code of the catalog',
      () => credential(),
      { signatureVerifier: async () => ({ valid: false, reason: 'no', code: 'did_invalid' }) },
      'did_invalid',
      false,
    ],
    [
      'whose signature verifier refuses it with a code outside the catalog',
      () => credential(),
      { signatureVerifier: async () => ({ valid: false, reason: 'no', code: 'nope' as never }) },
      'invalid_proof',
      false,
    ],
    ['whose signature verifier answers what is not a verdict', () => credential(), { signatureVerifier: async () => ({ valid: 'yes' }) as never }, 'runtime_error', true],
    [
      'whose signature verifier throws',
      () => credential(),
      { signatureVerifier: async () => { throw new Error('verifier down'); } },
      'runtime_error',
      true,
    ],
    ['whose signature verifier never answers', () => credential(), { signatureVerifier: never }, 'deadline_exceeded', true],
  ])('%s', async (_name, make, setup, code, transient) => {
    const result = await embedded(make(), setup);
    expect(result.stage).toBe('signature');
    expectRefused(result, code, transient);
  });
});

/** The issuer's DID could not be resolved, on both paths, each case with the code it is refused with. */
const UNRESOLVED: [string, DIDResolver, RefusalCode, boolean][] = [
  ['a resolver that finds nothing and gives no cause', { resolve: async () => null }, 'did_unavailable', true],
  ['a resolver that throws', { resolve: async () => { throw new Error('registry down'); } }, 'did_unavailable', true],
  ['a resolver that never answers', { resolve: never }, 'deadline_exceeded', true],
  ['a resolver that reports host_refused', failingWith('host_refused'), 'host_refused', false],
  ['a resolver that reports deadline_exceeded', failingWith('deadline_exceeded'), 'deadline_exceeded', true],
  ['a resolver that reports unavailable', failingWith('unavailable'), 'did_unavailable', true],
  ['a resolver that reports invalid_document', failingWith('invalid_document'), 'did_invalid', false],
  [
    'a resolver whose document is not plain data',
    { resolve: async () => ({ ...acmeDocument(login, assert), service: [() => 'x'] }) as unknown as DIDDocument },
    'did_invalid',
    false,
  ],
  [
    'a resolver whose method has no usable key',
    { resolve: async () => documentOf({ verificationMethod: [keylessMethod(`${ACME}#assert-1`)], assertionMethod: [`${ACME}#assert-1`] }) },
    'did_invalid',
    false,
  ],
];

describe.each<[string, (didResolver: DIDResolver) => Promise<DelegationVCVerificationResult>]>([
  ['Data Integrity', (didResolver) => embedded(credential(), { didResolver })],
  ['VC-JWT', (didResolver) => jwt(signedJwt(assert, { kid: assert.kid }), { didResolver })],
])("%s: a credential whose issuer's DID document is not had", (_path, verify) => {
  it.each(UNRESOLVED)('through %s', async (_name, didResolver, code, transient) => {
    const result = await verify(didResolver);
    expect(result.stage).toBe('signature');
    expectRefused(result, code, transient);
  });

  it('whose issuer DID is over its length limit, refused before any resolver is asked', async () => {
    const long = `did:web:${'a'.repeat(2_100)}.example`;
    const asked: string[] = [];
    const didResolver: DIDResolver = { resolve: async (did) => { asked.push(did); return null; } };
    const result = _path === 'VC-JWT'
      ? await jwt(jwtClaiming(assert, { iss: long }, long, assert.kid), { didResolver })
      : await embedded(credentialNaming(assert, long), { didResolver });
    expectRefused(result, 'did_invalid', false);
    expect(asked).toEqual([]);
  });
});

describe("a credential refused at its status", () => {
  const withStatus = (answer: () => Promise<boolean>): Setup => ({ statusListResolver: { checkStatus: answer } });

  it.each<[string, Setup, RefusalCode, boolean, string]>([
    ['whose status bit is set', withStatus(async () => true), 'delegation_revoked', false, 'revoked'],
    ['whose status list resolver throws', withStatus(async () => { throw new Error('list down'); }), 'status_unavailable', true, 'status_unresolvable'],
    ['whose status list resolver answers what is not a boolean', withStatus(async () => 'no' as never), 'status_unavailable', true, 'status_unresolvable'],
    ['whose status list resolver never answers', withStatus(never), 'deadline_exceeded', true, 'status_unresolvable'],
    ['with no status list resolver configured', {}, 'configuration_error', false, 'status_unresolvable'],
  ])('%s, on both paths, keeping its statusOutcome', async (_name, setup, code, transient, statusOutcome) => {
    for (const result of [
      await embedded(credential({}, credentialStatus), setup),
      await jwt(signedJwt(assert, { kid: assert.kid, credentialStatus }), setup),
    ]) {
      expect(result.stage).toBe('status');
      expect(result.statusOutcome).toBe(statusOutcome);
      expectRefused(result, code, transient);
    }
  });
});

describe('a VC-JWT refused', () => {
  const past = now() - HOUR;
  const future = now() + HOUR;

  it.each<[string, () => Promise<string>, RefusalCode]>([
    ['that does not parse', async () => 'not.a.jwt', 'delegation_malformed'],
    ['whose exp is past', async () => credentialJwt(await credential(), assert, { claims: { exp: past } }), 'delegation_expired'],
    ['whose nbf is ahead', async () => credentialJwt(await credential(), assert, { claims: { nbf: future } }), 'delegation_not_yet_valid'],
    ['whose exp is not a number', async () => credentialJwt(await credential(), assert, { claims: { exp: 'soon' } }), 'delegation_malformed'],
    ['whose iss is not a URL', () => jwtClaiming(assert, { iss: 'acme' }, ACME, assert.kid), 'delegation_malformed'],
    ['whose credential names another issuer than its iss', () => jwtClaiming(assert, { iss: ACME }, OTHER, assert.kid), 'delegation_malformed'],
    ['whose credential is expired', async () => credentialJwt(await credential({ constraints: { scopes: ['orders:place'], notAfter: past } }), assert), 'delegation_expired'],
  ])('at the basic stage, %s', async (_name, make, code) => {
    const result = await jwt(make());
    expect(result.stage).toBe('basic');
    expectRefused(result, code, false);
  });

  it.each<[string, () => Promise<string>, Setup, RefusalCode]>([
    ['with no DID resolver configured', () => signedJwt(assert, { kid: assert.kid }), { didResolver: null }, 'configuration_error'],
    ['whose kid is listed only under authentication', () => signedJwt(login, { kid: login.kid }), {}, 'key_not_authorized'],
    ['whose envelope signature does not hold under its kid', () => signedJwt(stray, { kid: assert.kid }), {}, 'invalid_proof'],
  ])('at the signature, %s', async (_name, make, setup, code) => {
    const result = await jwt(make(), setup);
    expect(result.stage).toBe('signature');
    expectRefused(result, code, false);
  });
});

describe('a credential that verifies', () => {
  it('carries no code', async () => {
    for (const result of [await embedded(credential()), await jwt(signedJwt(assert, { kid: assert.kid }))]) {
      expect(result).toMatchObject({ valid: true });
      expect(result).not.toHaveProperty('code');
      expect(result).not.toHaveProperty('transient');
    }
  });
});
