/**
 * The `signed-proof/request-binding-*` and `delegation-chain/parent-digest-*` vectors (suite 1.13.0)
 * each have to turn on one rule and nothing else: of how a verifier holds a holder's request proof
 * to the delegation its call presented (SPEC.md §7.8), and of a base profile re-delegation's
 * commitment to its parent (SPEC.md §6.2). A negative one that failed for a broken signature would
 * pass an implementation that never reads the statement, so each is held here to the reason the
 * reference refuses it for, and the committed files to what their generator writes.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { decodeProtectedHeader } from 'jose';
import { describe, expect, it } from 'vitest';
import {
  DELEGATION_HEADER_PARAMETER,
  MemoryNonceCacheProvider,
  ProofVerifier,
  delegationCredentialDigest,
  delegationRefOf,
  generateDidKeyFromBase64,
  verifyDelegatedCallProof,
  type DetachedProof,
  type ReceivedCredential,
  type RequestBindingMode,
} from '../../src/index.js';
import { ClockProvider, FetchProvider } from '../../src/providers/base.js';
import type { Ed25519JWK } from '../../src/utils/crypto-service.js';
import { VECTORS_DIR, loadVectors } from '../loader.js';
import { vectorFileText } from '../numbers-as-written.js';
import { parentCommitmentVectorFile } from '../parent-commitment-vectors.js';
import { ReferenceConformanceAdapter } from '../reference-adapter.js';
import { requestBindingVectorFile } from '../request-binding-vectors.js';
import type { ConformanceVector, DelegationChainInput, SignedProofInput } from '../types.js';
import { type Credential, crypto, hash, issuerSigned } from './helpers/delegation-vectors.js';

const vectors = loadVectors();
const named = (prefix: string) => (name: string): ConformanceVector => {
  const vector = vectors.find(({ id }) => id === `${prefix}${name}`);
  if (vector === undefined) throw new Error(`missing vector ${prefix}${name}`);
  return vector;
};
const requestVector = named('signed-proof/request-binding-');
const chainVector = named('delegation-chain/parent-digest-');
const inputOf = (name: string) => requestVector(name).input as SignedProofInput;
const presentedOf = (name: string) => inputOf(name).expected!.presentedDelegation as ReceivedCredential | null;
const headerOf = (name: string) => decodeProtectedHeader((inputOf(name).proof as DetachedProof).jws);

class PinnedClock extends ClockProvider {
  constructor(private readonly nowMs: number) {
    super();
  }
  now = (): number => this.nowMs;
  isWithinSkew = (timestampMs: number, skewSeconds: number): boolean => Math.abs(this.nowMs - timestampMs) <= skewSeconds * 1000;
  hasExpired = (expiresAt: number): boolean => this.nowMs > expiresAt;
  calculateExpiry = (ttlSeconds: number): number => this.nowMs + ttlSeconds * 1000;
  format = (timestamp: number): string => new Date(timestamp).toISOString();
}
class NoFetch extends FetchProvider {
  resolveDID = async (): Promise<null> => null;
  fetchStatusList = async (): Promise<null> => null;
  fetchDelegationChain = async (): Promise<never[]> => [];
  fetch = async (): Promise<Response> => new Response('not found', { status: 404 });
}
const verifierAt = (input: SignedProofInput): ProofVerifier =>
  new ProofVerifier({
    cryptoProvider: crypto,
    clockProvider: new PinnedClock(input.now * 1000),
    nonceCacheProvider: new MemoryNonceCacheProvider(),
    fetchProvider: new NoFetch(),
    timestampSkewSeconds: input.skewSeconds,
  });

/** How the reference holds the vector's proof to the delegation presented, under `mode` or the vector's own policy. */
function held(name: string, mode?: RequestBindingMode) {
  const input = inputOf(name);
  const policy = mode ?? input.expected!.requestBinding;
  return verifyDelegatedCallProof({
    proof: input.proof as DetachedProof,
    subjectDid: generateDidKeyFromBase64(Buffer.from(input.publicKeyJwk.x, 'base64url').toString('base64')),
    request: input.expected!.request as never,
    proofVerifier: verifierAt(input),
    presented: presentedOf(name),
    ...(policy === undefined ? {} : { mode: policy }),
    hash,
  });
}

/** Whether the proof verifies as a proof of its call, whatever it states of a delegation. */
async function verifiesAlone(name: string): Promise<boolean> {
  const input = inputOf(name);
  return (await verifierAt(input).verifyProof(input.proof as never, input.publicKeyJwk as Ed25519JWK, { request: input.expected!.request as never })).valid;
}

describe('the committed request-binding and parent-commitment vector files', () => {
  it.each([
    ['signed-proof-request-binding.json', requestBindingVectorFile],
    ['delegation-chain-parent-commitment.json', parentCommitmentVectorFile],
  ] as const)('%s is what its generator writes, on every run', async (name, generate) => {
    const committed = readFileSync(join(VECTORS_DIR, name), 'utf8').replace(/\r\n/g, '\n');
    expect(vectorFileText(await generate(), name, [])).toBe(committed);
  });
});

describe('signed-proof/request-binding-* vectors', () => {
  it('named: the header states the digest of the credential presented, after the alg and kid the generator writes', async () => {
    const presented = presentedOf('named')!;
    expect(Object.keys(headerOf('named'))).toEqual(['alg', 'kid', DELEGATION_HEADER_PARAMETER]);
    expect(headerOf('named')[DELEGATION_HEADER_PARAMETER]).toBe(await delegationCredentialDigest(presented, hash));
    expect(await issuerSigned(presented as Credential)).toBe(true);
    expect(await held('named')).toMatchObject({ status: 'bound', named: true });
  });

  it('named-vc-jwt and reserialized: the form sent is what is named, and a copy that differs in nothing signed is the same credential', async () => {
    expect(typeof presentedOf('named-vc-jwt')).toBe('string');
    expect(await issuerSigned(presentedOf('named-vc-jwt') as Credential)).toBe(true);
    expect(headerOf('named-vc-jwt')[DELEGATION_HEADER_PARAMETER]).toBe(await delegationCredentialDigest(presentedOf('named-vc-jwt')!, hash));
    expect(await held('named-vc-jwt')).toMatchObject({ status: 'bound', named: true });

    expect(inputOf('reserialized').proof).toEqual(inputOf('named').proof);
    expect(presentedOf('reserialized')).not.toEqual(presentedOf('named'));
    expect(await held('reserialized')).toMatchObject({ status: 'bound', named: true });
  });

  it.each(['other-delegation', 'reissued-under-same-id', 'other-form'])(
    '%s: the proof that binds beside the credential it names is refused beside this one, for the statement alone',
    async (name) => {
      expect(inputOf(name).proof).toEqual(inputOf('named').proof);
      expect(await issuerSigned(presentedOf(name) as Credential)).toBe(true);
      expect(await verifiesAlone(name)).toBe(true);
      for (const mode of ['prefer', 'require'] as const) {
        expect(await held(name, mode)).toMatchObject({ status: 'unbound', cause: 'delegation_mismatch' });
      }
    },
  );

  it('reissued-under-same-id and other-form: the credential presented goes by every name the named one does', async () => {
    const named = presentedOf('named') as Exclude<Credential, string>;
    const reissued = presentedOf('reissued-under-same-id') as Exclude<Credential, string>;
    expect(reissued.id).toBe(named.id);
    expect(reissued.credentialSubject.delegation.id).toBe(named.credentialSubject.delegation.id);
    expect(reissued.credentialSubject.delegation.constraints.scopes).not.toEqual(named.credentialSubject.delegation.constraints.scopes);
    expect(presentedOf('other-form')).toBe(presentedOf('named-vc-jwt'));
  });

  it('none: a call that presents no delegation says so, and is bound under either policy', async () => {
    expect(headerOf('none')[DELEGATION_HEADER_PARAMETER]).toBe('none');
    expect(presentedOf('none')).toBeNull();
    for (const mode of ['prefer', 'require'] as const) expect(await held('none', mode)).toMatchObject({ status: 'bound', named: true });
  });

  it.each([
    ['none-beside-delegation', 'delegation_stated_none'],
    ['unnamed-beside-delegation', 'delegation_unnamed'],
    ['unnamed', 'delegation_unnamed'],
  ])('%s: refused by a verifier that requires naming, and taken unnamed by one that does not', async (name, cause) => {
    expect(inputOf(name).expected!.requestBinding).toBe('require');
    expect(await verifiesAlone(name)).toBe(true);
    expect(await held(name)).toMatchObject({ status: 'unbound', cause });
    expect(await held(name, 'prefer')).toMatchObject({ status: 'bound', named: false });
  });

  it('unnamed: the header states nothing, as a proof made before the parameter existed', () => {
    expect(Object.keys(headerOf('unnamed'))).toEqual(['alg', 'kid']);
    expect(headerOf('unnamed-beside-delegation')).toEqual(headerOf('unnamed'));
  });

  it.each(['statement-not-lowercase', 'statement-not-a-string'])('%s: a signed statement of neither form is refused as malformed', async (name) => {
    const digest = await delegationCredentialDigest(presentedOf(name)!, hash);
    const stated = headerOf(name)[DELEGATION_HEADER_PARAMETER];
    expect(stated).not.toBe(digest);
    expect(JSON.stringify(stated).toLowerCase()).toContain(digest);
    expect(await verifiesAlone(name)).toBe(true);
    for (const mode of ['prefer', 'require'] as const) {
      expect(await held(name, mode)).toMatchObject({ status: 'unbound', cause: 'delegation_statement_malformed' });
    }
  });

  it.each(['statement-altered', 'statement-stripped'])('%s: only the header differs from the proof that binds, and the signature no longer covers it', async (name) => {
    const [bound, changed] = [inputOf('named').proof as DetachedProof, inputOf(name).proof as DetachedProof];
    expect(changed.meta).toEqual(bound.meta);
    expect(changed.jws.split('.').slice(1)).toEqual(bound.jws.split('.').slice(1));
    expect(await verifiesAlone(name)).toBe(false);
    for (const mode of ['prefer', 'require'] as const) {
      expect(await held(name, mode)).toMatchObject({ status: 'unbound', cause: 'INVALID_JWS_SIGNATURE' });
    }
  });

  it('statement-altered: the header was rewritten to name the credential presented, which the holder never named', async () => {
    expect(headerOf('statement-altered')[DELEGATION_HEADER_PARAMETER]).toBe(await delegationCredentialDigest(presentedOf('statement-altered')!, hash));
    expect(headerOf('statement-stripped')).toEqual(headerOf('unnamed'));
  });

  it('statement-duplicated: the signed header holds the parameter twice, and the last, which is read, names another credential', async () => {
    const header = Buffer.from((inputOf('statement-duplicated').proof as DetachedProof).jws.split('.')[0]!, 'base64url').toString('utf8');
    const stated = [...header.matchAll(/"org\.kya-os\/delegation":"(sha256:[0-9a-f]{64})"/g)].map((match) => match[1]);
    expect(stated).toHaveLength(2);
    expect(stated[0]).toBe(await delegationCredentialDigest(presentedOf('statement-duplicated')!, hash));
    expect(stated[1]).toBe(await delegationCredentialDigest(presentedOf('other-delegation')!, hash));
    expect(await verifiesAlone('statement-duplicated')).toBe(true);
    expect(await held('statement-duplicated')).toMatchObject({ status: 'unbound', cause: 'delegation_mismatch' });
  });

  it('payload-names-another: the header names the credential presented, and the signed delegationRef another', async () => {
    const { meta } = inputOf('payload-names-another').proof as DetachedProof;
    expect(headerOf('payload-names-another')[DELEGATION_HEADER_PARAMETER]).toBe(await delegationCredentialDigest(presentedOf('payload-names-another')!, hash));
    expect(meta.delegationRef).toBe(await delegationRefOf(presentedOf('other-delegation'), hash));
    expect(meta.delegationRef).not.toBe(await delegationRefOf(presentedOf('payload-names-another'), hash));
    expect(await verifiesAlone('payload-names-another')).toBe(true);
    expect(await held('payload-names-another')).toMatchObject({ status: 'unbound', cause: 'delegation_mismatch' });
  });

  it('have the same verdict under either policy where they name none, and the verdict the reference adapter reaches', async () => {
    const adapter = new ReferenceConformanceAdapter();
    const binding = vectors.filter(({ id }) => id.startsWith('signed-proof/request-binding-'));
    expect(binding).toHaveLength(16);
    for (const vector of binding) {
      const name = vector.id.slice('signed-proof/request-binding-'.length);
      expect((await adapter.verifySignedProof(vector.input as SignedProofInput)).outcome, vector.id).toBe(vector.expected);
      if (inputOf(name).expected!.requestBinding !== undefined) continue;
      expect((await held(name, 'require')).status, vector.id).toBe((await held(name, 'prefer')).status);
    }
  });
});

describe('delegation-chain/parent-digest-* vectors', () => {
  const adapter = new ReferenceConformanceAdapter();
  const input = (name: string) => chainVector(name).input as DelegationChainInput;
  const verdict = (name: string) => adapter.verifyDelegationChain(input(name));
  const stated = (name: string) => (input(name).leaf as Exclude<Credential, string>).credentialSubject.delegation;

  it('committed: every credential is signed by its issuer, and the leaf states the digest of its parent', async () => {
    const [parent] = input('committed').ancestors as Credential[];
    expect(await issuerSigned(parent!)).toBe(true);
    expect(await issuerSigned(input('committed').leaf as Credential)).toBe(true);
    expect(stated('committed').parentCredentialDigest).toBe(await delegationCredentialDigest(parent!, hash));
    expect(await verdict('committed')).toEqual({ outcome: 'pass' });
  });

  it('reissued-parent: the same leaf, under a parent of the same id that verifies and still covers its scopes', async () => {
    const [parent] = input('committed').ancestors as Exclude<Credential, string>[];
    const [reissued] = input('reissued-parent').ancestors as Exclude<Credential, string>[];
    expect(input('reissued-parent').leaf).toEqual(input('committed').leaf);
    expect(reissued!.id).toBe(parent!.id);
    expect(await issuerSigned(reissued!)).toBe(true);
    const scopes = stated('committed').constraints.scopes ?? [];
    expect(scopes).not.toEqual([]);
    expect(reissued!.credentialSubject.delegation.constraints.scopes).toEqual(expect.arrayContaining(scopes));
    const refused = await verdict('reissued-parent');
    expect(refused.outcome).toBe('fail');
    expect(refused.detail).toMatch(/states a parentCredentialDigest that is not the digest of the parent/);
    // Without the commitment the same chain is accepted: the member is what refuses it.
    expect(await adapter.verifyDelegationChain({ ...input('absent'), ancestors: [reissued] })).toEqual({ outcome: 'pass' });
  });

  it('absent and null: a leaf that states none is held to none, and one that states null states one', async () => {
    expect(stated('absent')).not.toHaveProperty('parentCredentialDigest');
    expect(await verdict('absent')).toEqual({ outcome: 'pass' });
    expect(stated('null').parentCredentialDigest).toBeNull();
    expect(await issuerSigned(input('null').leaf as Credential)).toBe(true);
    expect((await verdict('null')).detail).toMatch(/states a parentCredentialDigest that is not the digest of the parent/);
  });

  it('on-root: a signed credential with no parent that states a parent digest is refused for stating it', async () => {
    expect(stated('on-root').parentId).toBeUndefined();
    expect(await issuerSigned(input('on-root').leaf as Credential)).toBe(true);
    const refused = await verdict('on-root');
    expect(refused.outcome).toBe('fail');
    expect(refused.detail).toMatch(/has no parent credential, so it states no parentCredentialDigest/);
  });
});
