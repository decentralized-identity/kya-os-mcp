/**
 * The verifier waits on two more dependencies the host supplies besides its DID resolver: a custom
 * `StatusListResolver` and an injected `resolveDelegationChain`. Each gets the deadline the DID
 * resolver has, 5 seconds, and a call that has not answered by then is refused: the status check as
 * `status_unresolvable`, the chain as one that could not be resolved. Neither waits on, and neither
 * throws. Each dependency here hangs on a promise that never settles; the clock is faked, the keys
 * and signatures are real.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createRealSignatureVerifier } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import type { AgentIdentity } from '../../providers/base.js';
import type { CredentialStatus, DelegationCredential } from '../../types/protocol.js';
import { validateDelegationChain } from '../chain-enforcement.js';
import { DID_RESOLUTION_TIMEOUT_MS } from '../did-resource-limits.js';
import { DelegationCredentialVerifier } from '../vc-verifier.js';

const SERVER = 'did:web:server.example';
const STATUS: CredentialStatus = {
  id: 'https://status.example/1#7',
  type: 'BitstringStatusListEntry',
  statusPurpose: 'revocation',
  statusListIndex: '7',
  statusListCredential: 'https://status.example/1',
};
const never = <T>(): Promise<T> => new Promise<T>(() => undefined);

let issuer: AgentIdentity;
beforeAll(async () => {
  issuer = await keyOf('did:web:root.example', 'key');
});
afterEach(() => {
  vi.useRealTimers();
});

/** `work`'s result once it settles, read without waiting on it: `undefined` while it is pending. */
function watch<T>(work: Promise<T>): { readonly settled: T | undefined; readonly done: Promise<void> } {
  const state: { settled: T | undefined; done: Promise<void> } = { settled: undefined, done: Promise.resolve() };
  state.done = work.then((value) => {
    state.settled = value;
  });
  return state;
}

describe('a status list resolver that never answers', () => {
  it('is refused as status_unresolvable at 5,000 ms, and no sooner', async () => {
    expect(DID_RESOLUTION_TIMEOUT_MS).toBe(5_000);
    const credential = await signedCredential(issuer, { credentialStatus: STATUS });
    vi.useFakeTimers();
    let asked!: () => void;
    const reached = new Promise<void>((resolve) => {
      asked = resolve;
    });
    const verifier = new DelegationCredentialVerifier({
      didResolver: { resolve: async (did) => (did === issuer.did ? issuerDidDocument(methodOf(issuer)) : null) },
      signatureVerifier: createRealSignatureVerifier(new NodeCryptoProvider()),
      statusListResolver: {
        checkStatus: () => {
          asked();
          return never<boolean>();
        },
      },
    });
    const verdict = watch(verifier.verifyDelegationCredential(credential, { skipCache: true }));
    await reached;
    await vi.advanceTimersByTimeAsync(DID_RESOLUTION_TIMEOUT_MS - 1);
    expect(verdict.settled).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    await verdict.done;
    expect(verdict.settled).toMatchObject({
      valid: false,
      stage: 'status',
      statusOutcome: 'status_unresolvable',
      reason: 'Status check error: the status list resolver did not answer within 5 seconds',
    });
    expect(vi.getTimerCount()).toBe(0);
  });

  it('leaves no timer behind when the resolver answers or throws at once', async () => {
    const credential = await signedCredential(issuer, { credentialStatus: STATUS });
    vi.useFakeTimers();
    const answers: (() => Promise<boolean>)[] = [
      async () => false,
      async () => {
        throw new Error('list unreachable');
      },
      () => {
        throw new Error('thrown before any promise');
      },
    ];
    const reasons: (string | undefined)[] = [];
    for (const checkStatus of answers) {
      const verifier = new DelegationCredentialVerifier({
        didResolver: { resolve: async () => issuerDidDocument(methodOf(issuer)) },
        signatureVerifier: createRealSignatureVerifier(new NodeCryptoProvider()),
        statusListResolver: { checkStatus },
      });
      reasons.push((await verifier.verifyDelegationCredential(credential, { skipCache: true })).reason);
      expect(vi.getTimerCount()).toBe(0);
    }
    expect(reasons).toEqual([
      undefined,
      'Status check error: list unreachable',
      'Status check error: thrown before any promise',
    ]);
  });
});

describe('a resolveDelegationChain that never answers', () => {
  const constraints = { scopes: ['orders:place'], audience: SERVER, notAfter: Math.floor(Date.now() / 1000) + 3600 };
  const validate = (leaf: DelegationCredential, resolveDelegationChain: () => Promise<DelegationCredential[]>) =>
    validateDelegationChain(leaf, {
      serverDid: SERVER,
      verifier: { verifyDelegationCredential: async () => ({ valid: true }) },
      resolveDelegationChain,
      statusListConfigured: false,
    });

  it('is refused as a chain that could not be resolved at 5,000 ms, and no sooner', async () => {
    const leaf = await signedCredential(issuer, {
      record: delegationRecord(issuer.did, { parentId: 'del-parent', constraints }),
    });
    vi.useFakeTimers();
    const verdict = watch(validate(leaf, never));
    await vi.advanceTimersByTimeAsync(DID_RESOLUTION_TIMEOUT_MS - 1);
    expect(verdict.settled).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    await verdict.done;
    expect(verdict.settled).toEqual({
      valid: false,
      reason: 'Failed to resolve delegation chain: the chain resolver did not answer within 5 seconds',
    });
    expect(vi.getTimerCount()).toBe(0);
  });

  it('leaves no timer behind when the resolver answers or throws at once', async () => {
    const leaf = await signedCredential(issuer, {
      record: delegationRecord(issuer.did, { parentId: 'del-parent', constraints }),
    });
    vi.useFakeTimers();
    expect(await validate(leaf, async () => [])).toMatchObject({ valid: false, reason: expect.stringMatching(/resolved chain is empty$/) });
    expect(vi.getTimerCount()).toBe(0);
    expect(await validate(leaf, () => { throw new Error('store offline'); })).toEqual({
      valid: false,
      reason: 'Failed to resolve delegation chain: store offline',
    });
    expect(vi.getTimerCount()).toBe(0);
  });
});
