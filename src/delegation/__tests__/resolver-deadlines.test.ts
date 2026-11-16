/**
 * The verifier waits on dependencies the host supplies: its DID resolver, a custom
 * `StatusListResolver`, a custom signature verifier, an injected `resolveDelegationChain` and a
 * `RevocationChecker`, and the built-in resolvers and `RuntimeFetchProvider` wait on a `fetch`.
 * Each gets one deadline, 5 seconds or the `dependencyTimeoutMs` the host gives that verifier or
 * resolver, and a call that has not answered by then is refused: the status check as
 * `status_unresolvable`, the signature as one that could not be verified, the chain as one that
 * could not be resolved, the revocation check as failed, a resolution as no document. None waits
 * on, and none throws. Each dependency here hangs on a promise that never settles; the clock is
 * faked, the keys and signatures are real. Every case runs under the default and a raised deadline.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createRealSignatureVerifier } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { DEADLINES, REFUSED_TIMEOUTS, settledAt, timeoutTypeError } from '../../__tests__/utils/deadlines.js';
import { delegationRecord, keyOf, signedCredential, signedJwt } from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { ProofVerifier } from '../../proof/verifier.js';
import type { AgentIdentity, FetchProvider } from '../../providers/base.js';
import { MemoryNonceCacheProvider } from '../../providers/memory.js';
import { RuntimeFetchProvider } from '../../providers/runtime-fetch.js';
import { SystemClockProvider } from '../../providers/system-clock.js';
import type { CredentialStatus, DelegationCredential } from '../../types/protocol.js';
import { validateDelegationChain, type ChainEnforcementDeps } from '../chain-enforcement.js';
import { DID_RESOLUTION_TIMEOUT_MS } from '../did-resource-limits.js';
import { createDidWebResolver, DidWebResolver } from '../did-web-resolver.js';
import { createDelegationVerifier, DelegationCredentialVerifier, type DIDResolver } from '../vc-verifier.js';

const SERVER = 'did:web:server.example';
const SLOW = 'did:web:slow.example';
const STATUS: CredentialStatus = {
  id: 'https://status.example/1#7',
  type: 'BitstringStatusListEntry',
  statusPurpose: 'revocation',
  statusListIndex: '7',
  statusListCredential: 'https://status.example/1',
};
const crypto = new NodeCryptoProvider();
const constraints = { scopes: ['orders:place'], audience: SERVER, notAfter: Math.floor(Date.now() / 1000) + 3600 };

let issuer: AgentIdentity;
let answering: DIDResolver;
beforeAll(async () => {
  issuer = await keyOf('did:web:root.example', 'key');
  answering = { resolve: async (did) => (did === issuer.did ? issuerDidDocument(methodOf(issuer)) : null) };
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

it('waits 5,000 ms by default', () => {
  expect(DID_RESOLUTION_TIMEOUT_MS).toBe(5_000);
});

describe.each(DEADLINES)('%s', (_label, option, ms, stated) => {
  describe('DelegationCredentialVerifier', () => {
    it('refuses a credential whose issuer DID its resolver has not resolved by the deadline', async () => {
      const credential = await signedCredential(issuer);
      const result = await settledAt(ms, (never) =>
        new DelegationCredentialVerifier({ didResolver: { resolve: never }, signatureVerifier: createRealSignatureVerifier(crypto), ...option })
          .verifyDelegationCredential(credential, { skipCache: true }));
      expect(result).toMatchObject({ valid: false, stage: 'signature', reason: 'Signature verification error: DID resolution deadline exceeded' });
    });

    it('gives a resolver passed with the call the same deadline', async () => {
      const credential = await signedCredential(issuer);
      const result = await settledAt(ms, (never) =>
        new DelegationCredentialVerifier({ didResolver: answering, signatureVerifier: createRealSignatureVerifier(crypto), ...option })
          .verifyDelegationCredential(credential, { didResolver: { resolve: never } }));
      expect(result).toMatchObject({ valid: false, stage: 'signature', reason: 'Signature verification error: DID resolution deadline exceeded' });
    });

    it('refuses a VC-JWT whose issuer DID its resolver has not resolved by the deadline', async () => {
      const jwt = await signedJwt(issuer);
      const result = await settledAt(ms, (never) =>
        createDelegationVerifier({ didResolver: { resolve: never }, ...option }).verifyDelegationJwt(jwt, { skipCache: true }));
      expect(result).toMatchObject({
        valid: false,
        stage: 'signature',
        reason: `Could not resolve issuer DID "${issuer.did}": DID resolution deadline exceeded`,
      });
    });

    it('refuses a signature its signature verifier has not answered for by the deadline', async () => {
      const credential = await signedCredential(issuer);
      const result = await settledAt(ms, (never) =>
        new DelegationCredentialVerifier({ didResolver: answering, signatureVerifier: never, ...option })
          .verifyDelegationCredential(credential, { skipCache: true }));
      expect(result).toMatchObject({
        valid: false,
        stage: 'signature',
        reason: `Signature verification error: the signature verifier did not answer within ${stated}`,
      });
    });

    it('refuses as status_unresolvable a status its resolver has not answered for by the deadline', async () => {
      const credential = await signedCredential(issuer, { credentialStatus: STATUS });
      const result = await settledAt(ms, (never) =>
        new DelegationCredentialVerifier({
          didResolver: answering,
          signatureVerifier: createRealSignatureVerifier(crypto),
          statusListResolver: { checkStatus: never },
          ...option,
        }).verifyDelegationCredential(credential, { skipCache: true }));
      expect(result).toMatchObject({
        valid: false,
        stage: 'status',
        statusOutcome: 'status_unresolvable',
        reason: `Status check error: the status list resolver did not answer within ${stated}`,
      });
    });

    it('leaves no timer behind when the status resolver answers or throws at once', async () => {
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
          didResolver: answering,
          signatureVerifier: createRealSignatureVerifier(crypto),
          statusListResolver: { checkStatus },
          ...option,
        });
        reasons.push((await verifier.verifyDelegationCredential(credential, { skipCache: true })).reason);
        expect(vi.getTimerCount()).toBe(0);
      }
      expect(reasons).toEqual([undefined, 'Status check error: list unreachable', 'Status check error: thrown before any promise']);
    });
  });

  describe('validateDelegationChain', () => {
    const validate = (leaf: DelegationCredential, deps: Partial<ChainEnforcementDeps>) =>
      validateDelegationChain(leaf, {
        serverDid: SERVER,
        verifier: { verifyDelegationCredential: async () => ({ valid: true }) },
        statusListConfigured: false,
        ...option,
        ...deps,
      });
    const child = () => signedCredential(issuer, { record: delegationRecord(issuer.did, { parentId: 'del-parent', constraints }) });

    it('refuses a chain its resolver has not returned by the deadline as one that could not be resolved', async () => {
      const leaf = await child();
      expect(await settledAt(ms, (never) => validate(leaf, { resolveDelegationChain: never }))).toEqual({
        valid: false,
        reason: `Failed to resolve delegation chain: the chain resolver did not answer within ${stated}`,
      });
    });

    it('leaves no timer behind when the chain resolver answers or throws at once', async () => {
      const leaf = await child();
      vi.useFakeTimers();
      expect(await validate(leaf, { resolveDelegationChain: async () => [] })).toMatchObject({ valid: false, reason: expect.stringMatching(/resolved chain is empty$/) });
      expect(vi.getTimerCount()).toBe(0);
      expect(await validate(leaf, { resolveDelegationChain: () => { throw new Error('store offline'); } })).toEqual({
        valid: false,
        reason: 'Failed to resolve delegation chain: store offline',
      });
      expect(vi.getTimerCount()).toBe(0);
    });

    it('refuses a chain whose revocation checker has not answered by the deadline as a check that failed', async () => {
      const leaf = await signedCredential(issuer, { record: delegationRecord(issuer.did, { id: 'del-leaf', constraints }) });
      expect(await settledAt(ms, (never) => validate(leaf, { revocationChecker: { isRevoked: never } }))).toEqual({
        valid: false,
        reason: `Revocation check failed for delegation "del-leaf": the revocation checker did not answer within ${stated}`,
        evaluated: [leaf],
      });
    });
  });

  describe('the did:web resolver', () => {
    it('resolves no document when its fetch has not answered by the deadline', async () => {
      for (const build of [(fetch: FetchProvider) => new DidWebResolver(fetch, option), (fetch: FetchProvider) => createDidWebResolver(fetch, option)]) {
        expect(await settledAt(ms, (never) => build({ fetch: never } as unknown as FetchProvider).resolve(SLOW))).toBeNull();
        vi.useRealTimers();
      }
    });

    it('shares one pending read among resolutions of a DID until the deadline, and starts another after it', async () => {
      vi.useFakeTimers();
      const fetch = vi.fn(() => new Promise<Response>(() => undefined));
      const resolver = new DidWebResolver({ fetch } as unknown as FetchProvider, option);
      void resolver.resolve(SLOW);
      await vi.advanceTimersByTimeAsync(ms - 1);
      void resolver.resolve(SLOW);
      await vi.advanceTimersByTimeAsync(0);
      expect(fetch).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(1);
      void resolver.resolve(SLOW);
      await vi.advanceTimersByTimeAsync(0);
      expect(fetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('RuntimeFetchProvider', () => {
    it('resolves no document when a configured resolver has not answered by the deadline', async () => {
      expect(await settledAt(ms, (never) => new RuntimeFetchProvider({ didResolvers: { web: { resolve: never } }, ...option }).resolveDID(SLOW))).toBeNull();
    });

    it('resolves no did:web document when its fetch has not answered by the deadline', async () => {
      const provider = new RuntimeFetchProvider(option);
      expect(await settledAt(ms, (never) => {
        vi.spyOn(provider, 'fetch').mockImplementation(never);
        return provider.resolveDID(SLOW);
      })).toBeNull();
    });

    it('fetches no status list when its fetch has not answered by the deadline', async () => {
      const provider = new RuntimeFetchProvider(option);
      expect(await settledAt(ms, (never) => {
        vi.spyOn(provider, 'fetch').mockImplementation(never);
        return provider.fetchStatusList(STATUS.statusListCredential);
      })).toBeNull();
    });
  });

  describe('ProofVerifier', () => {
    it('finds no key when resolveDID has not answered by the deadline', async () => {
      const outcome = await settledAt(ms, (never) =>
        new ProofVerifier({
          cryptoProvider: crypto,
          clockProvider: new SystemClockProvider(),
          nonceCacheProvider: new MemoryNonceCacheProvider(),
          fetchProvider: { resolveDID: never } as unknown as FetchProvider,
          ...option,
        }).fetchPublicKeyFromDID(SLOW).then(() => 'resolved', (error: Error) => error.message));
      expect(outcome).toMatch(/DID resolution deadline exceeded/);
    });
  });
});

describe('a dependencyTimeoutMs that is not a number of milliseconds a timer can hold', () => {
  const set = <T>(dependencyTimeoutMs: unknown, rest: object = {}): T => ({ ...rest, dependencyTimeoutMs }) as T;
  const fetchProvider = { fetch: async () => new Response('{}') } as unknown as FetchProvider;

  it.each(REFUSED_TIMEOUTS)('throws a TypeError where a verifier, a resolver or a provider is built, for %s', (_label, value, got) => {
    const error = timeoutTypeError(got);
    expect(() => new DelegationCredentialVerifier(set(value))).toThrow(error);
    expect(() => createDelegationVerifier(set(value))).toThrow(error);
    expect(() => new DidWebResolver(fetchProvider, set(value))).toThrow(error);
    expect(() => createDidWebResolver(fetchProvider, set(value))).toThrow(error);
    expect(() => new RuntimeFetchProvider(set(value))).toThrow(error);
    expect(() => new ProofVerifier(set(value, {
      cryptoProvider: crypto, clockProvider: new SystemClockProvider(), nonceCacheProvider: new MemoryNonceCacheProvider(), fetchProvider,
    }))).toThrow(error);
  });

  it.each(REFUSED_TIMEOUTS)('makes validateDelegationChain refuse every chain, asking nothing, for %s', async (_label, value, got) => {
    const asked = vi.fn();
    const leaf = await signedCredential(issuer, { record: delegationRecord(issuer.did, { parentId: 'del-parent', constraints }) });
    expect(await validateDelegationChain(leaf, set(value, {
      serverDid: SERVER,
      verifier: { verifyDelegationCredential: asked },
      resolveDelegationChain: asked,
      revocationChecker: { isRevoked: asked },
      statusListConfigured: false,
    }))).toEqual({ valid: false, reason: timeoutTypeError(got).message.slice('[kya-os] '.length) });
    expect(asked).not.toHaveBeenCalled();
  });
});
