/**
 * `delegation.dependencyTimeoutMs` is the one deadline the delegation gate gives each dependency
 * it waits on: a DID resolver, a did:web read through the default fetch provider, a status list
 * resolver, a `resolveDelegationChain` and a `RevocationChecker`. Each case hangs one of them on a
 * promise that never settles and holds the gate to refusing at the deadline and no sooner, under
 * the default of 5 seconds and under a raised value. The verification of each credential, which
 * resolves its issuer's DID and reads its status, is held to the same deadline as a whole, so a
 * DID or status read that hangs is refused as the credential's verification that did not answer. A value that is not a number of milliseconds a
 * timer can hold is refused when the middleware is created.
 */

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { DEADLINES, REFUSED_TIMEOUTS, settledAt, timeoutTypeError, type Hang } from '../../__tests__/utils/deadlines.js';
import { delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { cheqdResolver } from '../../integrations/cheqd/resolver.js';
import type { AgentIdentity, FetchProvider } from '../../providers/base.js';
import type { CredentialStatus, DelegationCredential } from '../../types/protocol.js';
import type { KyaOsDelegationConfig } from '../with-kya-os.config-types.js';
import { createDelegationVerification } from '../with-kya-os.delegation-verify.js';
import type { MiddlewareDeps } from '../with-kya-os.deps.js';
import { delegationGate } from './helpers/delegation-gate.js';

const SERVER = 'did:web:server.example';
const STATUS: CredentialStatus = {
  id: 'https://status.example/1#7', type: 'StatusList2021Entry', statusPurpose: 'revocation',
  statusListIndex: '7', statusListCredential: 'https://status.example/1',
};
let root: AgentIdentity;
beforeAll(async () => {
  root = await keyOf('did:web:root.example', 'key');
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

/** A credential the root signs, with `status` and under `parentId` when given. */
function credential(overrides: { parentId?: string; status?: CredentialStatus } = {}): Promise<DelegationCredential> {
  return signedCredential(root, {
    record: delegationRecord(root.did, {
      id: 'del-leaf',
      ...(overrides.parentId === undefined ? {} : { parentId: overrides.parentId }),
      constraints: { scopes: ['tools:read'], audience: SERVER, notAfter: Math.floor(Date.now() / 1000) + 3600 },
    }),
    ...(overrides.status === undefined ? {} : { credentialStatus: overrides.status }),
  });
}

/** The gate's verification, trusting the root and resolving its DID, with `config` over that. */
function gate(config: KyaOsDelegationConfig) {
  return createDelegationVerification({
    identity: { ...root, did: SERVER },
    cryptoProvider: new NodeCryptoProvider(),
    delegationConfig: {
      trustedRootIssuers: [root.did],
      didResolver: { resolve: async (did: string) => (did === root.did ? issuerDidDocument(methodOf(root)) : null) },
      ...config,
    },
  } as unknown as MiddlewareDeps).verifyDelegation;
}

describe.each(DEADLINES)('the delegation gate, %s', (_label, option, ms, stated) => {
  /** The gate's reason for refusing `vc` when the dependency `config` builds from one that never answers hangs. */
  const refusal = async (vc: DelegationCredential, config: (never: Hang) => KyaOsDelegationConfig) => {
    const check = await settledAt(ms, (never) => gate({ ...option, ...config(never) })(vc));
    expect(check.valid).toBe(false);
    return check.valid ? undefined : check.reason;
  };

  /** The reason for a credential whose verification has not answered by the deadline. */
  const unanswered = `Delegation "del-leaf" could not be verified: the credential verifier did not answer within ${stated}`;

  it('refuses a delegation whose issuer DID its resolver has not resolved by the deadline', async () => {
    expect(await refusal(await credential(), (never) => ({ didResolver: { resolve: never } }))).toBe(unanswered);
  });

  it('refuses a delegation whose did:web document the default fetch provider has not read by the deadline', async () => {
    const reason = await refusal(await credential(), (never) => {
      vi.stubGlobal('fetch', never);
      return { didResolver: undefined };
    });
    expect(reason).toBe(unanswered);
  });

  it('builds the default fetch provider, which it hands a didResolvers factory, with the same deadline', async () => {
    let provider: FetchProvider | undefined;
    gate({ ...option, didResolvers: { example: (given) => {
      provider = given;
      return { resolve: async () => null };
    } } });
    const resolved = await settledAt(ms, (never) => {
      vi.stubGlobal('fetch', never);
      // The root is pinned, so its document is read through the runtime's fetch, which never answers.
      return provider!.resolveDID(root.did);
    });
    expect(resolved).toBeNull();
  });

  it('gives a resolver it builds from a didResolvers factory, such as the cheqd resolver, the same deadline', async () => {
    const issuer = await keyOf('did:cheqd:testnet:6c9b1bbe-1a2c-4c1e-9d3c-2e0f0f0b0a01', 'key');
    const vc = await signedCredential(issuer, {
      record: delegationRecord(issuer.did, { id: 'del-leaf', constraints: { scopes: ['tools:read'], audience: SERVER, notAfter: Math.floor(Date.now() / 1000) + 3600 } }),
    });
    const check = await settledAt(ms, (never) => gate({
      ...option,
      trustedRootIssuers: [issuer.did],
      didResolver: undefined,
      fetchProvider: { fetch: never } as unknown as FetchProvider,
      didResolvers: { cheqd: cheqdResolver({ resolverUrl: 'https://resolver.example' }) },
    })(vc));
    expect(check).toMatchObject({ valid: false });
  });

  describe('a resolver that finds nothing', () => {
    /** A resolver that answers `null` after `delay` ms. */
    const nothingAfter = (delay: number) => ({ resolve: () => new Promise<null>((resolve) => setTimeout(() => resolve(null), delay)) });
    /** How many did:web reads the gate starts for a credential whose resolvers are `config`, once the clock is well past the deadline. */
    const fallbackReads = async (config: KyaOsDelegationConfig) => {
      const vc = await credential();
      vi.useFakeTimers();
      const fetch = vi.fn(() => new Promise<Response>(() => undefined));
      vi.stubGlobal('fetch', fetch);
      const check = gate({ ...option, didResolver: undefined, ...config })(vc);
      await vi.advanceTimersByTimeAsync(3 * ms);
      expect((await check).valid).toBe(false);
      return fetch.mock.calls.length;
    };

    it('is followed by the did:web read when it answers before the deadline', async () => {
      expect(await fallbackReads({ didResolver: nothingAfter(ms - 1) })).toBe(1);
      vi.useRealTimers();
      expect(await fallbackReads({ didResolvers: { web: nothingAfter(ms - 1) } })).toBe(1);
    });

    it('starts no did:web read when it answers at the deadline or after it', async () => {
      for (const delay of [ms, ms + 1, 2 * ms]) {
        expect(await fallbackReads({ didResolver: nothingAfter(delay) })).toBe(0);
        vi.useRealTimers();
        expect(await fallbackReads({ didResolvers: { web: nothingAfter(delay) } })).toBe(0);
        vi.useRealTimers();
      }
    });

    it('asks no configured resolver when the custom one answers at the deadline or after it', async () => {
      const configured = vi.fn(async () => null);
      expect(await fallbackReads({ didResolver: nothingAfter(ms), didResolvers: { web: { resolve: configured } } })).toBe(0);
      expect(configured).not.toHaveBeenCalled();
    });
  });

  it('refuses a delegation whose status its resolver has not answered for by the deadline', async () => {
    expect(await refusal(await credential({ status: STATUS }), (never) => ({ statusListResolver: { checkStatus: never } }))).toBe(unanswered);
  });

  it('refuses a delegation whose chain its resolver has not returned by the deadline', async () => {
    expect(await refusal(await credential({ parentId: 'del-parent' }), (never) => ({ resolveDelegationChain: never })))
      .toBe(`Failed to resolve delegation chain: the chain resolver did not answer within ${stated}`);
  });

  it('refuses a delegation whose revocation checker has not answered by the deadline', async () => {
    expect(await refusal(await credential(), (never) => ({ revocationChecker: { isRevoked: never } })))
      .toBe(`Revocation check failed for delegation "del-leaf": the revocation checker did not answer within ${stated}`);
  });
});

describe('a delegation.dependencyTimeoutMs that is not a number of milliseconds a timer can hold', () => {
  it.each(REFUSED_TIMEOUTS)('is refused with a TypeError when the middleware is created, for %s', async (_label, value, got) => {
    const config = { dependencyTimeoutMs: value } as KyaOsDelegationConfig;
    expect(() => gate(config)).toThrow(timeoutTypeError(got, 'delegation.'));
    await expect(delegationGate({ trustedRootIssuers: [root.did], config })).rejects.toThrow(timeoutTypeError(got, 'delegation.'));
  });

  it('is not refused when it is a number of milliseconds, or left out', async () => {
    await expect(delegationGate({ trustedRootIssuers: [root.did], config: { dependencyTimeoutMs: 30_000 } })).resolves.toBeDefined();
    await expect(delegationGate({ trustedRootIssuers: [root.did] })).resolves.toBeDefined();
  });
});
