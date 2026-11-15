/**
 * `delegation.dependencyTimeoutMs` is the one deadline the delegation gate gives each dependency
 * it waits on: a DID resolver, a did:web read through the default fetch provider, a status list
 * resolver, a `resolveDelegationChain` and a `RevocationChecker`. Each case hangs one of them on a
 * promise that never settles and holds the gate to refusing at the deadline and no sooner, under
 * the default of 5 seconds and under a raised value. A value that is not a number of milliseconds a
 * timer can hold is refused when the middleware is created.
 */

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { DEADLINES, REFUSED_TIMEOUTS, settledAt, timeoutTypeError, type Hang } from '../../__tests__/utils/deadlines.js';
import { delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
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

  it('refuses a delegation whose issuer DID its resolver has not resolved by the deadline', async () => {
    expect(await refusal(await credential(), (never) => ({ didResolver: { resolve: never } })))
      .toBe('Delegation del-leaf invalid: Signature verification error: DID resolution deadline exceeded');
  });

  it('refuses a delegation whose did:web document the default fetch provider has not read by the deadline', async () => {
    const reason = await refusal(await credential(), (never) => {
      vi.stubGlobal('fetch', never);
      return { didResolver: undefined };
    });
    expect(reason).toBe('Delegation del-leaf invalid: Signature verification error: DID resolution deadline exceeded');
  });

  it('builds the default fetch provider, which it hands a didResolvers factory, with the same deadline', async () => {
    let provider: FetchProvider | undefined;
    gate({ ...option, didResolvers: { example: (given) => {
      provider = given;
      return { resolve: async () => null };
    } } });
    const resolved = await settledAt(ms, (never) => {
      vi.stubGlobal('fetch', never);
      return provider!.resolveDID('did:web:slow.example');
    });
    expect(resolved).toBeNull();
  });

  it('refuses a delegation whose status its resolver has not answered for by the deadline', async () => {
    expect(await refusal(await credential({ status: STATUS }), (never) => ({ statusListResolver: { checkStatus: never } })))
      .toBe(`Delegation del-leaf invalid: Status check error: the status list resolver did not answer within ${stated}`);
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
