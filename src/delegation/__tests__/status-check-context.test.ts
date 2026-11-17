/**
 * The delegation verifier names a credential's issuer to its `StatusListResolver`, so the resolver
 * can hold the status list to that issuer (W3C Bitstring Status List v1.0 §3.2), on the Data
 * Integrity and VC-JWT paths alike, and `withStatusCache` passes the context through and keys on it.
 * On the delegation middleware's path the resolver is told that issuer alone, never the chain's root,
 * even when the root is pinned.
 */

import { beforeAll, describe, it, expect, vi } from 'vitest';
import { DelegationCredentialVerifier, type DIDDocument, type StatusListResolver } from '../vc-verifier.js';
import { validateDelegationChain } from '../chain-enforcement.js';
import { checkCredentialStatus } from '../vc-verification-checks.js';
import { withStatusCache } from '../status-cache.js';
import { acceptStatusList, statusListExpectationFor, type StatusListIssuers } from '../../utils/statuslist-acceptance.js';
import { RefusalError } from '../../utils/refusal.js';
import {
  credentialJwt, delegationRecord, keyOf, resignedCredential, signedCredential,
} from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import type { AgentIdentity } from '../../providers/base.js';
import type { CredentialStatus, DelegationCredential } from '../../types/protocol.js';

const ISSUER = 'did:web:acme.example';
const ROOT = 'did:web:root.example';
const SUBJECT = 'did:web:agent.example';

const STATUS: CredentialStatus = {
  id: 'https://status.example/1#7',
  type: 'StatusList2021Entry',
  statusPurpose: 'revocation',
  statusListIndex: '7',
  statusListCredential: 'https://status.example/1',
};

let acme: AgentIdentity;
let rootKey: AgentIdentity;
beforeAll(async () => {
  [acme, rootKey] = await Promise.all([keyOf(ISSUER, 'key-1'), keyOf(ROOT, 'key-1')]);
});

/** A delegation credential Acme signs, naming `issuer` as its issuer, as written, whose status is {@link STATUS}. */
async function credential(issuer: unknown): Promise<DelegationCredential> {
  const signed = await signedCredential(acme, {
    record: delegationRecord(ISSUER, {
      id: 'del-status-context', subjectDid: SUBJECT, vcId: 'urn:uuid:status-context', constraints: { scopes: ['tools:read'] },
    }),
    credentialStatus: STATUS,
  });
  return resignedCredential(signed, { issuer }, acme);
}

const clearStatus = () => ({ checkStatus: vi.fn<StatusListResolver['checkStatus']>(async () => false) });

/**
 * A resolver that serves `list`, with no bit set, and holds it to the credential as the docs tell a
 * custom resolver to,
 * `acceptStatusList(list, statusListExpectationFor(status, context, statusListIssuers))`, refusing
 * with a `RefusalError` so its reason reaches the verifier's. It checks no proof here.
 */
function ruleResolver(list: Record<string, unknown>, statusListIssuers?: StatusListIssuers) {
  return {
    checkStatus: vi.fn<StatusListResolver['checkStatus']>(async (status, context) => {
      if (!context) throw new RefusalError('configuration_error', 'no credential named');
      const verdict = acceptStatusList(list, statusListExpectationFor(status, context, statusListIssuers));
      if (!verdict.valid) throw new RefusalError('status_signer_untrusted', verdict.reason);
      return false;
    }),
  };
}

describe('DelegationCredentialVerifier names the credential issuer to the status-list resolver', () => {
  it("on the Data Integrity path, whether the issuer is a string or an object's id", async () => {
    for (const issuer of [ISSUER, { id: ISSUER, name: 'Acme' }]) {
      const resolver = clearStatus();
      const result = await new DelegationCredentialVerifier().verifyDelegationCredential(await credential(issuer), {
        skipSignature: true,
        statusListResolver: resolver,
      });
      expect(result.valid).toBe(true);
      expect(resolver.checkStatus.mock.calls).toEqual([[STATUS, { credentialIssuer: ISSUER }]]);
    }
  });

  it('on the VC-JWT path', async () => {
    const didResolver = {
      resolve: async (did: string): Promise<DIDDocument | null> => (did === ISSUER ? issuerDidDocument(methodOf(acme)) : null),
    };
    const jwt = await credentialJwt(await credential(ISSUER), acme);
    const resolver = clearStatus();
    const result = await new DelegationCredentialVerifier({ didResolver }).verifyDelegationJwt(jwt, {
      statusListResolver: resolver,
    });
    expect(result.valid).toBe(true);
    expect(resolver.checkStatus.mock.calls).toEqual([[STATUS, { credentialIssuer: ISSUER }]]);
  });

  it('denies a credential that names no issuer DID, without asking the resolver', async () => {
    for (const issuer of [{ name: 'Acme' }, { id: '' }, { id: 7 }]) {
      const resolver = clearStatus();
      const result = await new DelegationCredentialVerifier().verifyDelegationCredential(await credential(issuer), {
        skipSignature: true,
        statusListResolver: resolver,
      });
      // The basic stage refuses an issuer that is not a URL, so no status is read.
      expect(result).toMatchObject({ valid: false, stage: 'basic' });
      expect(result.reason).toMatch(/ is not a URL$/);
      expect(resolver.checkStatus).not.toHaveBeenCalled();
    }
  });

  it("reads the credential issuer's list that states no id only while the resolver's configuration names no other issuer", async () => {
    const idless = { issuer: ISSUER, credentialSubject: { statusPurpose: 'revocation' } };
    const verify = async (resolver: StatusListResolver) =>
      new DelegationCredentialVerifier().verifyDelegationCredential(await credential(ISSUER), { skipSignature: true, statusListResolver: resolver });
    expect(await verify(ruleResolver(idless))).toMatchObject({ valid: true });
    expect(await verify(ruleResolver(idless, { [ISSUER]: ['https://lists.elsewhere.example'] }))).toMatchObject({ valid: true });
    expect(await verify(ruleResolver(idless, { [ROOT]: ['https://lists.elsewhere.example'] }))).toMatchObject({
      valid: false,
      statusOutcome: 'status_unresolvable',
      reason: `Status check error: status list states no id, but must state the URL it was fetched from ("${STATUS.statusListCredential}")`,
    });
  });

  it('denies a status check told no issuer DID as status_unresolvable, without asking the resolver', async () => {
    for (const credentialIssuer of [undefined, '']) {
      const resolver = clearStatus();
      expect(await checkCredentialStatus(STATUS, resolver, credentialIssuer)).toMatchObject({
        valid: false,
        outcome: 'status_unresolvable',
        reason: expect.stringMatching(/names no issuer DID/),
      });
      expect(resolver.checkStatus).not.toHaveBeenCalled();
    }
  });
});

describe('withStatusCache and the status check context', () => {
  it('passes the context to the wrapped resolver unchanged', async () => {
    const resolver = clearStatus();
    const context = { credentialIssuer: ISSUER, trustedRootIssuer: ROOT };
    await withStatusCache(resolver, { maxStalenessMs: 60_000 }).checkStatus(STATUS, context);
    expect(resolver.checkStatus.mock.calls).toEqual([[STATUS, context]]);
  });

  it("never serves one credential's verdict for another credential that names other issuers", async () => {
    // The list is the root's: it speaks for the root's credentials and, once the root is pinned, for
    // those below it.
    const resolver: StatusListResolver = {
      checkStatus: async (_status, context) => {
        if (context?.credentialIssuer !== ROOT && context?.trustedRootIssuer !== ROOT) {
          throw new Error('not a list that speaks for this credential');
        }
        return false;
      },
    };
    const cached = withStatusCache(resolver, { maxStalenessMs: 60_000 });
    expect(await cached.checkStatus(STATUS, { credentialIssuer: ROOT })).toBe(false);
    expect(await cached.checkStatus(STATUS, { credentialIssuer: ISSUER, trustedRootIssuer: ROOT })).toBe(false);
    await expect(cached.checkStatus(STATUS, { credentialIssuer: ISSUER })).rejects.toThrow();
    await expect(cached.checkStatus(STATUS, { credentialIssuer: ISSUER, trustedRootIssuer: SUBJECT })).rejects.toThrow();
    await expect(cached.checkStatus(STATUS, { credentialIssuer: 'did:web:mallory.example' })).rejects.toThrow();
    await expect(cached.checkStatus(STATUS)).rejects.toThrow();
  });

  it("never serves a verdict kept for one root status-list URL to an entry whose root's credential names another", async () => {
    // The root's list, read by the rule: it is the root's only where the root's credential names its URL.
    const list = { id: STATUS.statusListCredential, issuer: ROOT, credentialSubject: { statusPurpose: 'revocation' } };
    const resolver = ruleResolver(list);
    const cached = withStatusCache(resolver, { maxStalenessMs: 60_000 });
    const pinned = { credentialIssuer: ISSUER, trustedRootIssuer: ROOT };
    const named = { ...pinned, trustedRootStatusList: STATUS.statusListCredential };
    expect(await cached.checkStatus(STATUS, named)).toBe(false);
    expect(await cached.checkStatus(STATUS, named)).toBe(false);
    for (const context of [{ ...pinned, trustedRootStatusList: 'https://root.example/own' }, pinned]) {
      await expect(cached.checkStatus(STATUS, context)).rejects.toThrow(/does not keep this list's URL/);
    }
    expect(resolver.checkStatus).toHaveBeenCalledTimes(3);
  });

  it('caches per issuer, pinned root and root status-list URL, and a call that names none under its own key', async () => {
    const resolver = clearStatus();
    const cached = withStatusCache(resolver, { maxStalenessMs: 60_000 });
    const contexts = [
      { credentialIssuer: ISSUER },
      { credentialIssuer: 'did:web:other.example' },
      { credentialIssuer: ISSUER, trustedRootIssuer: ROOT },
      { credentialIssuer: ISSUER, trustedRootIssuer: SUBJECT },
      { credentialIssuer: ISSUER, trustedRootIssuer: ROOT, trustedRootStatusList: STATUS.statusListCredential },
      { credentialIssuer: ISSUER, trustedRootIssuer: ROOT, trustedRootStatusList: 'https://root.example/own' },
      undefined,
    ];
    for (let i = 0; i < 2; i += 1) {
      for (const context of contexts) await cached.checkStatus(STATUS, context);
    }
    expect(resolver.checkStatus.mock.calls).toEqual(contexts.map((context) => [STATUS, context]));
  });
});

describe("the delegation middleware's path names no root to the resolver", () => {
  const SERVER = 'did:web:server.example';
  const LEAF = 'did:web:worker.example';

  /** A chain-enforcement credential from `issuer`, the root or Acme, to `subject`. */
  function link(opts: { id: string; issuer: string; subject: string; parentId?: string; status?: CredentialStatus }) {
    return signedCredential(opts.issuer === ROOT ? rootKey : acme, {
      record: delegationRecord(opts.issuer, {
        id: opts.id, subjectDid: opts.subject,
        ...(opts.parentId ? { parentId: opts.parentId } : {}),
        constraints: { scopes: ['tools:read'], audience: SERVER },
      }),
      credentialStatus: opts.status,
    });
  }

  /** A resolver that holds the root's list, with no bit set, to the issuers `context` names. */
  function rootListResolver(statusListIssuers?: StatusListIssuers) {
    const list = { id: STATUS.statusListCredential, issuer: ROOT, credentialSubject: { statusPurpose: 'revocation' } };
    return ruleResolver(list, statusListIssuers);
  }

  async function verifyChain(resolver: StatusListResolver) {
    const root = await link({ id: 'del-root', issuer: ROOT, subject: ISSUER });
    const leaf = await link({ id: 'del-leaf', issuer: ISSUER, subject: LEAF, parentId: 'del-root', status: STATUS });
    const verifier = new DelegationCredentialVerifier({ statusListResolver: resolver });
    return validateDelegationChain(leaf, {
      serverDid: SERVER,
      statusListConfigured: true,
      trustedRootIssuers: [ROOT],
      resolveDelegationChain: async () => [root],
      verifier: { verifyDelegationCredential: (vc) => verifier.verifyDelegationCredential(vc, { skipSignature: true }) },
    });
  }

  it("refuses a re-delegated credential's entry on the pinned root's list, telling the resolver its issuer alone", async () => {
    const resolver = rootListResolver();
    const result = await verifyChain(resolver);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain(
      `status list issuer "${ROOT}" does not keep this list's URL: "${ISSUER}" does, as the issuer of the credential`,
    );
    expect(resolver.checkStatus.mock.calls).toEqual([[STATUS, { credentialIssuer: ISSUER }]]);
  });

  it("reads it once the resolver's own configuration binds the list's URL, or its origin, to the root", async () => {
    expect(await verifyChain(rootListResolver({ [ROOT]: [STATUS.statusListCredential] }))).toMatchObject({ valid: true });
    const origin = /^https:\/\/[^/]+/.exec(STATUS.statusListCredential)![0];
    expect(await verifyChain(rootListResolver({ [ROOT]: [origin] }))).toMatchObject({ valid: true });
    expect((await verifyChain(rootListResolver({ [ROOT]: [`${STATUS.statusListCredential}/other`] }))).valid).toBe(false);
  });
});
