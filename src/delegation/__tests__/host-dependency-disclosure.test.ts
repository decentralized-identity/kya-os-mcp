/**
 * A dependency the host gives a verifier (a DID resolver, a signature verifier, a chain resolver,
 * a revocation checker) may throw its transport's words about the verifier's network, and whoever
 * presented the credential chose what it is asked about. So the reason a refusal goes back with
 * says only what could not be done, and what the dependency threw goes to the operator's log. A
 * dependency gives the presenter words of its own by throwing a `RefusalError`, whose code the
 * refusal carries, and a deadline that passed keeps its words. The code of a refusal is as before,
 * and a reason a revocation checker returns, rather than throws, stays in the refusal.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DelegationCredentialVerifier,
  RefusalError,
  createDidKeyResolver,
  logger,
  type DIDResolver,
} from '../../index.js';
import { validateDelegationChain, type ChainEnforcementDeps } from '../chain-enforcement.js';
import { verifyRequestDelegation } from '../../card/index.js';
import { createRealCryptoProvider, createRealIdentity, createRealSignatureVerifier } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { delegationRecord, keyOf, signedCredential, signedJwt } from '../../__tests__/utils/delegation-credentials.js';
import { NOW_MS, RESOURCE, parties } from '../../card/__tests__/signed-chain-helpers.js';
import { createMiddleware, crypto as gateCrypto, handshake, served } from '../../middleware/__tests__/helpers/received-proof.js';
import { WITHHELD_SUFFIX } from '../../utils/thrown-words.js';

const crypto = createRealCryptoProvider();
const TRANSPORT = 'getaddrinfo ENOTFOUND jenkins.corp.example';

afterEach(() => {
  vi.restoreAllMocks();
});

/** What the operator's log was told while `run` ran, with what `run` answered. */
async function logged<T>(run: () => Promise<T>): Promise<{ answer: T; log: string }> {
  const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  const answer = await run();
  return { answer, log: warn.mock.calls.map((call) => call.map(String).join(' ')).join('\n') };
}

/** A dependency's method that throws `error`. */
const throwing = (error: unknown) => async (): Promise<never> => {
  throw error;
};

/** A delegation its issuer signs both ways, with the verifier answers on either path from `deps`. */
async function verdicts(deps: { didResolver: DIDResolver; signatureVerifier?: ReturnType<typeof createRealSignatureVerifier> }) {
  const issuer = await createRealIdentity(crypto);
  const record = delegationRecord(issuer.did, { id: 'del-1' });
  const verifier = new DelegationCredentialVerifier({ signatureVerifier: createRealSignatureVerifier(crypto), ...deps });
  const embedded = await verifier.verifyDelegationCredential(await signedCredential(issuer, { record }), { skipCache: true });
  const enveloped = await verifier.verifyDelegationJwt(await signedJwt(issuer, { record, kid: issuer.kid }), { skipCache: true });
  const pick = ({ reason, code }: { reason?: string; code?: string }) => ({ reason, code });
  return { did: issuer.did, embedded: pick(embedded), enveloped: pick(enveloped) };
}

describe("the delegation verifier, when the host's DID resolver throws", () => {
  it('says only that the DID could not be resolved, on either proof path, and logs what it threw', async () => {
    const { answer, log } = await logged(() => verdicts({ didResolver: { resolve: throwing(new TypeError(TRANSPORT)) } }));
    const unresolved = { reason: `Could not resolve issuer DID: "${answer.did}"${WITHHELD_SUFFIX}`, code: 'did_unavailable' };
    expect(answer).toMatchObject({ embedded: unresolved, enveloped: unresolved });
    expect(log).toContain(TRANSPORT);
  });

  it('gives the words and the code of a RefusalError it throws', async () => {
    const refused = new RefusalError('did_invalid', 'the issuer is not enrolled with this host');
    const answer = await verdicts({ didResolver: { resolve: throwing(refused) } });
    expect(answer.embedded).toEqual({ reason: 'Signature verification error: the issuer is not enrolled with this host', code: 'did_invalid' });
    expect(answer.enveloped).toEqual({
      reason: `Could not resolve issuer DID "${answer.did}": the issuer is not enrolled with this host`,
      code: 'did_invalid',
    });
  });
});

describe("the delegation verifier, when the host's signature verifier throws", () => {
  it('says only that the signature could not be checked, and logs what it threw', async () => {
    const { answer, log } = await logged(async () => {
      const issuer = await createRealIdentity(crypto);
      const verifier = new DelegationCredentialVerifier({
        didResolver: createDidKeyResolver(),
        signatureVerifier: throwing(new TypeError('connect ECONNREFUSED 10.1.2.3:443')),
      });
      return verifier.verifyDelegationCredential(await signedCredential(issuer), { skipCache: true });
    });
    expect(answer).toMatchObject({ valid: false, reason: `Signature verification error: the signature could not be checked${WITHHELD_SUFFIX}`, code: 'runtime_error' });
    expect(log).toContain('connect ECONNREFUSED 10.1.2.3:443');
  });
});

describe("chain enforcement, when the host's chain resolver or revocation checker throws", () => {
  const leaf = async (parentId?: string) =>
    signedCredential(await keyOf('did:web:acme.example', 'k'), {
      record: delegationRecord('did:web:acme.example', { id: 'del-1', ...(parentId ? { parentId } : {}) }),
    });
  const deps: ChainEnforcementDeps = {
    serverDid: 'did:web:server.example',
    verifier: { verifyDelegationCredential: async () => ({ valid: true }) },
    statusListConfigured: true,
  };

  it('says only that the chain could not be resolved, and logs what the resolver threw', async () => {
    const { answer, log } = await logged(async () =>
      validateDelegationChain(await leaf('del-0'), { ...deps, resolveDelegationChain: throwing(new Error(`store at ${TRANSPORT}`)) }),
    );
    expect(answer).toMatchObject({ valid: false, reason: `Failed to resolve delegation chain: the chain resolver failed${WITHHELD_SUFFIX}`, code: 'runtime_error' });
    expect(log).toContain(TRANSPORT);
  });

  it('says only that the revocation check failed, and logs what the checker threw', async () => {
    const { answer, log } = await logged(async () =>
      validateDelegationChain(await leaf(), { ...deps, revocationChecker: { isRevoked: throwing(new Error(TRANSPORT)) } }),
    );
    expect(answer).toMatchObject({
      valid: false,
      reason: `Revocation check failed for delegation "del-1": the revocation checker failed${WITHHELD_SUFFIX}`,
      code: 'status_unavailable',
    });
    expect(log).toContain(TRANSPORT);
  });

  it('gives the words and the code of a RefusalError either throws', async () => {
    const resolved = await validateDelegationChain(await leaf('del-0'), {
      ...deps, resolveDelegationChain: throwing(new RefusalError('chain_invalid', 'the chain store holds no parent del-0')),
    });
    expect(resolved).toMatchObject({ reason: 'Failed to resolve delegation chain: the chain store holds no parent del-0', code: 'chain_invalid' });
    const checked = await validateDelegationChain(await leaf(), {
      ...deps, revocationChecker: { isRevoked: throwing(new RefusalError('delegation_revoked', 'revoked by the operator')) },
    });
    expect(checked).toMatchObject({ reason: 'Revocation check failed for delegation "del-1": revoked by the operator', code: 'delegation_revoked' });
  });
});

describe("the Card request verifier, when the host's chain resolver throws", () => {
  it('says only that the chain could not be resolved, and logs what it threw', async () => {
    const p = parties();
    const { answer, log } = await logged(() =>
      verifyRequestDelegation(
        { meta: {}, proofDid: p.subAgent.did, action: 'orders.place' },
        {
          resource: RESOURCE,
          trustedRootIssuers: [p.acme.did],
          resolveDelegationChain: throwing(new Error(TRANSPORT)),
          verifyHopProof: async () => true,
          checkRevocation: async () => ({ revoked: false, fresh: true }),
          now: () => NOW_MS,
        },
      ),
    );
    expect(answer).toMatchObject({ ok: false, refusalCode: 'runtime_error', reasons: [`delegation chain could not be resolved: the chain resolver failed${WITHHELD_SUFFIX}`] });
    expect(log).toContain(TRANSPORT);
  });
});

describe("the delegation gate, when the host's own DID resolver throws", () => {
  it('tells the client only that the DID could not be resolved', async () => {
    const { answer, log } = await logged(async () => {
      const kyaos = await served(await createMiddleware({ delegation: { didResolver: { resolve: throwing(new TypeError(TRANSPORT)) } } }));
      const sessionId = await handshake(kyaos);
      const [grantor, agent] = await Promise.all([createRealIdentity(gateCrypto), createRealIdentity(gateCrypto)]);
      const delegation = await signedCredential(grantor, {
        record: delegationRecord(grantor.did, {
          id: 'del-1',
          subjectDid: agent.did,
          vcId: 'urn:uuid:del-1',
          constraints: { scopes: ['vault:read'], notAfter: Math.floor(Date.now() / 1000) + 3600 },
        }),
      });
      const ran = async () => ({ content: [{ type: 'text' as const, text: 'ran' }] });
      const consent = { scopeId: 'vault:read', consentUrl: 'https://example.com/consent' };
      const result = (await kyaos.wrapWithDelegation('vault', consent, ran)({ _kyaos_delegation: delegation }, sessionId)) as {
        content: Array<{ text: string }>;
      };
      return { did: grantor.did, body: JSON.parse(result.content[0]!.text) as unknown };
    });
    expect(answer.body).toEqual({ error: 'delegation_invalid', reason: `Delegation del-1 invalid: Could not resolve issuer DID: "${answer.did}"${WITHHELD_SUFFIX}` });
    expect(log).toContain(TRANSPORT);
  });
});
