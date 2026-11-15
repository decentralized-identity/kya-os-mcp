import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { createRevocationChecker } from '../../card/revocation.js';
import { createRealSignatureVerifier, createRealSigningFunction } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { credentialJwt, delegationRecord, keyFromJwk, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { NodeCryptoProvider as TestCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { identity, serveAt } from '../../card/__tests__/signed-chain-helpers.js';
import { CheqdStatusListResolver } from '../../integrations/cheqd/statuslist-resolver.js';
import { NodeCryptoProvider } from '../../providers/node-crypto.js';
import type { FetchProvider } from '../../providers/base.js';
import type { CredentialStatus, DelegationCredential } from '../../types/protocol.js';
import { statusListGzipCodec } from '../../utils/statuslist-gzip.js';
import { validateDelegationChain } from '../chain-enforcement.js';
import { createDidKeyResolver } from '../did-key-resolver.js';
import { withStatusCache } from '../status-cache.js';
import { canonicalizeJSON } from '../utils.js';
import { verifySignature } from '../vc-verification-checks.js';
import { DelegationCredentialVerifier, type StatusListResolver } from '../vc-verifier.js';

const parties = [identity(), identity(), identity(), identity()];
const root = parties[0]!;
const server = 'did:web:server.example';
const didResolver = createDidKeyResolver();
const url = (hop: number) => `https://status.example/hop-${hop}`;
const crypto = new TestCryptoProvider();
/** Each party's key as the shared credential helpers take one. */
const keys = parties.map((party) => keyFromJwk(party.did, party.method, party.privateJwk));
/** `document`, a status list, with a proof the root makes over it through the shared signing function. */
async function signedList(document: Record<string, unknown>): Promise<Record<string, unknown>> {
  return { ...document, proof: await createRealSigningFunction(crypto, keys[0]!)(canonicalizeJSON(document), root.did, root.method) };
}
const signatureVerifier = createRealSignatureVerifier(crypto);
const chain = await Promise.all([0, 1, 2].map((hop) => signedCredential(keys[hop]!, {
  record: delegationRecord(parties[hop]!.did, {
    id: `hop-${hop}`, subjectDid: parties[hop + 1]!.did,
    ...(hop ? { parentId: `hop-${hop - 1}` } : {}),
    constraints: { scopes: ['read'], audience: server },
  }),
  credentialStatus: { type: 'StatusList2021Entry', statusPurpose: 'revocation', statusListIndex: '7', statusListCredential: url(hop) } as CredentialStatus,
})));

async function lists(badHop = -1, defect = 'none') {
  return Object.fromEntries(await Promise.all([0, 1, 2].map(async (hop) => {
    const bad = hop === badHop;
    const bits = Buffer.alloc(16384);
    if (bad && defect === 'revoked') bits[0] = 1; // index 7, MSB-first
    const document = await signedList({
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'],
      ...(bad && defect === 'missing-id' ? {} : { id: bad && defect === 'wrong-id' ? `${url(hop)}?other` : url(hop) }),
      type: ['VerifiableCredential', 'StatusList2021Credential'], issuer: root.did,
      issuanceDate: '2026-01-01T00:00:00Z',
      credentialSubject: { type: 'StatusList2021', statusPurpose: bad && defect === 'purpose' ? 'suspension' : 'revocation', encodedList: `u${gzipSync(bits).toString('base64url')}` },
    });
    if (bad && defect === 'signature') document.issuanceDate = '2026-01-02T00:00:00Z';
    return [url(hop), document] as const;
  })));
}

type Mode = 'issuer-only' | 'configured-root' | 'cheqd-root';
function resolver(mode: Mode, bodies: Record<string, Record<string, unknown>>, cached: boolean): StatusListResolver {
  let inner: StatusListResolver;
  if (mode === 'cheqd-root') {
    inner = new CheqdStatusListResolver({
      expectedIssuerDid: root.did, didResolver, cryptoProvider: new NodeCryptoProvider(),
      decompressor: statusListGzipCodec,
      fetchProvider: { fetch: async (url: string) => new Response(JSON.stringify(bodies[url]), { status: bodies[url] ? 200 : 404 }) } as unknown as FetchProvider,
    });
  } else {
    const checker = createRevocationChecker({
      fetch: serveAt(bodies),
      verifyStatusList: async (list) => (await verifySignature(list as unknown as DelegationCredential, didResolver, signatureVerifier)).valid,
      ...(mode === 'configured-root' ? { statusListIssuers: { [root.did]: ['https://status.example'] } } : {}),
    });
    inner = { checkStatus: async (entry, context) => (await checker(entry, context)).revoked };
  }
  return cached ? withStatusCache(inner, { maxStalenessMs: 60_000 }) : inner;
}

async function checkChain(statusListResolver: StatusListResolver, form: 'object' | 'JWT') {
  const verifier = new DelegationCredentialVerifier({ didResolver, statusListResolver, signatureVerifier });
  return validateDelegationChain(chain[2]!, {
    serverDid: server, trustedRootIssuers: [root.did], statusListConfigured: true,
    resolveDelegationChain: async () => chain.slice(0, 2),
    verifier: { verifyDelegationCredential: async (vc) => {
      if (form === 'object') return verifier.verifyDelegationCredential(vc);
      return verifier.verifyDelegationJwt(await credentialJwt(vc, keys.find((key) => key.did === vc.issuer)!));
    } },
  });
}

describe.each(['object', 'JWT'] as const)('status authority through the middleware chain core: %s credentials', (form) => {
  it.each([false, true])('a root pin alone cannot authorize the issuer-only reader, cached=%s', async (cached) => {
    const reader = resolver('issuer-only', await lists(), cached);
    // Warm the root's own allow. The same root signature does not authorize it
    // for another hop when the middleware supplies only that hop's issuer.
    expect(await reader.checkStatus(chain[0]!.credentialStatus!, { credentialIssuer: root.did })).toBe(false);
    expect((await checkChain(reader, form)).valid).toBe(false);
  });
  describe.each(['configured-root', 'cheqd-root'] as const)('%s', (mode) => {
    it.each([false, true])('accepts clear lists, cached=%s', async (cached) => {
      expect((await checkChain(resolver(mode, await lists(), cached), form)).valid).toBe(true);
    });
    // One test per hop, so each walks the chain at most ten times.
    it.each([0, 1, 2].flatMap((hop) => [false, true].map((cached) => ({ hop, cached }))))(
      'refuses a defect at hop $hop, cached=$cached',
      async ({ hop, cached }) => {
        for (const defect of ['revoked', 'wrong-id', 'purpose', 'signature', 'missing-id']) {
          const reader = resolver(mode, await lists(hop, defect), cached);
          const result = await checkChain(reader, form);
          expect(result.valid, `${mode} ${form} hop ${hop} ${defect}`).toBe(false);
          // Refusal must survive a second walk (including cheqd's document cache).
          expect((await checkChain(reader, form)).valid).toBe(false);
        }
      },
    );
  });
});
