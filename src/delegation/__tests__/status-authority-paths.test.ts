import { createPublicKey, sign, verify, type JsonWebKeyInput } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { importJWK, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import { createRevocationChecker } from '../../card/revocation.js';
import { identity, serveAt, type TestIdentity } from '../../card/__tests__/signed-chain-helpers.js';
import { CheqdStatusListResolver } from '../../integrations/cheqd/statuslist-resolver.js';
import { NodeCryptoProvider } from '../../providers/node-crypto.js';
import type { FetchProvider } from '../../providers/base.js';
import type { DelegationCredential } from '../../types/protocol.js';
import { statusListGzipCodec } from '../../utils/statuslist-gzip.js';
import { validateDelegationChain } from '../chain-enforcement.js';
import { createDidKeyResolver } from '../did-key-resolver.js';
import { withStatusCache } from '../status-cache.js';
import { canonicalizeJSON } from '../utils.js';
import { verifySignature } from '../vc-verification-checks.js';
import { DelegationCredentialVerifier, type SignatureVerificationFunction, type StatusListResolver } from '../vc-verifier.js';

const parties = [identity(), identity(), identity(), identity()];
const root = parties[0]!;
const server = 'did:web:server.example';
const didResolver = createDidKeyResolver();
const url = (hop: number) => `https://status.example/hop-${hop}`;
function signed(document: Record<string, unknown>, signer: TestIdentity): Record<string, unknown> {
  return { ...document, proof: {
    type: 'Ed25519Signature2020', verificationMethod: signer.method, proofPurpose: 'assertionMethod',
    proofValue: sign(null, Buffer.from(canonicalizeJSON(document)), signer.privateKey).toString('base64url'),
  } };
}
const signatureVerifier: SignatureVerificationFunction = async (vc, jwk) => {
  const { proof, ...document } = vc;
  return { valid: verify(null, Buffer.from(canonicalizeJSON(document)),
    createPublicKey({ key: jwk as JsonWebKeyInput['key'], format: 'jwk' }), Buffer.from(proof!.proofValue as string, 'base64url')) };
};
const chain = [0, 1, 2].map((hop) => signed({
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential', 'DelegationCredential'], issuer: parties[hop]!.did,
  issuanceDate: '2026-01-01T00:00:00Z',
  credentialSubject: { id: parties[hop + 1]!.did, delegation: {
    id: `hop-${hop}`, issuerDid: parties[hop]!.did, subjectDid: parties[hop + 1]!.did,
    ...(hop ? { parentId: `hop-${hop - 1}` } : {}),
    constraints: { scopes: ['read'], audience: server }, status: 'active', signature: '',
  } },
  credentialStatus: { type: 'StatusList2021Entry', statusPurpose: 'revocation', statusListIndex: '7', statusListCredential: url(hop) },
}, parties[hop]!) as unknown as DelegationCredential);

function lists(badHop = -1, defect = 'none') {
  return Object.fromEntries([0, 1, 2].map((hop) => {
    const bad = hop === badHop;
    const bits = Buffer.alloc(16384);
    if (bad && defect === 'revoked') bits[0] = 1; // index 7, MSB-first
    const document = signed({
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'],
      ...(bad && defect === 'missing-id' ? {} : { id: bad && defect === 'wrong-id' ? `${url(hop)}?other` : url(hop) }),
      type: ['VerifiableCredential', 'StatusList2021Credential'], issuer: root.did,
      issuanceDate: '2026-01-01T00:00:00Z',
      credentialSubject: { type: 'StatusList2021', statusPurpose: bad && defect === 'purpose' ? 'suspension' : 'revocation', encodedList: `u${gzipSync(bits).toString('base64url')}` },
    }, root);
    if (bad && defect === 'signature') document.issuanceDate = '2026-01-02T00:00:00Z';
    return [url(hop), document];
  }));
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
      ...(mode === 'configured-root' ? { statusListIssuers: Object.fromEntries(parties.map((p) => [p.did, [root.did]])) } : {}),
    });
    inner = { checkStatus: async (entry, context) => (await checker(entry, context)).revoked };
  }
  return cached ? withStatusCache(inner, { maxStalenessMs: 60_000 }) : inner;
}

/** Each party's signing key, imported once. */
const signingKeys = new Map<string, ReturnType<typeof importJWK>>();
function signingKey(signer: TestIdentity): ReturnType<typeof importJWK> {
  if (!signingKeys.has(signer.did)) signingKeys.set(signer.did, importJWK(signer.privateJwk, 'EdDSA'));
  return signingKeys.get(signer.did)!;
}

async function checkChain(statusListResolver: StatusListResolver, form: 'object' | 'JWT') {
  const verifier = new DelegationCredentialVerifier({ didResolver, statusListResolver, signatureVerifier });
  return validateDelegationChain(chain[2]!, {
    serverDid: server, trustedRootIssuers: [root.did], statusListConfigured: true,
    resolveDelegationChain: async () => chain.slice(0, 2),
    verifier: { verifyDelegationCredential: async (vc) => {
      if (form === 'object') return verifier.verifyDelegationCredential(vc);
      const signer = parties.find((p) => p.did === vc.issuer)!;
      const { proof: _proof, ...unsigned } = vc;
      const jwt = await new SignJWT({ vc: unsigned }).setProtectedHeader({ alg: 'EdDSA', kid: signer.method })
        .setIssuer(signer.did).sign(await signingKey(signer));
      return verifier.verifyDelegationJwt(jwt);
    } },
  });
}

describe.each(['object', 'JWT'] as const)('status authority through the middleware chain core: %s credentials', (form) => {
  it.each([false, true])('a root pin alone cannot authorize the issuer-only reader, cached=%s', async (cached) => {
    const reader = resolver('issuer-only', lists(), cached);
    // Warm the root's own allow. The same root signature does not authorize it
    // for another hop when the middleware supplies only that hop's issuer.
    expect(await reader.checkStatus(chain[0]!.credentialStatus!, { credentialIssuer: root.did })).toBe(false);
    expect((await checkChain(reader, form)).valid).toBe(false);
  });
  describe.each(['configured-root', 'cheqd-root'] as const)('%s', (mode) => {
    it.each([false, true])('accepts clear lists, cached=%s', async (cached) => {
      expect((await checkChain(resolver(mode, lists(), cached), form)).valid).toBe(true);
    });
    // One test per hop, so each walks the chain at most ten times.
    it.each([0, 1, 2].flatMap((hop) => [false, true].map((cached) => ({ hop, cached }))))(
      'refuses a defect at hop $hop, cached=$cached',
      async ({ hop, cached }) => {
        for (const defect of ['revoked', 'wrong-id', 'purpose', 'signature', 'missing-id']) {
          // The root is the only issuer accepted for hop 0, so its list may omit the id; cheqd's global
          // pin never gets that exemption.
          if (mode === 'configured-root' && hop === 0 && defect === 'missing-id') continue;
          const reader = resolver(mode, lists(hop, defect), cached);
          const result = await checkChain(reader, form);
          expect(result.valid, `${mode} ${form} hop ${hop} ${defect}`).toBe(false);
          // Refusal must survive a second walk (including cheqd's document cache).
          expect((await checkChain(reader, form)).valid).toBe(false);
        }
      },
    );
  });
});
