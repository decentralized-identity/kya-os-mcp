import { beforeAll, describe, expect, it, vi } from 'vitest';
import { createDelegationVerification } from '../with-kya-os.delegation-verify.js';
import type { MiddlewareDeps } from '../with-kya-os.deps.js';
import type { KyaOsDelegationConfig } from '../with-kya-os.config-types.js';
import { DelegationCredentialIssuer } from '../../delegation/vc-issuer.js';
import { canonicalizeJSON, completeVCJWT, createUnsignedVCJWT } from '../../delegation/utils.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import type { VCSigningFunction } from '../../delegation/vc-issuer.js';
import type { AgentIdentity } from '../../providers/base.js';
import type { DIDDocument } from '../../delegation/vc-verifier.js';
import type { DelegationCredential } from '../../types/protocol.js';

const crypto = new NodeCryptoProvider();
const SERVER = 'did:web:server.example';
let root: AgentIdentity, delegate: AgentIdentity, outsider: AgentIdentity;
beforeAll(async () => {
  const identity = async (name: string) => ({
    ...await crypto.generateKeyPair(), type: 'development' as const, createdAt: new Date().toISOString(), did: `did:web:${name}.example`, kid: `did:web:${name}.example#key`,
  });
  const keys = await Promise.all(['root', 'delegate', 'outsider'].map(identity));
  root = keys[0]!; delegate = keys[1]!; outsider = keys[2]!;
});

function signing(key: AgentIdentity): VCSigningFunction {
  return async (canonical, _issuer, kid) => ({
    type: 'Ed25519Signature2020', created: new Date().toISOString(),
    verificationMethod: kid, proofPurpose: 'assertionMethod',
    proofValue: Buffer.from(await crypto.sign(new TextEncoder().encode(canonical), key.privateKey)).toString('base64url'),
  });
}

async function credential(key: AgentIdentity, id: string, parentId?: string): Promise<DelegationCredential> {
  return new DelegationCredentialIssuer(
    { getDid: () => key.did, getKeyId: () => key.kid, getPrivateKey: () => key.privateKey },
    signing(key),
  ).issueDelegationCredential({
    id, issuerDid: key.did, subjectDid: delegate.did, vcId: `urn:uuid:${id}`,
    ...(parentId === undefined ? {} : { parentId }),
    constraints: { scopes: ['tools:read'], audience: SERVER, notAfter: Math.floor(Date.now() / 1000) + 3600 },
    signature: '', status: 'active', createdAt: Date.now(),
  });
}

async function jwt(vc: DelegationCredential, key: AgentIdentity, claims: Record<string, unknown> = {}): Promise<string> {
  const { proof: _proof, ...unsigned } = vc;
  const { payload } = createUnsignedVCJWT(unsigned);
  const encodedPayload = Buffer.from(JSON.stringify({ ...payload, ...claims })).toString('base64url');
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: key.kid })).toString('base64url');
  const input = `${header}.${encodedPayload}`;
  const signature = await crypto.sign(new TextEncoder().encode(input), key.privateKey);
  return completeVCJWT(input, Buffer.from(signature).toString('base64url'));
}

function setup(config: KyaOsDelegationConfig = {}) {
  const resolve = vi.fn(async (did: string): Promise<DIDDocument | null> => {
    const key = [root, delegate, outsider].find(key => key.did === did);
    return key ? {
      id: did,
      verificationMethod: [{
        id: key.kid, type: 'JsonWebKey2020', controller: did,
        publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(key.publicKey, 'base64').toString('base64url') },
      }],
      assertionMethod: [key.kid],
    } : null;
  });
  const isRevoked = vi.fn(async () => ({ revoked: false }));
  const verification = createDelegationVerification({
    identity: { ...root, did: SERVER }, cryptoProvider: crypto,
    delegationConfig: {
      trustedRootIssuers: [root.did], didResolver: { resolve }, revocationChecker: { isRevoked }, ...config,
    },
  } as unknown as MiddlewareDeps);
  return { verify: verification.verifyDelegation, resolve, isRevoked };
}

/** A revocation status entry, the list it names served by whichever status resolver a test sets up. */
const STATUS_ENTRY = {
  id: 'https://status.example/1#0', type: 'StatusList2021Entry' as const,
  statusPurpose: 'revocation' as const, statusListIndex: '0', statusListCredential: 'https://status.example/1',
};

/** A credential `key` issues as `id`, naming {@link STATUS_ENTRY}, signed over it. */
async function listed(key: AgentIdentity, id: string): Promise<DelegationCredential> {
  const { proof: _proof, ...unsigned } = await credential(key, id);
  const withStatus = { ...unsigned, credentialStatus: STATUS_ENTRY };
  return { ...withStatus, proof: await signing(key)(canonicalizeJSON(withStatus), key.did, key.kid) } as DelegationCredential;
}

/** A string a substring test would have matched against any root DID that is part of it. */
const ACME_LIST = 'did:web:root.example did:web:acme.example';

describe('trustedRootIssuers at creation', () => {
  it('refuses a list that is not an array of DIDs without surrounding white space, naming the option, and takes an absent or empty one', () => {
    for (const list of [null, ACME_LIST, [''], [5], {}, ['root.example'], ['did:web:root.example ']]) {
      expect(() => setup({ trustedRootIssuers: list as unknown as string[] })).toThrow(TypeError);
      expect(() => setup({ trustedRootIssuers: list as unknown as string[] })).toThrow(
        /^\[kya-os\] delegation\.trustedRootIssuers must be an array of DIDs, each a string that starts with "did:" and has no white space around it \(got /,
      );
    }
    for (const list of [undefined, [], ['did:web:root.example']]) {
      expect(() => setup({ trustedRootIssuers: list })).not.toThrow();
    }
  });
});

describe('root admission before DID and status resolution', () => {
  it('rejects malformed time claims and inconsistent JWT issuers before resolving a DID', async () => {
    const vc = await credential(root, 'numeric-date');
    const { verify, resolve } = setup();
    for (const exp of [{ valueOf: 0, toString: 0 }, [], '9999999999']) {
      expect(await verify(await jwt(vc, root, { exp }))).toMatchObject({
        valid: false, reason: 'JWT exp must be a finite NumericDate',
      });
    }
    expect(await verify(await jwt(vc, root, { iss: outsider.did }))).toMatchObject({
      valid: false, reason: expect.stringContaining('does not match the JWT'),
    });
    expect(resolve).not.toHaveBeenCalled();
  });

  it("JWT: hands resolveDelegationChain the leaf's unverified payload, then verifies the chain it returns as before", async () => {
    const parent = await credential(root, 'good-root');
    const leaf = await credential(delegate, 'leaf', 'good-root');
    const resolveDelegationChain = vi.fn(async (_leaf: DelegationCredential) => [parent]);
    const { verify, resolve } = setup({ resolveDelegationChain });
    // Signed with an outsider's key: the envelope's signature is checked only after the chain is resolved.
    expect((await verify(await jwt(leaf, outsider))).valid).toBe(false);
    expect(resolveDelegationChain).toHaveBeenCalledOnce();
    expect(resolveDelegationChain.mock.calls[0]![0].credentialSubject.delegation).toMatchObject({ id: 'leaf', parentId: 'good-root' });
    expect(resolve.mock.calls[0]).toEqual([root.did]);
  });

  for (const form of ['object', 'JWT'] as const) {
    const wire = (vc: DelegationCredential, key: AgentIdentity) => form === 'JWT' ? jwt(vc, key) : vc;

    it(`${form}: rejects an untrusted root before any verification I/O`, async () => {
      const { verify, resolve, isRevoked } = setup();
      const result = await verify(await wire(await credential(outsider, 'untrusted'), outsider));
      expect(result).toMatchObject({ valid: false, reason: expect.stringContaining('not a trusted root issuer') });
      expect(resolve).not.toHaveBeenCalled();
      expect(isRevoked).not.toHaveBeenCalled();
    });

    it(`${form}: admits issuer.id, but still rejects a forged signature claiming a trusted issuer`, async () => {
      const { verify, resolve } = setup();
      const valid = await credential(root, 'trusted');
      expect((await verify(await wire(valid, root))).valid).toBe(true);
      const { proof: _proof, ...unsigned } = valid;
      const named = { ...unsigned, issuer: { id: root.did } };
      const proof = await signing(root)(canonicalizeJSON(named), root.did, root.kid);
      expect((await verify(await wire({ ...named, proof }, root))).valid).toBe(true);
      const forged = await credential(outsider, 'forged');
      forged.issuer = { id: root.did };
      expect((await verify(await wire(forged, outsider))).valid).toBe(false);
      expect(resolve).toHaveBeenCalledWith(root.did);
    });

    it(`${form}: does not use delegation.issuerDid as the root admission identity`, async () => {
      const { verify, resolve } = setup();
      const vc = await credential(outsider, 'false-claim');
      vc.credentialSubject.delegation.issuerDid = root.did;
      expect((await verify(await wire(vc, outsider))).valid).toBe(false);
      expect(resolve).not.toHaveBeenCalled();
    });

    it(`${form}: rejects every root with an empty allowlist; omission preserves acceptance`, async () => {
      const input = await wire(await credential(outsider, 'policy'), outsider);
      const closed = setup({ trustedRootIssuers: [] });
      expect((await closed.verify(input)).valid).toBe(false);
      expect(closed.resolve).not.toHaveBeenCalled();
      expect((await setup({ trustedRootIssuers: undefined }).verify(input)).valid).toBe(true);
    });

    it(`${form}: admits the resolved root before verifying even the leaf`, async () => {
      const parent = await credential(outsider, 'bad-root');
      const leaf = await credential(delegate, 'leaf', 'bad-root');
      const resolveDelegationChain = vi.fn(async () => [parent]);
      const { verify, resolve, isRevoked } = setup({ resolveDelegationChain });
      expect((await verify(await wire(leaf, delegate))).valid).toBe(false);
      expect(resolveDelegationChain).toHaveBeenCalledOnce();
      expect(resolve).not.toHaveBeenCalled();
      expect(isRevoked).not.toHaveBeenCalled();
    });

    it(`${form}: authenticates a permitted chain whose leaf issuer is not a trusted root`, async () => {
      const parent = await credential(root, 'good-root');
      const leaf = await credential(delegate, 'leaf', 'good-root');
      const resolveDelegationChain = vi.fn(async () => [parent]);
      const { verify, resolve, isRevoked } = setup({ resolveDelegationChain });
      expect((await verify(await wire(leaf, delegate))).valid).toBe(true);
      expect(resolveDelegationChain).toHaveBeenCalledOnce();
      expect(resolve.mock.calls.map(([did]) => did)).toEqual([root.did, delegate.did]);
      expect(isRevoked.mock.calls).toHaveLength(2);
      // A good ancestor must not turn an invalid leaf into an authenticated one.
      const bad = await credential(outsider, 'bad-leaf', 'good-root');
      bad.issuer = delegate.did;
      expect((await verify(await wire(bad, outsider))).valid).toBe(false);
    });

    it(`${form}: checks status afresh after a cached signature and refuses revocation`, async () => {
      const input = await wire(await listed(root, 'status'), root);
      const checkStatus = vi.fn(async () => false);
      const { verify, resolve } = setup({ statusListResolver: { checkStatus } });
      expect((await verify(input)).valid).toBe(true);
      expect(checkStatus).toHaveBeenCalledOnce();
      checkStatus.mockResolvedValue(true);
      expect((await verify(input)).valid).toBe(false);
      expect(checkStatus).toHaveBeenCalledTimes(2);
      expect(resolve).toHaveBeenCalledOnce();
    });

    it(`${form}: refuses a revoked leaf, and one whose status read fails, as it refuses any credential in the chain`, async () => {
      const input = await wire(await listed(root, 'listed'), root);
      const reasons: string[] = [];
      for (const checkStatus of [async () => true, async () => { throw new Error('list down'); }]) {
        const check = await setup({ statusListResolver: { checkStatus } }).verify(input);
        reasons.push(check.valid ? 'accepted' : check.reason);
      }
      expect(reasons).toEqual([
        'Delegation listed invalid: Credential revoked via "StatusList2021Entry" ("revocation")',
        'Delegation listed invalid: Status check error: list down',
      ]);
    });

    it(`${form}: refuses a resolved root that still references a parent, before any verification I/O`, async () => {
      const parent = await credential(root, 'good-root', 'gone');
      const leaf = await credential(delegate, 'leaf', 'good-root');
      const { verify, resolve, isRevoked } = setup({ resolveDelegationChain: async () => [parent] });
      expect(await verify(await wire(leaf, delegate))).toMatchObject({
        valid: false, reason: 'Resolved delegation chain is incomplete: root delegation good-root still references parent gone',
      });
      expect(resolve).not.toHaveBeenCalled();
      expect(isRevoked).not.toHaveBeenCalled();
    });

    it(`${form}: caps the chain before resolving any signing key`, async () => {
      const parent = await credential(root, 'good-root');
      const leaf = await credential(delegate, 'leaf', 'good-root');
      const { verify, resolve } = setup({ maxChainLength: 1, resolveDelegationChain: async () => [parent] });
      expect(await verify(await wire(leaf, delegate))).toMatchObject({ valid: false, reason: expect.stringContaining('exceeds the maximum') });
      expect(resolve).not.toHaveBeenCalled();
    });
  }
});
