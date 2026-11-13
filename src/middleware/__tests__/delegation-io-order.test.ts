/**
 * The order of the gate's I/O for a presented chain: the chain's linkage first, then the root's
 * issuer against `trustedRootIssuers`, then each credential's signature, root first, and only then
 * that credential's status list. A credential that only names a trusted issuer, or a parent it does
 * not descend from, costs no status read, and a linkage failure costs no DID resolution at all.
 */

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
import type { CredentialStatus, DelegationCredential } from '../../types/protocol.js';

const crypto = new NodeCryptoProvider();
const SERVER = 'did:web:server.example';
const ATTACKER_LIST = 'https://attacker.example/list';
let root: AgentIdentity, delegate: AgentIdentity, attacker: AgentIdentity;
beforeAll(async () => {
  const identity = async (name: string) => ({
    ...await crypto.generateKeyPair(), type: 'development' as const, createdAt: new Date().toISOString(),
    did: `did:web:${name}.example`, kid: `did:web:${name}.example#key`,
  });
  [root, delegate, attacker] = await Promise.all([identity('root'), identity('delegate'), identity('attacker')]);
});

const statusEntry: CredentialStatus = {
  id: `${ATTACKER_LIST}#0`, type: 'StatusList2021Entry', statusPurpose: 'revocation',
  statusListIndex: '0', statusListCredential: ATTACKER_LIST,
};

function signing(key: AgentIdentity): VCSigningFunction {
  return async (canonical, _issuer, kid) => ({
    type: 'Ed25519Signature2020', created: new Date().toISOString(),
    verificationMethod: kid, proofPurpose: 'assertionMethod',
    proofValue: Buffer.from(await crypto.sign(new TextEncoder().encode(canonical), key.privateKey)).toString('base64url'),
  });
}

/** A credential `key` issues to `subject`, as `issuerDid` claims; `parentId` makes it a re-delegation. */
async function credential(
  key: AgentIdentity, id: string, subject: string, parentId?: string, issuerDid = key.did,
): Promise<DelegationCredential> {
  return new DelegationCredentialIssuer(
    { getDid: () => key.did, getKeyId: () => key.kid, getPrivateKey: () => key.privateKey },
    signing(key),
  ).issueDelegationCredential({
    id, issuerDid, subjectDid: subject, vcId: `urn:uuid:${id}`,
    ...(parentId === undefined ? {} : { parentId }),
    constraints: { scopes: ['tools:read'], audience: SERVER, notAfter: Math.floor(Date.now() / 1000) + 3600 },
    signature: '', status: 'active', createdAt: Date.now(),
  });
}

/** `vc` with `changes` applied, re-signed by `signer` under `kid`: a valid proof only when `signer` is the issuer. */
async function resigned(vc: DelegationCredential, changes: Partial<DelegationCredential>, signer: AgentIdentity, kid: string) {
  const { proof: _proof, ...unsigned } = vc;
  const changed = { ...unsigned, ...changes } as DelegationCredential;
  return { ...changed, proof: await signing(signer)(canonicalizeJSON(changed), signer.did, kid) } as DelegationCredential;
}

/** `vc` as a compact VC-JWT signed by `signer` under `kid`. */
async function jwt(vc: DelegationCredential, signer: AgentIdentity, kid: string): Promise<string> {
  const { proof: _proof, ...unsigned } = vc;
  const { payload } = createUnsignedVCJWT(unsigned);
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid })).toString('base64url');
  const input = `${header}.${encodedPayload}`;
  const signature = await crypto.sign(new TextEncoder().encode(input), signer.privateKey);
  return completeVCJWT(input, Buffer.from(signature).toString('base64url'));
}

function gate(config: KyaOsDelegationConfig = {}) {
  const resolve = vi.fn(async (did: string): Promise<DIDDocument | null> => {
    const key = [root, delegate, attacker].find(candidate => candidate.did === did);
    return key ? {
      id: did,
      verificationMethod: [{
        id: key.kid, type: 'JsonWebKey2020', controller: did,
        publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(key.publicKey, 'base64').toString('base64url') },
      }],
      assertionMethod: [key.kid],
    } : null;
  });
  const checkStatus = vi.fn(async () => false);
  const verification = createDelegationVerification({
    identity: { ...root, did: SERVER }, cryptoProvider: crypto,
    delegationConfig: { trustedRootIssuers: [root.did], didResolver: { resolve }, statusListResolver: { checkStatus }, ...config },
  } as unknown as MiddlewareDeps);
  return { verify: verification.verifyDelegation, resolve, checkStatus };
}

for (const form of ['object', 'JWT'] as const) {
  /** `vc` on the wire as this form presents it, signed by `signer` under `kid`. */
  const wire = async (vc: DelegationCredential, signer: AgentIdentity, kid: string) =>
    form === 'JWT' ? jwt(vc, signer, kid) : resigned(vc, {}, signer, kid);

  describe(`${form}: a status list is read only for a credential whose signature verified`, () => {
    it('reads none for a root that names the trusted issuer but is signed by another key', async () => {
      const named = await resigned(await credential(attacker, 'forged-root', delegate.did), { issuer: root.did, credentialStatus: statusEntry }, attacker, root.kid);
      const { verify, resolve, checkStatus } = gate();
      expect(await verify(await wire(named, attacker, root.kid))).toMatchObject({ valid: false });
      expect(resolve.mock.calls.map(([did]) => did)).toEqual([root.did]);
      expect(checkStatus).not.toHaveBeenCalled();
    });

    it("reads none for a leaf that names its parent's subject but is signed by another key", async () => {
      const parent = await credential(root, 'good-root', delegate.did);
      const leaf = await resigned(
        await credential(delegate, 'forged-leaf', attacker.did, 'good-root'), { credentialStatus: statusEntry }, attacker, delegate.kid,
      );
      const { verify, resolve, checkStatus } = gate({ resolveDelegationChain: async () => [parent] });
      expect(await verify(await wire(leaf, attacker, delegate.kid))).toMatchObject({ valid: false });
      expect(resolve.mock.calls.map(([did]) => did)).toEqual([root.did, delegate.did]);
      expect(checkStatus).not.toHaveBeenCalled();
    });

    it('reads it once the signature verified', async () => {
      const valid = await resigned(await credential(root, 'live-root', delegate.did), { credentialStatus: statusEntry }, root, root.kid);
      const { verify, checkStatus } = gate();
      expect(await verify(await wire(valid, root, root.kid))).toMatchObject({ valid: true });
      expect(checkStatus).toHaveBeenCalledOnce();
    });
  });

  describe(`${form}: the chain's linkage is checked before any DID resolution`, () => {
    it('refuses a leaf whose issuerDid is not its parent\'s subject, resolving nothing and reading no status', async () => {
      const parent = await credential(root, 'good-root', delegate.did);
      const leaf = await resigned(await credential(attacker, 'evil-leaf', delegate.did, 'good-root'), { credentialStatus: statusEntry }, attacker, attacker.kid);
      const { verify, resolve, checkStatus } = gate({ resolveDelegationChain: async () => [parent] });
      expect(await verify(await wire(leaf, attacker, attacker.kid))).toMatchObject({
        valid: false, reason: `Delegation evil-leaf issued by ${attacker.did} but parent subject is ${delegate.did}`,
      });
      expect(resolve).not.toHaveBeenCalled();
      expect(checkStatus).not.toHaveBeenCalled();
    });

    it("refuses a leaf that claims the parent's subject as issuerDid but names another issuer", async () => {
      const parent = await credential(root, 'good-root', delegate.did);
      const leaf = await resigned(
        await credential(attacker, 'claiming-leaf', delegate.did, 'good-root', delegate.did),
        { issuer: attacker.did, credentialStatus: statusEntry }, attacker, attacker.kid,
      );
      const { verify, resolve, checkStatus } = gate({ resolveDelegationChain: async () => [parent] });
      expect(await verify(await wire(leaf, attacker, attacker.kid))).toMatchObject({
        valid: false, reason: `Delegation claiming-leaf is signed by ${attacker.did} but parent subject is ${delegate.did}`,
      });
      expect(resolve).not.toHaveBeenCalled();
      expect(checkStatus).not.toHaveBeenCalled();
    });

    it('refuses a leaf whose parentId is not the credential before it', async () => {
      const parent = await credential(root, 'good-root', delegate.did);
      const leaf = await credential(delegate, 'orphan-leaf', attacker.did, 'other-root');
      const { verify, resolve } = gate({ resolveDelegationChain: async () => [parent] });
      expect(await verify(await wire(leaf, delegate, delegate.kid))).toMatchObject({
        valid: false, reason: 'Delegation orphan-leaf references parent other-root but expected good-root',
      });
      expect(resolve).not.toHaveBeenCalled();
    });
  });
}
