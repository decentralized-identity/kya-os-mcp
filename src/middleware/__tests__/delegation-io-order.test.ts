/**
 * The order of the gate's I/O for a presented chain: the chain's linkage first, then the root's
 * issuer against `trustedRootIssuers`, then the presented credential's signature, then each
 * ancestor's, root first, and each credential's status list only once its signature verified. A
 * credential that only names a trusted issuer, or a parent it does not descend from, costs no
 * status read, a presented credential its parent's subject did not sign costs no ancestor's
 * verification, and a linkage failure costs no DID resolution at all.
 */

import { beforeAll, describe, expect, it, vi } from 'vitest';
import { createDelegationVerification } from '../with-kya-os.delegation-verify.js';
import type { MiddlewareDeps } from '../with-kya-os.deps.js';
import type { KyaOsDelegationConfig } from '../with-kya-os.config-types.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import {
  credentialJwt, delegationRecord, keyOf, resignedCredential, signedCredential,
} from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import type { AgentIdentity } from '../../providers/base.js';
import type { DIDDocument } from '../../delegation/vc-verifier.js';
import type { CredentialStatus, DelegationCredential } from '../../types/protocol.js';
import { WITHHELD_SUFFIX } from '../../utils/thrown-words.js';

const crypto = new NodeCryptoProvider();
const SERVER = 'did:web:server.example';
const ATTACKER_LIST = 'https://attacker.example/list';
let root: AgentIdentity, delegate: AgentIdentity, attacker: AgentIdentity;
beforeAll(async () => {
  const key = (name: string) => keyOf(`did:web:${name}.example`, 'key');
  [root, delegate, attacker] = await Promise.all([key('root'), key('delegate'), key('attacker')]);
});

const statusEntry: CredentialStatus = {
  id: `${ATTACKER_LIST}#0`, type: 'StatusList2021Entry', statusPurpose: 'revocation',
  statusListIndex: '0', statusListCredential: ATTACKER_LIST,
};

/** A credential `key` signs to `subject`, as `issuerDid` claims; `parentId` makes it a re-delegation. */
function credential(
  key: AgentIdentity, id: string, subject: string, parentId?: string, issuerDid = key.did,
): Promise<DelegationCredential> {
  return signedCredential(key, {
    record: delegationRecord(issuerDid, {
      id, subjectDid: subject, vcId: `urn:uuid:${id}`,
      ...(parentId === undefined ? {} : { parentId }),
      constraints: { scopes: ['tools:read'], audience: SERVER, notAfter: Math.floor(Date.now() / 1000) + 3600 },
    }),
  });
}

function gate(config: KyaOsDelegationConfig = {}) {
  const resolve = vi.fn(async (did: string): Promise<DIDDocument | null> => {
    const key = [root, delegate, attacker].find(candidate => candidate.did === did);
    return key ? issuerDidDocument(methodOf(key)) : null;
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
    form === 'JWT' ? credentialJwt(vc, signer, { kid }) : resignedCredential(vc, {}, signer, kid);

  describe(`${form}: a status list is read only for a credential whose signature verified`, () => {
    it('reads none for a root that names the trusted issuer but is signed by another key', async () => {
      const named = await resignedCredential(await credential(attacker, 'forged-root', delegate.did, undefined, root.did), { credentialStatus: statusEntry }, attacker, root.kid);
      const { verify, resolve, checkStatus } = gate();
      expect(await verify(await wire(named, attacker, root.kid))).toMatchObject({ valid: false });
      expect(resolve.mock.calls.map(([did]) => did)).toEqual([root.did]);
      expect(checkStatus).not.toHaveBeenCalled();
    });

    it("reads none, and verifies no ancestor, for a leaf that names its parent's subject but is signed by another key", async () => {
      const parent = await credential(root, 'good-root', delegate.did);
      const leaf = await resignedCredential(
        await credential(delegate, 'forged-leaf', attacker.did, 'good-root'), { credentialStatus: statusEntry }, attacker, delegate.kid,
      );
      const { verify, resolve, checkStatus } = gate({ resolveDelegationChain: async () => [parent] });
      expect(await verify(await wire(leaf, attacker, delegate.kid))).toMatchObject({ valid: false });
      expect(resolve.mock.calls.map(([did]) => did)).toEqual([delegate.did]);
      expect(checkStatus).not.toHaveBeenCalled();
    });

    it('reads it once the signature verified', async () => {
      const valid = await resignedCredential(await credential(root, 'live-root', delegate.did), { credentialStatus: statusEntry }, root, root.kid);
      const { verify, checkStatus } = gate();
      expect(await verify(await wire(valid, root, root.kid))).toMatchObject({ valid: true });
      expect(checkStatus).toHaveBeenCalledOnce();
    });
  });

  describe(`${form}: the chain's linkage is checked before any DID resolution`, () => {
    it('refuses a leaf whose issuerDid is not its parent\'s subject, resolving nothing and reading no status', async () => {
      const parent = await credential(root, 'good-root', delegate.did);
      const leaf = await resignedCredential(await credential(attacker, 'evil-leaf', delegate.did, 'good-root'), { credentialStatus: statusEntry }, attacker, attacker.kid);
      const { verify, resolve, checkStatus } = gate({ resolveDelegationChain: async () => [parent] });
      expect(await verify(await wire(leaf, attacker, attacker.kid))).toMatchObject({
        valid: false, reason: `Delegation "evil-leaf" issued by "${attacker.did}" is not a re-delegation by the subject of parent "good-root"${WITHHELD_SUFFIX}`,
      });
      expect(resolve).not.toHaveBeenCalled();
      expect(checkStatus).not.toHaveBeenCalled();
    });

    it("refuses a leaf that claims the parent's subject as issuerDid but names another issuer", async () => {
      const parent = await credential(root, 'good-root', delegate.did);
      const leaf = await resignedCredential(
        await credential(attacker, 'claiming-leaf', delegate.did, 'good-root', delegate.did),
        { issuer: attacker.did, credentialStatus: statusEntry }, attacker, attacker.kid,
      );
      const { verify, resolve, checkStatus } = gate({ resolveDelegationChain: async () => [parent] });
      expect(await verify(await wire(leaf, attacker, attacker.kid))).toMatchObject({
        valid: false, reason: `Delegation "claiming-leaf" is signed by "${attacker.did}", not by the subject of parent "good-root"${WITHHELD_SUFFIX}`,
      });
      expect(resolve).not.toHaveBeenCalled();
      expect(checkStatus).not.toHaveBeenCalled();
    });

    it('refuses a leaf whose parentId is not the credential before it', async () => {
      const parent = await credential(root, 'good-root', delegate.did);
      const leaf = await credential(delegate, 'orphan-leaf', attacker.did, 'other-root');
      const { verify, resolve } = gate({ resolveDelegationChain: async () => [parent] });
      expect(await verify(await wire(leaf, delegate, delegate.kid))).toMatchObject({
        valid: false, reason: `Delegation "orphan-leaf" references parent "other-root", which its resolved chain does not end with${WITHHELD_SUFFIX}`,
      });
      expect(resolve).not.toHaveBeenCalled();
    });
  });
}
