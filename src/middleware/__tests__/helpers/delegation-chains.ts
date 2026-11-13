/**
 * Test helper: delegation chains to present to a server, as credential
 * objects and as VC-JWTs, and the digest a proof binds each by.
 */
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { digestDelegationChain, type ReceivedCredential } from '../../../delegation/chain-digest.js';
import type { DelegationCredential } from '../../../types/protocol.js';
import { base64urlDecodeToBytes, bytesToBase64 } from '../../../utils/base64.js';
import { generateDidKeyFromBase64 } from '../../../utils/did-helpers.js';
import { hash } from './delegation-gate-server.js';
import { SCOPE } from './delegated-call.js';
import { delegate, party } from './delegating-party.js';

/** User to orchestrator to agent to sub-agent: three credentials, the last one presented. */
export async function threeHops(serverDid: string, leafScopes: string[] = [SCOPE]) {
  const [user, orchestrator, agent, subAgent] = await Promise.all([party(), party(), party(), party()]);
  const root = await delegate(user, orchestrator.did, { scopes: [SCOPE, 'records:list'] });
  const middle = await delegate(orchestrator, agent.did, { parent: root, audience: serverDid });
  const leaf = await delegate(agent, subAgent.did, {
    parent: middle,
    audience: serverDid,
    scopes: leafScopes,
  });
  return { user, orchestrator, agent, subAgent, root, middle, leaf, chain: [root, middle, leaf] };
}

/** A chain of `length` credentials, each party delegating to the next, root first. */
export async function linearChain(length: number, serverDid: string): Promise<DelegationCredential[]> {
  const parties = await Promise.all(Array.from({ length: length + 1 }, () => party()));
  const chain: DelegationCredential[] = [await delegate(parties[0]!, parties[1]!.did)];
  for (let hop = 1; hop < length; hop += 1) {
    chain.push(await delegate(parties[hop]!, parties[hop + 1]!.did, {
      parent: chain[hop - 1]!,
      audience: serverDid,
    }));
  }
  return chain;
}

/** One hop a {@link jwtParty} signs. */
export interface JwtHop {
  /** The credential's own id, which a VC-JWT need not carry. */
  id?: string;
  delegationId: string;
  /** Whom the hop delegates to: the party itself unless it is given. */
  subject?: string;
  parent?: DelegationCredential;
  audience?: string;
  metadata?: Record<string, unknown>;
  /** Claims the payload carries beside `vc`. */
  claims?: Record<string, unknown>;
  jti?: string;
}

/**
 * A party that signs its hops as VC-JWTs, with a key a JWS library made: a
 * CryptoKey, where a {@link party} signs with a key of its own.
 */
export async function jwtParty() {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { extractable: true });
  const did = generateDidKeyFromBase64(bytesToBase64(base64urlDecodeToBytes((await exportJWK(publicKey)).x!)));
  /** The VC-JWT of `hop`, which delegates SCOPE. */
  const issue = (hop: JwtHop): Promise<string> => {
    const subject = hop.subject ?? did;
    const jwt = new SignJWT({
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        ...(hop.id === undefined ? {} : { id: hop.id }),
        type: ['VerifiableCredential', 'DelegationCredential'],
        issuer: did,
        issuanceDate: '2026-01-01T00:00:00.000Z',
        expirationDate: '2099-01-01T00:00:00.000Z',
        credentialSubject: {
          id: subject,
          delegation: {
            id: hop.delegationId,
            issuerDid: did,
            subjectDid: subject,
            ...(hop.parent ? { parentId: hop.parent.credentialSubject.delegation.id } : {}),
            status: 'active',
            constraints: {
              scopes: [SCOPE],
              ...(hop.audience === undefined ? {} : { audience: hop.audience }),
              notAfter: Math.floor(Date.now() / 1000) + 3600,
            },
            ...(hop.metadata === undefined ? {} : { metadata: hop.metadata }),
          },
        },
      },
      ...hop.claims,
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
      .setIssuer(did)
      .setSubject(subject);
    if (hop.jti !== undefined) jwt.setJti(hop.jti);
    return jwt.setIssuedAt().sign(privateKey);
  };
  return { did, issue };
}

/** The digest a proof binds `chain` by. */
export const chainDigestOf = async (chain: readonly ReceivedCredential[]) =>
  (await digestDelegationChain(chain, hash)).chain;
