/**
 * What the request-binding and parent-commitment vectors (SPEC.md §6.2, §7.8, suite 1.13.0) are
 * minted with: FIXED test-only parties, the suite's fixed time, and credentials and request proofs
 * signed as the package signs them. Ed25519 signs deterministically, so the generator
 * (./request-binding-vectors.ts) writes byte-identical files on every run.
 */

import { generateRequestProof, type DelegationCredential, type DetachedProof, type ReceivedCredential } from '../src/index.js';
import { extractPublicKeyFromDidKey, publicKeyToJwk } from '../src/delegation/did-key-resolver.js';
import { NodeCryptoProvider } from '../src/providers/node-crypto.js';
import { jwsProtectedHeader } from '../src/utils/crypto-service.js';
import { signedDelegation, type SignedDelegationArgs } from './credential-kit.js';
import { ed25519VerificationMethod, fixedParty, signProofMeta, type KeyedParty } from './crypto-kit.js';
import type { SignedProofInput } from './types.js';

export const crypto = new NodeCryptoProvider();
/** The suite's fixed time, in epoch seconds: every proof is signed at it and verified at it. */
export const NOW = 1_750_000_000;
/** The server every call is addressed to, and every credential is bound to. */
export const SERVER_DID = 'did:web:server.example.com';

/** The user that delegates, the agent it delegates to, and the sub-agent that agent delegates to. */
export const USER = fixedParty('org.kya-os/conformance/request-binding/user');
export const AGENT = fixedParty('org.kya-os/conformance/request-binding/agent');
export const SUB_AGENT = fixedParty('org.kya-os/conformance/request-binding/sub-agent');

/** The call every request proof is of: the tool, and the business arguments its hash covers. */
export const TOOL = 'records.read';
export const ARGUMENTS = { recordId: 'r-1' };
/** The same call as the server receives it. */
export const REQUEST = { method: 'tools/call', params: { name: TOOL, arguments: ARGUMENTS } };

/** A delegation bound to the server, signed by its issuer at the suite's fixed time. */
export function credential(args: Omit<SignedDelegationArgs, 'audience'>): Promise<DelegationCredential> {
  return signedDelegation(crypto, { ...args, audience: SERVER_DID }, NOW);
}

/** The DID document of a did:key party, as the vectors give a verifier one. */
export function didDocumentOf(party: KeyedParty): Record<string, unknown> {
  return {
    id: party.did,
    verificationMethod: [ed25519VerificationMethod(party.kid, party.did, extractPublicKeyFromDidKey(party.did)!)],
    assertionMethod: [party.kid],
    authentication: [party.kid],
  };
}

/** `meta` of the agent's request proof, signed at the suite's fixed time under `header`. */
function signedAtNow(draft: DetachedProof, nonce: string, header: Record<string, unknown> | string): Promise<DetachedProof> {
  return signProofMeta(AGENT, { ...draft.meta, ts: NOW, nonce }, header);
}

/**
 * The agent's request proof for the call, made by the package's own generator for the arguments the
 * call sends: `delegation` among them when it is a credential, and none when it is `null`. The
 * generator signs at the time it runs, so what it made is signed again at the suite's fixed time,
 * under the protected header the generator wrote.
 */
export async function requestProof(delegation: ReceivedCredential | null, nonce: string): Promise<DetachedProof> {
  const draft = await generateRequestProof({
    identity: AGENT,
    crypto,
    toolName: TOOL,
    args: delegation === null ? ARGUMENTS : { ...ARGUMENTS, _kyaos_delegation: delegation },
    audience: SERVER_DID,
    sessionId: 'sess_request_binding',
  });
  return signedAtNow(draft, nonce, jwsProtectedHeader(draft.jws));
}

/**
 * The same proof signed under another protected header: `header(own)`, given the `alg` and `kid`
 * the generator writes. A string is signed as that text.
 */
export async function requestProofUnder(
  nonce: string,
  header: (own: { alg: string; kid: string }) => Record<string, unknown> | string,
  meta: Partial<DetachedProof['meta']> = {},
): Promise<DetachedProof> {
  const draft = await requestProof(null, nonce);
  return signedAtNow({ ...draft, meta: { ...draft.meta, ...meta } }, nonce, header({ alg: 'EdDSA', kid: AGENT.kid }));
}

/** `proof` with the protected header of its JWS replaced after signing, so its signature no longer covers it. */
export function withHeaderReplaced(proof: DetachedProof, header: Record<string, unknown>): DetachedProof {
  const [, payload, signature] = proof.jws.split('.');
  return { ...proof, jws: `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${payload}.${signature}` };
}

/** A vector's input: the agent's `proof`, verified with its key at the suite's fixed time, beside `presented`. */
export function inputOf(
  proof: DetachedProof,
  presented: ReceivedCredential | null,
  requestBinding?: 'require',
): SignedProofInput {
  return {
    proof,
    publicKeyJwk: { ...publicKeyToJwk(extractPublicKeyFromDidKey(AGENT.did)!), kid: AGENT.kid },
    now: NOW,
    skewSeconds: 300,
    expected: {
      request: REQUEST,
      presentedDelegation: presented,
      ...(requestBinding === undefined ? {} : { requestBinding }),
    },
  };
}
