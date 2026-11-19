/**
 * Test helper: request proofs as a holder makes them, and as a party on the path can remake them
 * without the holder's key.
 */
import { MemoryNonceCacheProvider, RealClockProvider, RealFetchProvider } from '../../../__tests__/audit/helpers/crypto-helpers.js';
import { nodeCrypto as crypto } from '../../../__tests__/utils/node-crypto-provider.js';
import { ProofGenerator, PROTECTED_HEADER_PARAMETERS, type InternalProofOptions, type ProofAgentIdentity } from '../../../proof/generator.js';
import { ProofVerifier } from '../../../proof/verifier.js';
import type { DetachedProof } from '../../../types/protocol.js';
import { toHolderBindingRequest } from '../../holder-binding.js';
import { DELEGATION_HEADER_PARAMETER } from '../../stated-delegation.js';

export const AUDIENCE = 'did:web:server.example.com';
export const TOOL = 'payments.send';
export const ARGS = { amount: 100, to: 'acct-7' };
export const hash = (bytes: Uint8Array): Promise<string> => crypto.hash(bytes);

/** A verifier with a replay cache of its own. */
export const proofVerifier = (): ProofVerifier =>
  new ProofVerifier({
    cryptoProvider: crypto,
    clockProvider: new RealClockProvider(),
    nonceCacheProvider: new MemoryNonceCacheProvider(),
    fetchProvider: new RealFetchProvider(),
    timestampSkewSeconds: 300,
  });

/**
 * A request proof of `holder`'s over {@link TOOL} and {@link ARGS} whose protected header states
 * `statement` as it is given, well formed or not, or states nothing for `undefined`, as a proof made
 * before the parameter existed does. `payload` adds the signed members a proof may also name its
 * delegation by.
 */
export async function proofStating(
  holder: ProofAgentIdentity,
  statement: string | undefined,
  payload: { delegationRef?: string | undefined; delegationChainDigest?: string | undefined } = {},
  audience: string = AUDIENCE,
): Promise<DetachedProof> {
  const now = Math.floor(Date.now() / 1000);
  const options: InternalProofOptions = {
    ...(payload.delegationRef === undefined ? {} : { delegationRef: payload.delegationRef }),
    ...(payload.delegationChainDigest === undefined ? {} : { delegationChainDigest: payload.delegationChainDigest }),
    [PROTECTED_HEADER_PARAMETERS]: statement === undefined ? {} : { [DELEGATION_HEADER_PARAMETER]: statement },
  };
  return new ProofGenerator(holder, crypto).generateProof(
    toHolderBindingRequest(TOOL, ARGS),
    undefined,
    {
      sessionId: `req-${Math.random().toString(36).slice(2)}`,
      audience,
      nonce: 'unused',
      timestamp: now,
      createdAt: now,
      lastActivity: now,
      ttlMinutes: 30,
      identityState: 'anonymous',
    },
    options,
  );
}

/**
 * `proof` with `changes` made to its protected header, a member set to `undefined` being removed,
 * and its payload and signature left as they were: all a party without the key can do.
 */
export function withHeader(proof: DetachedProof, changes: Record<string, unknown>): DetachedProof {
  const [header, payload, signature] = proof.jws.split('.') as [string, string, string];
  const read = JSON.parse(Buffer.from(header, 'base64url').toString('utf8')) as Record<string, unknown>;
  const written = Buffer.from(JSON.stringify({ ...read, ...changes })).toString('base64url');
  return { ...proof, jws: `${written}.${payload}.${signature}` };
}
