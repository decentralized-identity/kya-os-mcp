/**
 * Test helper: response proofs over one request and response, binding a
 * delegation chain (SPEC.md §7.8) an auditor holds, and a verifier to hold
 * them to it.
 */
import { decodeJwt } from "jose";
import {
  ProofGenerator,
  type ProofAgentIdentity,
  type ProofOptions,
  type ToolRequest,
  type ToolResponse,
} from "../../generator.js";
import { ProofVerifier } from "../../verifier.js";
import type { DetachedProof, SessionContext } from "../../../types/protocol.js";
import { digestDelegationChain, type ReceivedCredential } from "../../../delegation/chain-digest.js";
import { publicKeyToJwk } from "../../../delegation/did-key-resolver.js";
import { base64url, compactJwt } from "../../../__tests__/utils/encodings.js";
import { nodeCrypto, nodeHash } from "../../../__tests__/utils/node-crypto-provider.js";
import { base64ToBytes } from "../../../utils/base64.js";
import type { Ed25519JWK } from "../../../utils/crypto-service.js";
import {
  RealClockProvider,
  RealFetchProvider,
  MemoryNonceCacheProvider,
} from "../../../__tests__/audit/helpers/crypto-helpers.js";

export const REQUEST: ToolRequest = { method: "records.read", params: { recordId: "r-1" } };
export const RESPONSE: ToolResponse = { data: [{ type: "text", text: "released" }] };

/** A compact VC-JWT with `claims` for its payload. Nothing here checks its signature. */
export const jwt = (claims: unknown, signature = "bGVhZg"): string =>
  compactJwt(base64url(JSON.stringify(claims)), signature);

/** A three-hop chain, as an auditor would hold it: two credential objects and a VC-JWT leaf. */
export const ROOT = { id: "urn:uuid:root", issuer: "did:web:user.example", proof: { proofValue: "cm9vdA" } };
export const MIDDLE = { id: "urn:uuid:middle", issuer: "did:web:orchestrator.example", proof: { proofValue: "bWlk" } };
export const LEAF = jwt({ vc: { id: "urn:uuid:leaf" } });
export const CHAIN = [ROOT, MIDDLE, LEAF] as const;

export async function makeIdentity(): Promise<ProofAgentIdentity> {
  const keyPair = await nodeCrypto.generateKeyPair();
  return {
    did: "did:web:vault.example",
    kid: "did:web:vault.example#key-1",
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
  };
}

export function makeSession(): SessionContext {
  const now = Math.floor(Date.now() / 1000);
  return {
    sessionId: "sess_binding",
    audience: "did:web:vault.example",
    nonce: "nonce",
    timestamp: now,
    createdAt: now,
    lastActivity: now,
    ttlMinutes: 30,
    identityState: "anonymous",
  };
}

/** The key a verifier holds for `identity`, as a JWK. */
export const jwkFor = (identity: ProofAgentIdentity): Ed25519JWK =>
  ({ ...publicKeyToJwk(base64ToBytes(identity.publicKey)), kid: identity.kid }) as Ed25519JWK;

/** A verifier with replay state and a clock, that hashes with `provider`. */
export function makeVerifier(provider: typeof nodeCrypto = nodeCrypto): ProofVerifier {
  return new ProofVerifier({
    cryptoProvider: provider,
    clockProvider: new RealClockProvider(),
    nonceCacheProvider: new MemoryNonceCacheProvider(),
    fetchProvider: new RealFetchProvider(),
  });
}

/** A proof over REQUEST and, unless it `binds` nothing (a denial), RESPONSE. */
export async function signed(options: ProofOptions = {}, binds: "response" | "nothing" = "response") {
  const identity = await makeIdentity();
  const proof = await new ProofGenerator(identity, nodeCrypto).generateProof(
    REQUEST,
    binds === "response" ? RESPONSE : undefined,
    makeSession(),
    options,
  );
  return { proof, jwk: jwkFor(identity) };
}

/** The same, binding the digest of `chain`, and naming what `options` says. */
export async function boundTo(
  chain: readonly ReceivedCredential[],
  options: ProofOptions = {},
  binds: "response" | "nothing" = "response",
) {
  const digests = await digestDelegationChain(chain, nodeHash);
  return signed({ delegationChainDigest: digests.chain, ...options }, binds);
}

/** The same, naming CHAIN's leaf and binding CHAIN's digest. */
export const bound = (options: ProofOptions = {}, binds: "response" | "nothing" = "response") =>
  boundTo(CHAIN, { delegationRef: "urn:uuid:leaf", ...options }, binds);

/** The claims a proof's JWS signs. */
export const payloadOf = (proof: DetachedProof): Record<string, unknown> => decodeJwt(proof.jws);
