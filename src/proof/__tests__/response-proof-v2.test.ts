/**
 * Response proof profile v2 (`org.kya-os/response-proof.v2`) — envelope coverage.
 *
 * v1 binds `responseHash` over the response BODY only (`response.data` = the MCP
 * `content` array), leaving result members like `structuredContent`, `isError`,
 * and `resultType` unauthenticated. v2 closes that gap: `response.data` carries
 * the ENTIRE MCP result object and hashing covers it with the top-level `_meta`
 * member removed (mirroring the request side's `{method, params minus _meta}`
 * rule). The profile is discriminated by a signature-covered `prf` claim, so a
 * v2 proof cannot be silently downgraded to v1 semantics.
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  ProofGenerator,
  computeCanonicalHashes,
  buildProofJwsPayload,
  RESPONSE_PROOF_PROFILE_V2,
  type ToolRequest,
  type ToolResponse,
  type ProofAgentIdentity,
} from "../generator.js";
import { ProofVerifier } from "../verifier.js";
import { PROOF_VERIFICATION_ERROR_CODES } from "../errors.js";
import { validateDetachedProof, type SessionContext } from "../../types/protocol.js";
import { NodeCryptoProvider } from "../../__tests__/utils/node-crypto-provider.js";
import { canonicalize } from "json-canonicalize";
import type { Ed25519JWK } from "../../utils/crypto-service.js";
import {
  RealClockProvider,
  RealFetchProvider,
  MemoryNonceCacheProvider,
} from "../../__tests__/audit/helpers/crypto-helpers.js";

const cryptoProvider = new NodeCryptoProvider();

async function makeIdentity(): Promise<ProofAgentIdentity> {
  const keyPair = await cryptoProvider.generateKeyPair();
  return {
    did: "did:web:example.com:agents:test-agent",
    kid: "key-test-123",
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
  };
}

function makeSession(): SessionContext {
  return {
    sessionId: "sess_test_123",
    audience: "example.com",
    nonce: "test-nonce-456",
    timestamp: Math.floor(Date.now() / 1000),
    createdAt: Math.floor(Date.now() / 1000),
    lastActivity: Math.floor(Date.now() / 1000),
    ttlMinutes: 30,
    identityState: "anonymous",
  };
}

function jwkFor(identity: ProofAgentIdentity): Ed25519JWK {
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: Buffer.from(identity.publicKey, "base64").toString("base64url"),
    kid: identity.kid,
  };
}

function makeVerifier(): ProofVerifier {
  return new ProofVerifier({
    cryptoProvider,
    clockProvider: new RealClockProvider(),
    nonceCacheProvider: new MemoryNonceCacheProvider(),
    fetchProvider: new RealFetchProvider(),
  });
}

const REQUEST: ToolRequest = {
  method: "tools/call",
  params: { name: "echo", arguments: { msg: "hi" } },
};

/** A full MCP result envelope with members OUTSIDE the v1-covered content array. */
const RESULT_ENVELOPE = {
  content: [{ type: "text", text: "hi" }],
  structuredContent: { msg: "hi" },
  isError: false,
  resultType: "complete",
  _meta: { "io.modelcontextprotocol/trace": "abc" },
};

describe("computeCanonicalHashes — profile selection", () => {
  const hash = (bytes: Uint8Array) => cryptoProvider.hash(bytes);

  it("v1 (default) hashes response.data exactly as before", async () => {
    const response: ToolResponse = { data: RESULT_ENVELOPE.content };
    const { responseHash } = await computeCanonicalHashes(REQUEST, response, hash);
    const expected = await cryptoProvider.hash(
      new TextEncoder().encode(canonicalize(RESULT_ENVELOPE.content)),
    );
    expect(responseHash).toBe(expected);
  });

  it("v2 hashes the full envelope with top-level _meta removed", async () => {
    const response: ToolResponse = { data: RESULT_ENVELOPE };
    const { responseHash } = await computeCanonicalHashes(
      REQUEST,
      response,
      hash,
      RESPONSE_PROOF_PROFILE_V2,
    );
    const { _meta: _stripped, ...envelope } = RESULT_ENVELOPE;
    const expected = await cryptoProvider.hash(
      new TextEncoder().encode(canonicalize(envelope)),
    );
    expect(responseHash).toBe(expected);
  });

  it("v2 hash changes when structuredContent changes (v1's blind spot)", async () => {
    const a = await computeCanonicalHashes(
      REQUEST,
      { data: RESULT_ENVELOPE },
      hash,
      RESPONSE_PROOF_PROFILE_V2,
    );
    const b = await computeCanonicalHashes(
      REQUEST,
      { data: { ...RESULT_ENVELOPE, structuredContent: { msg: "TAMPERED" } } },
      hash,
      RESPONSE_PROOF_PROFILE_V2,
    );
    expect(a.responseHash).not.toBe(b.responseHash);
  });

  it("v2 hash is invariant to _meta mutation (intermediary-mutable real estate)", async () => {
    const a = await computeCanonicalHashes(
      REQUEST,
      { data: RESULT_ENVELOPE },
      hash,
      RESPONSE_PROOF_PROFILE_V2,
    );
    const b = await computeCanonicalHashes(
      REQUEST,
      { data: { ...RESULT_ENVELOPE, _meta: { rewritten: true } } },
      hash,
      RESPONSE_PROOF_PROFILE_V2,
    );
    const c = await computeCanonicalHashes(
      REQUEST,
      { data: (({ _meta: _m, ...rest }) => rest)(RESULT_ENVELOPE) },
      hash,
      RESPONSE_PROOF_PROFILE_V2,
    );
    expect(a.responseHash).toBe(b.responseHash);
    expect(a.responseHash).toBe(c.responseHash);
  });

  it("v2 hashes non-object data as-is (total function, signer/verifier symmetric)", async () => {
    const { responseHash } = await computeCanonicalHashes(
      REQUEST,
      { data: "plain-string" },
      hash,
      RESPONSE_PROOF_PROFILE_V2,
    );
    const expected = await cryptoProvider.hash(
      new TextEncoder().encode(canonicalize("plain-string")),
    );
    expect(responseHash).toBe(expected);
  });

  it("v1 does NOT strip _meta from data (byte-compat with existing proofs)", async () => {
    const withMeta = await computeCanonicalHashes(
      REQUEST,
      { data: { body: 1, _meta: { x: 1 } } },
      hash,
    );
    const withoutMeta = await computeCanonicalHashes(
      REQUEST,
      { data: { body: 1 } },
      hash,
    );
    expect(withMeta.responseHash).not.toBe(withoutMeta.responseHash);
  });
});

describe("ProofGenerator — v2 profile", () => {
  let identity: ProofAgentIdentity;
  let session: SessionContext;
  let generator: ProofGenerator;

  beforeEach(async () => {
    identity = await makeIdentity();
    session = makeSession();
    generator = new ProofGenerator(identity, cryptoProvider);
  });

  it("v2 proof carries prf in meta AND in the signed payload", async () => {
    const proof = await generator.generateProof(
      REQUEST,
      { data: RESULT_ENVELOPE },
      session,
      { profile: RESPONSE_PROOF_PROFILE_V2 },
    );
    expect(proof.meta.prf).toBe(RESPONSE_PROOF_PROFILE_V2);

    const payloadJson = JSON.parse(
      Buffer.from(proof.jws.split(".")[1]!, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    expect(payloadJson["prf"]).toBe(RESPONSE_PROOF_PROFILE_V2);
  });

  it("v1 proof (no profile) carries no prf — wire-identical to pre-v2 proofs", async () => {
    const proof = await generator.generateProof(
      REQUEST,
      { data: RESULT_ENVELOPE.content },
      session,
    );
    expect(proof.meta.prf).toBeUndefined();
    const payloadJson = JSON.parse(
      Buffer.from(proof.jws.split(".")[1]!, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    expect("prf" in payloadJson).toBe(false);
  });

  it("the `profile` option is consumed, never leaked into meta as a claim", async () => {
    const proof = await generator.generateProof(
      REQUEST,
      { data: RESULT_ENVELOPE },
      session,
      { profile: RESPONSE_PROOF_PROFILE_V2 },
    );
    expect("profile" in proof.meta).toBe(false);
  });

  it("a caller-supplied `prf` in options can never override the profile-derived claim", async () => {
    // TypeScript forbids this shape; a plain-JS caller could still pass it.
    // The claim must come only from the `profile` option — under v1 no prf,
    // regardless of what rides in the options bag.
    const proof = await generator.generateProof(
      REQUEST,
      { data: RESULT_ENVELOPE.content },
      session,
      { prf: "org.evil/other.v9" } as never,
    );
    expect(proof.meta.prf).toBeUndefined();
    const payloadJson = JSON.parse(
      Buffer.from(proof.jws.split(".")[1]!, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    expect("prf" in payloadJson).toBe(false);
  });

  it("generator.verifyProof derives the profile from the proof itself", async () => {
    const proof = await generator.generateProof(
      REQUEST,
      { data: RESULT_ENVELOPE },
      session,
      { profile: RESPONSE_PROOF_PROFILE_V2 },
    );
    await expect(
      generator.verifyProof(proof, REQUEST, { data: RESULT_ENVELOPE }),
    ).resolves.toBe(true);
    await expect(
      generator.verifyProof(proof, REQUEST, {
        data: { ...RESULT_ENVELOPE, isError: true },
      }),
    ).resolves.toBe(false);
  });
});

describe("buildProofJwsPayload — shared signer/verifier payload shape", () => {
  it("round-trips: generator payload === verifier reconstruction, incl. prf", async () => {
    const identity = await makeIdentity();
    const generator = new ProofGenerator(identity, cryptoProvider);
    const proof = await generator.generateProof(
      REQUEST,
      { data: RESULT_ENVELOPE },
      makeSession(),
      { profile: RESPONSE_PROOF_PROFILE_V2 },
    );
    const rebuilt = canonicalize(buildProofJwsPayload(proof.meta));
    const signed = Buffer.from(proof.jws.split(".")[1]!, "base64url").toString("utf8");
    expect(rebuilt).toBe(signed);
  });
});

describe("validateDetachedProof — prf fail-closed", () => {
  async function mintV2Proof() {
    const identity = await makeIdentity();
    const generator = new ProofGenerator(identity, cryptoProvider);
    return generator.generateProof(REQUEST, { data: RESULT_ENVELOPE }, makeSession(), {
      profile: RESPONSE_PROOF_PROFILE_V2,
    });
  }

  it("accepts the v2 prf literal", async () => {
    const proof = await mintV2Proof();
    expect(validateDetachedProof(proof).success).toBe(true);
  });

  it("rejects an unknown prf value (no silent fallback to weaker semantics)", async () => {
    const proof = await mintV2Proof();
    const forged = { ...proof, meta: { ...proof.meta, prf: "org.evil/other.v9" } };
    const result = validateDetachedProof(forged);
    expect(result.success).toBe(false);
    expect(result.error?.message).toContain("prf");
  });

  it("rejects a non-string prf", async () => {
    const proof = await mintV2Proof();
    const forged = { ...proof, meta: { ...proof.meta, prf: 2 } };
    expect(validateDetachedProof(forged).success).toBe(false);
  });
});

describe("ProofVerifier — v2 content binding", () => {
  let identity: ProofAgentIdentity;
  let generator: ProofGenerator;

  beforeEach(async () => {
    identity = await makeIdentity();
    generator = new ProofGenerator(identity, cryptoProvider);
  });

  async function mintV2Proof(envelope: unknown = RESULT_ENVELOPE) {
    return generator.generateProof(REQUEST, { data: envelope }, makeSession(), {
      profile: RESPONSE_PROOF_PROFILE_V2,
    });
  }

  it("accepts a v2 proof against the untampered envelope", async () => {
    const proof = await mintV2Proof();
    const result = await makeVerifier().verifyProof(proof, jwkFor(identity), {
      request: REQUEST,
      response: { data: RESULT_ENVELOPE },
    });
    expect(result.valid).toBe(true);
  });

  it("detects a swapped structuredContent under v2 (the v1 blind spot)", async () => {
    const proof = await mintV2Proof();
    const result = await makeVerifier().verifyProof(proof, jwkFor(identity), {
      request: REQUEST,
      response: {
        data: { ...RESULT_ENVELOPE, structuredContent: { msg: "TAMPERED" } },
      },
    });
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(
      PROOF_VERIFICATION_ERROR_CODES.CONTENT_BINDING_MISMATCH,
    );
  });

  it("detects a flipped isError under v2", async () => {
    const proof = await mintV2Proof();
    const result = await makeVerifier().verifyProof(proof, jwkFor(identity), {
      request: REQUEST,
      response: { data: { ...RESULT_ENVELOPE, isError: true } },
    });
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(
      PROOF_VERIFICATION_ERROR_CODES.CONTENT_BINDING_MISMATCH,
    );
  });

  it("detects a rewritten resultType under v2", async () => {
    const proof = await mintV2Proof();
    const result = await makeVerifier().verifyProof(proof, jwkFor(identity), {
      request: REQUEST,
      response: { data: { ...RESULT_ENVELOPE, resultType: "input_required" } },
    });
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(
      PROOF_VERIFICATION_ERROR_CODES.CONTENT_BINDING_MISMATCH,
    );
  });

  it("ignores _meta mutation under v2 (proof attachment cannot self-invalidate)", async () => {
    const proof = await mintV2Proof();
    const result = await makeVerifier().verifyProof(proof, jwkFor(identity), {
      request: REQUEST,
      response: {
        data: { ...RESULT_ENVELOPE, _meta: { "org.kya-os/response-proof": proof } },
      },
    });
    expect(result.valid).toBe(true);
  });

  it("rejects a v2 proof whose prf was stripped after signing (downgrade attempt)", async () => {
    const proof = await mintV2Proof();
    const { prf: _prf, ...metaWithoutPrf } = proof.meta;
    const downgraded = { jws: proof.jws, meta: metaWithoutPrf };
    // Without prf the verifier reconstructs a v1 payload, which no longer
    // matches the signature — the downgrade is not silent, it is a hard fail.
    const result = await makeVerifier().verifyProof(downgraded, jwkFor(identity), {
      request: REQUEST,
      response: { data: RESULT_ENVELOPE.content },
    });
    expect(result.valid).toBe(false);
  });

  it("still verifies v1 proofs end-to-end (no prf, content-array coverage)", async () => {
    const proof = await generator.generateProof(
      REQUEST,
      { data: RESULT_ENVELOPE.content },
      makeSession(),
    );
    const result = await makeVerifier().verifyProof(proof, jwkFor(identity), {
      request: REQUEST,
      response: { data: RESULT_ENVELOPE.content },
    });
    expect(result.valid).toBe(true);
  });
});
