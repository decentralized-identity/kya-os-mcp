/**
 * Outbound Delegation Proof Tests
 *
 * Tests for buildDelegationProofJWT and buildChainString helpers.
 * All 8 test cases from spec Section 5.
 */

import { describe, it, expect } from "vitest";
import { generateKeyPair, exportJWK, decodeJwt, decodeProtectedHeader } from "jose";
import {
  buildDelegationProofJWT,
  buildChainString,
  type DelegationProofOptions,
  type Ed25519PrivateJWK,
} from "../outbound-proof.js";
import type { DelegationRecord } from "../../types/protocol.js";

// ---------------------------------------------------------------------------
// Test key helpers
// ---------------------------------------------------------------------------

async function generateTestKeyPair(): Promise<{
  privateKeyJwk: Ed25519PrivateJWK;
  kid: string;
}> {
  // jose 6 generates non-extractable keys by default; this helper needs to
  // export the private key back out as a JWK for the test fixture.
  const { privateKey } = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
  const jwk = await exportJWK(privateKey);
  const privateKeyJwk: Ed25519PrivateJWK = {
    kty: "OKP",
    crv: "Ed25519",
    x: jwk.x as string,
    d: jwk.d as string,
  };
  return { privateKeyJwk, kid: "did:web:agent.example.com#key-1" };
}

const AGENT_DID = "did:web:agent.example.com";
const USER_DID = "did:web:alice.example.com";
const DELEGATION_ID = "del-abc-123";
const DELEGATION_CHAIN = "vc-abc>del-abc-123";
const SCOPES = ["read_files", "write_calendar"];
const TARGET_HOSTNAME = "api.example.com";

function baseOptions(overrides: Partial<DelegationProofOptions> = {}): DelegationProofOptions {
  return {
    agentDid: AGENT_DID,
    userDid: USER_DID,
    delegationId: DELEGATION_ID,
    delegationChain: DELEGATION_CHAIN,
    scopes: SCOPES,
    privateKeyJwk: {} as Ed25519PrivateJWK, // overridden in test setup
    kid: "did:web:agent.example.com#key-1",
    targetHostname: TARGET_HOSTNAME,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// buildDelegationProofJWT tests
// ---------------------------------------------------------------------------

describe("buildDelegationProofJWT", () => {
  it("happy path — produces a valid EdDSA compact JWT", async () => {
    const { privateKeyJwk, kid } = await generateTestKeyPair();
    const jwt = await buildDelegationProofJWT(baseOptions({ privateKeyJwk, kid }));

    expect(typeof jwt).toBe("string");
    // Compact JWT has exactly 3 parts
    expect(jwt.split(".")).toHaveLength(3);

    const header = decodeProtectedHeader(jwt);
    expect(header.alg).toBe("EdDSA");
    expect(header.kid).toBe(kid);
  });

  it("JWT payload contains all required claims", async () => {
    const { privateKeyJwk, kid } = await generateTestKeyPair();
    const jwt = await buildDelegationProofJWT(baseOptions({ privateKeyJwk, kid }));

    const payload = decodeJwt(jwt);
    expect(payload.iss).toBe(AGENT_DID);
    expect(payload.sub).toBe(USER_DID);
    expect(payload.aud).toBe(TARGET_HOSTNAME);
    expect(typeof payload.jti).toBe("string");
    expect(payload.delegation_id).toBe(DELEGATION_ID);
    expect(payload.delegation_chain).toBe(DELEGATION_CHAIN);
    expect(payload.scope).toBe(SCOPES.join(","));
    expect(typeof payload.iat).toBe("number");
    expect(typeof payload.exp).toBe("number");
  });

  it("exp is exactly 60 seconds from iat", async () => {
    const { privateKeyJwk, kid } = await generateTestKeyPair();
    const jwt = await buildDelegationProofJWT(baseOptions({ privateKeyJwk, kid }));

    const payload = decodeJwt(jwt);
    expect((payload.exp as number) - (payload.iat as number)).toBe(60);
  });

  it("jti is unique across multiple calls", async () => {
    const { privateKeyJwk, kid } = await generateTestKeyPair();
    const opts = baseOptions({ privateKeyJwk, kid });

    const jwt1 = await buildDelegationProofJWT(opts);
    const jwt2 = await buildDelegationProofJWT(opts);

    const payload1 = decodeJwt(jwt1);
    const payload2 = decodeJwt(jwt2);
    expect(payload1.jti).not.toBe(payload2.jti);
  });

  it("throws when private key is invalid", async () => {
    const badKeyJwk: Ed25519PrivateJWK = {
      kty: "OKP",
      crv: "Ed25519",
      x: "invalid",
      d: "invalid",
    };

    await expect(
      buildDelegationProofJWT(baseOptions({ privateKeyJwk: badKeyJwk }))
    ).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// buildChainString tests
// ---------------------------------------------------------------------------

describe("buildChainString", () => {
  const baseDelegation: DelegationRecord = {
    id: "del-123",
    issuerDid: "did:web:issuer.example.com",
    subjectDid: "did:web:agent.example.com",
    vcId: "vc-abc",
    constraints: { scopes: ["read:files"] },
    signature: "sig",
    status: "active",
  };

  it("single-hop delegation encodes correctly", () => {
    const result = buildChainString(baseDelegation);
    expect(result).toBe("vc-abc>del-123");
  });

  it("multi-hop (3 levels) encodes correctly when concatenated", () => {
    const del1: DelegationRecord = { ...baseDelegation, id: "del-1", vcId: "vc-1" };
    const del2: DelegationRecord = { ...baseDelegation, id: "del-2", vcId: "vc-2", parentId: "del-1" };
    const del3: DelegationRecord = { ...baseDelegation, id: "del-3", vcId: "vc-3", parentId: "del-2" };

    // Build the chain by concatenating each hop (caller responsibility for multi-hop)
    const chain = [del1, del2, del3].map(buildChainString).join(">");
    expect(chain).toBe("vc-1>del-1>vc-2>del-2>vc-3>del-3");
  });

  it("returns delegation.id when vcId is absent", () => {
    const delegation: DelegationRecord = {
      ...baseDelegation,
      vcId: undefined as unknown as string,
    };
    const result = buildChainString(delegation);
    expect(result).toBe("del-123");
  });

  it("empty chain returns empty string gracefully", () => {
    const emptyDelegation = {
      id: "",
      issuerDid: "did:web:issuer.example.com",
      subjectDid: "did:web:agent.example.com",
      vcId: undefined as unknown as string,
      constraints: { scopes: [] },
      signature: "sig",
      status: "active" as const,
    } satisfies DelegationRecord;

    const result = buildChainString(emptyDelegation);
    expect(result).toBe("");
  });
});
