/**
 * High-level VC-JWT verification tests (real EdDSA crypto).
 *
 * `vc-jwt.test.ts` covers the create/parse PRIMITIVES in `utils.ts`. This file
 * covers `DelegationCredentialVerifier.verifyDelegationJwt` — the DID-resolving
 * verify of the JWT serialization (the compact JWS a browser wallet mints,
 * where the envelope signature IS the proof, with no embedded `proof` block).
 * It proves the verifier accepts that wire format and rejects the failure modes
 * that matter — most importantly the DID-doc-key-vs-signing-key mismatch that
 * surfaced against the Hobbsidian wallet.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { generateKeyPair, exportJWK, SignJWT, type JWK } from "jose";
import {
  DelegationCredentialVerifier,
  type DIDResolver,
  type DIDDocument,
} from "../vc-verifier.js";
import { credentialIssuerDid } from "../vc-jwt-verify.js";
import type { DelegationCredential } from "../../types/protocol.js";

const ISSUER_DID = "did:web:example.com:u:alice";
const KID = `${ISSUER_DID}#0`;

function delegationVcClaim(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    id: "urn:uuid:test-credential-1",
    type: ["VerifiableCredential", "DelegationCredential"],
    issuer: ISSUER_DID,
    issuanceDate: "2026-01-01T00:00:00.000Z",
    expirationDate: "2099-01-01T00:00:00.000Z",
    credentialSubject: {
      id: ISSUER_DID,
      delegation: {
        id: "del_test_1",
        issuerDid: ISSUER_DID,
        subjectDid: ISSUER_DID,
        signature: "",
        status: "active",
        constraints: { scopes: ["vault:read"] },
      },
    },
    ...overrides,
  };
}

describe("verifyDelegationJwt (VC-JWT / compact JWS wire format)", () => {
  let privateKey: CryptoKey;
  let publicJwk: JWK;
  let verifier: DelegationCredentialVerifier;

  const resolverFor = (jwk: JWK): DIDResolver => ({
    async resolve(did: string): Promise<DIDDocument | null> {
      if (did !== ISSUER_DID) return null;
      return {
        id: ISSUER_DID,
        verificationMethod: [
          {
            id: KID,
            type: "JsonWebKey2020",
            controller: ISSUER_DID,
            publicKeyJwk: jwk,
          },
        ],
      };
    },
  });

  async function mintVcJwt(
    signer: CryptoKey,
    vcClaim: Record<string, unknown> = delegationVcClaim(),
  ): Promise<string> {
    return new SignJWT({ vc: vcClaim })
      .setProtectedHeader({ alg: "EdDSA", typ: "JWT", kid: KID })
      .setIssuer(ISSUER_DID)
      .setSubject(ISSUER_DID)
      .setIssuedAt()
      .sign(signer);
  }

  beforeAll(async () => {
    const pair = await generateKeyPair("EdDSA", { extractable: true });
    privateKey = pair.privateKey;
    publicJwk = await exportJWK(pair.publicKey);
    verifier = new DelegationCredentialVerifier({
      didResolver: resolverFor(publicJwk),
    });
  });

  it("accepts a valid VC-JWT that carries NO embedded proof", async () => {
    const jwt = await mintVcJwt(privateKey);
    const result = await verifier.verifyDelegationJwt(jwt, { skipCache: true });
    expect(result.valid).toBe(true);
    expect(result.stage).toBe("complete");
    expect(result.checks?.signatureValid).toBe(true);
  });

  it("rejects a token signed by a key that is NOT the one published in the DID Document", async () => {
    // The exact failure Hobbsidian hit: resolved DID-doc key != signing key.
    const attacker = await generateKeyPair("EdDSA", { extractable: true });
    const jwt = await mintVcJwt(attacker.privateKey);
    const result = await verifier.verifyDelegationJwt(jwt, { skipCache: true });
    expect(result.valid).toBe(false);
    expect(result.checks?.signatureValid).toBe(false);
    expect(result.reason).toMatch(/signature is not valid/i);
  });

  it("rejects a tampered payload (signature no longer covers the claims)", async () => {
    const jwt = await mintVcJwt(privateKey);
    const [header, , signature] = jwt.split(".");
    const forgedPayload = Buffer.from(
      JSON.stringify({
        iss: ISSUER_DID,
        vc: delegationVcClaim({ id: "urn:uuid:forged" }),
      }),
    ).toString("base64url");
    const tampered = `${header}.${forgedPayload}.${signature}`;
    const result = await verifier.verifyDelegationJwt(tampered, {
      skipCache: true,
    });
    expect(result.valid).toBe(false);
    expect(result.checks?.signatureValid).toBe(false);
  });

  it("rejects a token whose credential `issuer` differs from the signed `iss`", async () => {
    const jwt = await mintVcJwt(
      privateKey,
      delegationVcClaim({ issuer: "did:web:evil.example:u:mallory" }),
    );
    const result = await verifier.verifyDelegationJwt(jwt, { skipCache: true });
    expect(result.valid).toBe(false);
    expect(result.stage).toBe("basic");
    expect(result.reason).toMatch(/does not match the JWT `iss`/i);
  });

  it("denies when the issuer DID cannot be resolved", async () => {
    const isolated = new DelegationCredentialVerifier({
      didResolver: {
        async resolve(): Promise<DIDDocument | null> {
          return null;
        },
      },
    });
    const jwt = await mintVcJwt(privateKey);
    const result = await isolated.verifyDelegationJwt(jwt, { skipCache: true });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/could not resolve issuer DID/i);
  });

  it("denies when no DID resolver is configured", async () => {
    const noResolver = new DelegationCredentialVerifier({});
    const jwt = await mintVcJwt(privateKey);
    const result = await noResolver.verifyDelegationJwt(jwt, { skipCache: true });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/no DID resolver/i);
  });

  it("fast-rejects a non-JWT string at the basic stage", async () => {
    const result = await verifier.verifyDelegationJwt("not-a-jwt", {
      skipCache: true,
    });
    expect(result.valid).toBe(false);
    expect(result.stage).toBe("basic");
  });

  it("reads the declared issuer from a string or object `issuer`", () => {
    expect(credentialIssuerDid({ issuer: ISSUER_DID } as DelegationCredential)).toBe(
      ISSUER_DID,
    );
    expect(
      credentialIssuerDid({ issuer: { id: ISSUER_DID } } as DelegationCredential),
    ).toBe(ISSUER_DID);
    expect(
      credentialIssuerDid({} as DelegationCredential),
    ).toBeUndefined();
  });

  it("caches a valid result and serves it on the next call", async () => {
    const isolated = new DelegationCredentialVerifier({
      didResolver: resolverFor(publicJwk),
    });
    const jwt = await mintVcJwt(
      privateKey,
      delegationVcClaim({ id: "urn:uuid:cache-test" }),
    );

    const first = await isolated.verifyDelegationJwt(jwt);
    expect(first.valid).toBe(true);
    expect(first.cached).toBeUndefined();

    const second = await isolated.verifyDelegationJwt(jwt);
    expect(second.valid).toBe(true);
    expect(second.cached).toBe(true);
  });

  it("honors skipSignature (trusts the envelope without re-checking)", async () => {
    const jwt = await mintVcJwt(privateKey);
    const result = await verifier.verifyDelegationJwt(jwt, {
      skipCache: true,
      skipSignature: true,
    });
    expect(result.valid).toBe(true);
    expect(result.checks?.signatureValid).toBe(true);
  });

  it("checks credentialStatus when the JWT credential carries one", async () => {
    const checked: string[] = [];
    const withStatus = new DelegationCredentialVerifier({
      didResolver: resolverFor(publicJwk),
      statusListResolver: {
        async checkStatus(status): Promise<boolean> {
          checked.push(status.id);
          return false; // not revoked
        },
      },
    });
    const jwt = await mintVcJwt(
      privateKey,
      delegationVcClaim({
        credentialStatus: {
          id: "https://example.com/status/1",
          type: "StatusList2021Entry",
          statusPurpose: "revocation",
          statusListIndex: "0",
          statusListCredential: "https://example.com/status",
        },
      }),
    );

    const result = await withStatus.verifyDelegationJwt(jwt, { skipCache: true });
    expect(result.valid).toBe(true);
    expect(result.checks?.statusValid).toBe(true);
    expect(checked).toContain("https://example.com/status/1");
  });

  it('verifies a credential with no top-level id (cache key falls back to "")', async () => {
    const isolated = new DelegationCredentialVerifier({
      didResolver: resolverFor(publicJwk),
    });
    const claim = delegationVcClaim();
    delete (claim as Record<string, unknown>).id;

    const jwt = await mintVcJwt(privateKey, claim);
    const result = await isolated.verifyDelegationJwt(jwt);

    expect(result.valid).toBe(true);
  });
});
