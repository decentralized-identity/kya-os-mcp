/**
 * Stateless basic checks, exercised directly: validity bounds and delegation
 * status fail closed. `vc-verifier.test.ts` mocks the protocol helpers these
 * checks are built on, so the real ones are covered here.
 */

import { describe, it, expect, vi } from "vitest";
import { validateBasicProperties, verifySignature } from "../vc-verification-checks.js";
import type { DIDDocument, SignatureVerificationFunction } from "../vc-verifier.types.js";
import type { DelegationCredential } from "../../types/protocol.js";

const ISSUER = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

function credential(overrides: Partial<DelegationCredential> = {}): DelegationCredential {
  return {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: ["VerifiableCredential", "DelegationCredential"],
    issuer: ISSUER,
    issuanceDate: "2026-01-01T00:00:00.000Z",
    credentialSubject: {
      id: "did:key:z6MkSubject",
      delegation: {
        id: "d1",
        issuerDid: ISSUER,
        subjectDid: "did:key:z6MkSubject",
        constraints: { scopes: ["read"] },
        status: "active",
      },
    },
    proof: {
      type: "Ed25519Signature2020",
      verificationMethod: `${ISSUER}#${ISSUER.slice("did:key:".length)}`,
      proofPurpose: "assertionMethod",
      proofValue: "sig",
    },
    ...overrides,
  };
}

function withConstraints(constraints: Record<string, unknown>): DelegationCredential {
  const vc = credential();
  vc.credentialSubject.delegation.constraints = {
    ...vc.credentialSubject.delegation.constraints,
    ...constraints,
  };
  return vc;
}

describe("validateBasicProperties: validity bounds and status fail closed", () => {
  it("treats an unparseable expirationDate as expired, not as no expiry", () => {
    for (const expirationDate of ["2020-02-30T25:00:00Z", "not a date", "", 4102444800 as unknown as string]) {
      const result = validateBasicProperties(credential({ expirationDate }));
      expect(result, String(expirationDate)).toEqual({ valid: false, reason: "Delegation credential expired" });
    }
    expect(validateBasicProperties(credential({ expirationDate: "2099-01-01T00:00:00Z" }))).toEqual({ valid: true });
  });

  it("treats a non-numeric constraints.notAfter as expired, and still honours a numeric one", () => {
    for (const notAfter of ["2020-01-01", "4102444800", null, Number.NaN, Number.POSITIVE_INFINITY]) {
      const result = validateBasicProperties(withConstraints({ notAfter }));
      expect(result, String(notAfter)).toEqual({ valid: false, reason: "Delegation credential expired" });
    }
    const nowSec = Math.floor(Date.now() / 1000);
    expect(validateBasicProperties(withConstraints({ notAfter: nowSec + 60 })).valid).toBe(true);
    expect(validateBasicProperties(withConstraints({ notAfter: nowSec - 60 })).valid).toBe(false);
  });

  it("treats a notAfter of 0 as a bound in the past", () => {
    expect(validateBasicProperties(withConstraints({ notAfter: 0 }))).toEqual({
      valid: false,
      reason: "Delegation credential expired",
    });
  });

  it("treats a non-numeric constraints.notBefore as not yet valid, and still honours a numeric one", () => {
    for (const notBefore of ["2020-01-01", null, Number.NaN]) {
      const result = validateBasicProperties(withConstraints({ notBefore }));
      expect(result, String(notBefore)).toEqual({ valid: false, reason: "Delegation credential not yet valid" });
    }
    const nowSec = Math.floor(Date.now() / 1000);
    expect(validateBasicProperties(withConstraints({ notBefore: nowSec - 60 })).valid).toBe(true);
    expect(validateBasicProperties(withConstraints({ notBefore: nowSec + 60 })).valid).toBe(false);
  });

  it("passes only an active delegation", () => {
    expect(validateBasicProperties(credential())).toEqual({ valid: true });
    for (const [status, reason] of [
      ["revoked", "Delegation status is revoked"],
      ["expired", "Delegation status is expired"],
      ["suspended", "Delegation status is suspended"],
      [undefined, "Delegation status is missing"],
    ] as const) {
      const vc = credential();
      (vc.credentialSubject.delegation as { status?: string }).status = status;
      expect(validateBasicProperties(vc)).toEqual({ valid: false, reason });
    }
  });
});

describe("verifySignature: fail-closed paths", () => {
  const verificationMethodId = `${ISSUER}#${ISSUER.slice("did:key:".length)}`;
  const issuerDocument: DIDDocument = {
    id: ISSUER,
    verificationMethod: [
      {
        id: verificationMethodId,
        type: "Ed25519VerificationKey2020",
        controller: ISSUER,
        publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" },
      },
    ],
  };
  const resolver = { resolve: async () => issuerDocument };

  it("rejects a credential with no proof before calling the signature verifier", async () => {
    const signatureVerifier = vi.fn<SignatureVerificationFunction>(async () => ({ valid: true }));
    const result = await verifySignature(credential({ proof: undefined }), resolver, signatureVerifier);
    expect(result).toMatchObject({ valid: false, reason: "Proof is missing" });
    expect(signatureVerifier).not.toHaveBeenCalled();
  });

  it("reports a signature verifier that throws a non-Error as a failed verification", async () => {
    const signatureVerifier: SignatureVerificationFunction = async () => {
      throw "verifier crashed";
    };
    const result = await verifySignature(credential(), resolver, signatureVerifier);
    expect(result).toMatchObject({ valid: false, reason: "Signature verification error: Unknown error" });
  });
});
