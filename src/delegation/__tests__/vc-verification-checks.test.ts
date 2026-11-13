/**
 * Stateless basic checks, exercised directly: validity bounds and delegation
 * status fail closed, and a refusal reason quotes what the credential chose as
 * `describeValue` does. `vc-verifier.test.ts` mocks the protocol helpers these
 * checks are built on, so the real ones are covered here.
 */

import { describe, it, expect, vi } from "vitest";
import { checkCredentialStatus, validateBasicProperties, verifySignature } from "../vc-verification-checks.js";
import type { SignatureVerificationFunction } from "../vc-verifier.types.js";
import type { CredentialStatus, DelegationCredential } from "../../types/protocol.js";
import { issuerDidDocument } from "../../__tests__/utils/did-documents.js";

const ISSUER = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

/** A status entry of the credential's for `statusPurpose`. */
const credentialStatus = (statusPurpose: string): CredentialStatus => ({
  id: "https://status.example/1#7",
  type: "StatusList2021Entry",
  statusPurpose,
  statusListIndex: "7",
  statusListCredential: "https://status.example/1",
} as CredentialStatus);

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
      ["revoked", 'Delegation status is "revoked"'],
      ["expired", 'Delegation status is "expired"'],
      ["suspended", 'Delegation status is "suspended"'],
      [undefined, "Delegation status is missing"],
    ] as const) {
      const vc = credential();
      (vc.credentialSubject.delegation as { status?: string }).status = status;
      expect(validateBasicProperties(vc)).toEqual({ valid: false, reason });
    }
  });
});

describe("refusal reasons quote what the credential chose as describeValue does", () => {
  const long = "x".repeat(100_000);
  const cutLong = `"${"x".repeat(64)}"...`;

  it("quotes a delegation status other than active, never converting it", () => {
    const statuses: [unknown, string][] = [
      [long, cutLong],
      ["revoked\uD800", '"revoked\\ud800"'],
      [JSON.parse('{"toString":"active"}'), "of type object"],
    ];
    for (const [status, named] of statuses) {
      const vc = credential();
      (vc.credentialSubject.delegation as { status?: unknown }).status = status;
      expect(validateBasicProperties(vc)).toEqual({ valid: false, reason: `Delegation status is ${named}` });
    }
  });

  it("quotes the fields a credentialSubject must not carry", () => {
    const fields: [string, string][] = [[long, cutLong], ["claim\uD800", '"claim\\ud800"']];
    for (const [field, named] of fields) {
      const vc = credential();
      Object.assign(vc.credentialSubject, { [field]: true });
      expect(validateBasicProperties(vc).reason).toBe(
        `credentialSubject contains non-delegation field(s): ${named}. ` +
          "A DelegationCredential subject MUST carry only 'id' and 'delegation' (KYA-OS §11.6).",
      );
    }
  });

  it("quotes the type and purpose of a status entry its resolver reads as revoked", async () => {
    const status = { type: long, statusPurpose: "revocation\uD800" } as unknown as CredentialStatus;
    expect(await checkCredentialStatus(status, { checkStatus: async () => true }, ISSUER)).toMatchObject({
      valid: false,
      outcome: "revoked",
      reason: `Credential revoked via ${cutLong} ("revocation\\ud800")`,
    });
  });

  it("passes the message of a status resolver that throws through the message sanitizer", async () => {
    const thrower = (message: string) => ({ checkStatus: async () => { throw new Error(message); } });
    expect(await checkCredentialStatus(credentialStatus("revocation"), thrower("list\nunavailable\uD800"), ISSUER)).toEqual({
      valid: false,
      outcome: "status_unresolvable",
      reason: "Status check error: list\uFFFDunavailable\uFFFD",
      durationMs: expect.any(Number),
    });
    // A resolver that quotes a purpose the credential chose, raw: 2,074 UTF-16 units, not well-formed.
    const purpose = "x\uD800".repeat(1000);
    const raw = `status list statusPurpose mismatch: "revocation" != "${purpose}"`;
    const { reason } = await checkCredentialStatus(credentialStatus(purpose), thrower(raw), ISSUER);
    const expectedMessage = `status list statusPurpose mismatch: "revocation" != "${"x\uFFFD".repeat(1000)}`;
    expect(reason).toBe(`Status check error: ${expectedMessage.slice(0, 256)}\u2026`);
    expect(reason).not.toMatch(/\p{Cs}/u);
  });
});

describe("verifySignature: fail-closed paths", () => {
  const verificationMethodId = `${ISSUER}#${ISSUER.slice("did:key:".length)}`;
  const issuerDocument = issuerDidDocument({
    id: verificationMethodId,
    type: "Ed25519VerificationKey2020",
    controller: ISSUER,
    publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" },
  });
  const resolver = { resolve: async () => issuerDocument };

  it("rejects a credential with no proof before calling the signature verifier", async () => {
    const signatureVerifier = vi.fn<SignatureVerificationFunction>(async () => ({ valid: true }));
    const result = await verifySignature(credential({ proof: undefined }), resolver, signatureVerifier);
    expect(result).toMatchObject({ valid: false, reason: "Proof is missing" });
    expect(signatureVerifier).not.toHaveBeenCalled();
  });

  it("refuses a credential whose issuer names no DID before it resolves any, never converting the issuer", async () => {
    // The basic stage refuses such a credential first; this stage, run on its own, refuses it too.
    const resolve = vi.fn(async () => issuerDocument);
    const signatureVerifier = vi.fn<SignatureVerificationFunction>(async () => ({ valid: true }));
    const refusals: [unknown, string][] = [
      [{ id: 5 }, "Credential issuer id of type number is not a URL"],
      [[ISSUER], "Credential issuer of type array is not a URL"],
      [{ id: JSON.parse('{"toString":"x"}') }, "Credential issuer id of type object is not a URL"],
    ];
    for (const [issuer, reason] of refusals) {
      const result = await verifySignature(credential({ issuer } as never), { resolve }, signatureVerifier);
      expect(result).toMatchObject({ valid: false, reason });
    }
    expect(resolve).not.toHaveBeenCalled();
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
