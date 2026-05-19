import { describe, it, expect } from "vitest";
import {
  KYA_OS_ERROR_CODES,
  createKyaOsError,
} from "../errors.js";

describe("KYA_OS_ERROR_CODES", () => {
  it("should define all canonical error codes", () => {
    const codes = Object.values(KYA_OS_ERROR_CODES);
    expect(codes).toContain("invalid_proof");
    expect(codes).toContain("invalid_jws");
    expect(codes).toContain("nonce_replay");
    expect(codes).toContain("timestamp_skew");
    expect(codes).toContain("did_not_found");
    expect(codes).toContain("invalid_public_key");
    expect(codes).toContain("handshake_failed");
    expect(codes).toContain("session_expired");
    expect(codes).toContain("invalid_request");
    expect(codes).toContain("needs_authorization");
    expect(codes).toContain("insufficient_scope");
    expect(codes).toContain("delegation_expired");
    expect(codes).toContain("delegation_not_yet_valid");
    expect(codes).toContain("delegation_revoked");
    expect(codes).toContain("delegation_invalid");
    expect(codes).toContain("budget_exceeded");
    expect(codes).toContain("rate_limit_exceeded");
    expect(codes).toContain("invalid_token");
    expect(codes).toContain("token_expired");
    expect(codes).toContain("mirror_pending");
    expect(codes).toContain("claim_failed");
    expect(codes).toContain("configuration_error");
    expect(codes).toContain("runtime_error");
  });

  it("should have key === value for every code", () => {
    for (const [key, value] of Object.entries(KYA_OS_ERROR_CODES)) {
      expect(key).toBe(value);
    }
  });
});

describe("createKyaOsError", () => {
  it("should create an error response with code and message", () => {
    const error = createKyaOsError("handshake_failed", "Nonce already used");
    expect(error.code).toBe("handshake_failed");
    expect(error.message).toBe("Nonce already used");
    expect(error.details).toBeUndefined();
  });

  it("should include details when provided", () => {
    const error = createKyaOsError("delegation_revoked", "Credential revoked", {
      credentialId: "urn:uuid:123",
    });
    expect(error.details).toEqual({ credentialId: "urn:uuid:123" });
  });
});
