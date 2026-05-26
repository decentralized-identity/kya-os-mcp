import { describe, it, expect, beforeEach, vi, Mock } from "vitest";
import {
  DelegationCredentialVerifier,
  createDelegationVerifier,
  type DIDResolver,
  type StatusListResolver,
  type SignatureVerificationFunction,
  type DelegationVCVerificationResult,
} from "../vc-verifier.js";
import type { DelegationCredential } from "../../types/protocol.js";

// Mock the protocol functions (preserving all other exports)
vi.mock("../../types/protocol.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../types/protocol.js")>();
  return {
    ...actual,
    isDelegationCredentialExpired: vi.fn(),
    isDelegationCredentialNotYetValid: vi.fn(),
    validateDelegationCredential: vi.fn(),
  };
});

describe("DelegationCredentialVerifier", () => {
  let mockDidResolver: {
    resolve: ReturnType<typeof vi.fn>;
  };
  let mockStatusListResolver: {
    checkStatus: ReturnType<typeof vi.fn>;
  };
  let mockSignatureVerifier: Mock<SignatureVerificationFunction>;

  let verifier: DelegationCredentialVerifier;

  // Helper function to setup default contracts mocks
  const setupDefaultContractsMocks = async () => {
    // Import the mocked functions
    const protocol = await import("../../types/protocol.js");

    // Access the mocked functions and set return values
    const validateDelegationCredential = vi.mocked(
      protocol.validateDelegationCredential
    );
    const isDelegationCredentialExpired = vi.mocked(
      protocol.isDelegationCredentialExpired
    );
    const isDelegationCredentialNotYetValid = vi.mocked(
      protocol.isDelegationCredentialNotYetValid
    );

    // Setup default return values
    validateDelegationCredential.mockReturnValue({
      success: true,
      data: mockValidVC,
    });
    isDelegationCredentialExpired.mockReturnValue(false);
    isDelegationCredentialNotYetValid.mockReturnValue(false);

    return {
      validateDelegationCredential,
      isDelegationCredentialExpired,
      isDelegationCredentialNotYetValid,
    };
  };

  const mockValidVC: DelegationCredential = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    id: "urn:delegation:123",
    type: ["VerifiableCredential", "DelegationCredential"],
    issuer: "did:web:example.com:issuer",
    issuanceDate: "2024-01-01T00:00:00Z",
    credentialSubject: {
      id: "did:web:example.com:subject",
      delegation: {
        id: "urn:delegation:123",
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        constraints: {
          scopes: ["read:profile"],
        },
        status: "active",
      },
    },
    proof: {
      type: "Ed25519Signature2020",
      created: "2024-01-01T00:00:00Z",
      verificationMethod: "did:web:example.com:issuer#key-1",
      proofPurpose: "assertionMethod",
      proofValue: "mock-proof-value",
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();

    // Setup mocks as proper interface implementations with vitest mock types
    mockDidResolver = {
      resolve: vi.fn() as any,
    };

    mockStatusListResolver = {
      checkStatus: vi.fn() as any,
    };

    mockSignatureVerifier = vi.fn();

    verifier = new DelegationCredentialVerifier({
      didResolver: mockDidResolver as DIDResolver,
      statusListResolver: mockStatusListResolver as StatusListResolver,
      signatureVerifier: mockSignatureVerifier,
      cacheTtl: 1000, // Short TTL for testing
    });
  });

  describe("constructor", () => {
    it("should create verifier with default options", () => {
      const defaultVerifier = new DelegationCredentialVerifier();
      expect(defaultVerifier).toBeInstanceOf(DelegationCredentialVerifier);
    });

    it("should create verifier with custom options", () => {
      const customVerifier = new DelegationCredentialVerifier({
        cacheTtl: 5000,
      });
      expect(customVerifier).toBeInstanceOf(DelegationCredentialVerifier);
    });
  });

  describe("createDelegationVerifier", () => {
    it("should create a verifier instance", () => {
      const verifier = createDelegationVerifier();
      expect(verifier).toBeInstanceOf(DelegationCredentialVerifier);
    });

    it("should pass options to verifier", () => {
      const options = { cacheTtl: 3000 };
      const verifier = createDelegationVerifier(options);
      expect(verifier).toBeInstanceOf(DelegationCredentialVerifier);
    });
  });

  describe("verifyDelegationCredential - Basic Validation Stage", () => {
    it("should reject expired credentials at basic validation stage", async () => {
      const contractsMock = await setupDefaultContractsMocks();
      contractsMock.isDelegationCredentialExpired.mockReturnValue(true);

      const result = await verifier.verifyDelegationCredential(mockValidVC);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Delegation credential expired");
      expect(result.stage).toBe("basic");
      expect(result.metrics?.totalMs).toBeGreaterThanOrEqual(0);
      expect(result.checks?.basicValid).toBe(false);
    });

    it("should reject not-yet-valid credentials at basic validation stage", async () => {
      const contractsMock = await setupDefaultContractsMocks();
      contractsMock.isDelegationCredentialNotYetValid.mockReturnValue(true);

      const result = await verifier.verifyDelegationCredential(mockValidVC);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Delegation credential not yet valid");
      expect(result.stage).toBe("basic");
    });

    it("should reject revoked credentials at basic validation stage", async () => {
      await setupDefaultContractsMocks();

      const revokedVC = {
        ...mockValidVC,
        credentialSubject: {
          ...mockValidVC.credentialSubject,
          delegation: {
            ...mockValidVC.credentialSubject.delegation,
            status: "revoked" as const,
          },
        },
      };

      const result = await verifier.verifyDelegationCredential(revokedVC);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Delegation status is revoked");
      expect(result.stage).toBe("basic");
    });

    it("should reject expired status credentials at basic validation stage", async () => {
      await setupDefaultContractsMocks();
      const expiredVC = {
        ...mockValidVC,
        credentialSubject: {
          ...mockValidVC.credentialSubject,
          delegation: {
            ...mockValidVC.credentialSubject.delegation,
            status: "expired" as const,
          },
        },
      };

      const result = await verifier.verifyDelegationCredential(expiredVC);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Delegation status is expired");
      expect(result.stage).toBe("basic");
    });

    it("should reject credentials without issuer DID", async () => {
      await setupDefaultContractsMocks();
      const invalidVC = {
        ...mockValidVC,
        credentialSubject: {
          ...mockValidVC.credentialSubject,
          delegation: {
            ...mockValidVC.credentialSubject.delegation,
            issuerDid: undefined,
          },
        },
      } as any;

      const result = await verifier.verifyDelegationCredential(invalidVC);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Missing issuer or subject DID");
      expect(result.stage).toBe("basic");
    });

    it("should reject credentials without subject DID", async () => {
      await setupDefaultContractsMocks();
      const invalidVC = {
        ...mockValidVC,
        credentialSubject: {
          ...mockValidVC.credentialSubject,
          delegation: {
            ...mockValidVC.credentialSubject.delegation,
            subjectDid: undefined,
          },
        },
      } as any;

      const result = await verifier.verifyDelegationCredential(invalidVC);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Missing issuer or subject DID");
      expect(result.stage).toBe("basic");
    });

    it("should reject credentials without proof", async () => {
      await setupDefaultContractsMocks();
      const invalidVC = { ...mockValidVC };
      delete invalidVC.proof;

      const result = await verifier.verifyDelegationCredential(invalidVC);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Missing proof");
      expect(result.stage).toBe("basic");
    });

    it("should reject invalid schema at basic validation stage", async () => {
      const contractsMock = await setupDefaultContractsMocks();
      // Create a mock ZodError-like object without importing zod
      const mockZodError = {
        issues: [{ code: "custom", path: [], message: "Invalid schema" }],
        message: "Invalid schema",
      };
      contractsMock.validateDelegationCredential.mockReturnValue({
        success: false,
        error: mockZodError,
      } as any);

      const result = await verifier.verifyDelegationCredential(mockValidVC);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Schema validation failed: Invalid schema");
      expect(result.stage).toBe("basic");
    });
  });

  describe("verifyDelegationCredential - Subject Shape (claim contamination)", () => {
    // A DelegationCredential `credentialSubject` MUST carry only `id` and
    // `delegation`. Claim-bearing fields alongside a permission separate
    // designation from authorization — the confused-deputy class (KYA-OS §11.6).
    const contaminatedVC: DelegationCredential = {
      ...mockValidVC,
      credentialSubject: {
        ...mockValidVC.credentialSubject,
        // `alumniOf` is a canonical W3C VC *claim*; it has no place in a
        // delegation (permission) credential.
        alumniOf: "did:web:example.edu",
      } as DelegationCredential["credentialSubject"],
    };

    it("rejects a credentialSubject carrying non-delegation (claim) fields", async () => {
      await setupDefaultContractsMocks();

      const result = await verifier.verifyDelegationCredential(contaminatedVC, {
        skipSignature: true,
        skipStatus: true,
      });

      expect(result.valid).toBe(false);
      expect(result.stage).toBe("basic");
      expect(result.reason).toMatch(/non-delegation field/i);
      expect(result.reason).toContain("alumniOf");
    });

    it("accepts contaminated subject under allowNonDelegationSubjectFields, warning once per process", async () => {
      await setupDefaultContractsMocks();
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

      const first = await verifier.verifyDelegationCredential(contaminatedVC, {
        skipSignature: true,
        skipStatus: true,
        allowNonDelegationSubjectFields: true,
      });
      const second = await verifier.verifyDelegationCredential(contaminatedVC, {
        skipSignature: true,
        skipStatus: true,
        skipCache: true,
        allowNonDelegationSubjectFields: true,
      });

      expect(first.valid).toBe(true);
      expect(second.valid).toBe(true);
      // One-time per-process warning, not once per verification.
      expect(warnSpy).toHaveBeenCalledTimes(1);
      expect(warnSpy.mock.calls[0]?.[0]).toMatch(
        /allowNonDelegationSubjectFields/,
      );

      warnSpy.mockRestore();
    });

    it("accepts a well-formed subject carrying only id and delegation", async () => {
      await setupDefaultContractsMocks();

      const result = await verifier.verifyDelegationCredential(mockValidVC, {
        skipSignature: true,
        skipStatus: true,
      });

      expect(result.valid).toBe(true);
    });
  });

  describe("verifyDelegationCredential - Signature Verification", () => {
    it("should skip signature verification when skipSignature is true", async () => {
      await setupDefaultContractsMocks();
      mockStatusListResolver.checkStatus.mockResolvedValue(false);
      mockSignatureVerifier.mockResolvedValue({ valid: false }); // This should not be called

      const result = await verifier.verifyDelegationCredential(mockValidVC, {
        skipSignature: true,
      });

      expect(result.valid).toBe(true); // Only basic checks pass
      expect(result.stage).toBe("complete");
      expect(result.checks?.signatureValid).toBe(true); // Skipped = treated as valid
      expect(mockSignatureVerifier).not.toHaveBeenCalled();
    });

    it("should fail signature verification when no resolver available", async () => {
      await setupDefaultContractsMocks();
      const verifierWithoutResolver = new DelegationCredentialVerifier({
        statusListResolver: mockStatusListResolver,
        // No signatureVerifier
      });

      mockStatusListResolver.checkStatus.mockResolvedValue(false);

      const result =
        await verifierWithoutResolver.verifyDelegationCredential(mockValidVC);

      expect(result.valid).toBe(false);
      expect(result.checks?.signatureValid).toBe(false);
      expect(result.reason).toContain("No DID resolver or signature verifier configured");
    });

    it("should fail when DID resolution fails", async () => {
      await setupDefaultContractsMocks();
      mockDidResolver.resolve.mockResolvedValue(null);

      const result = await verifier.verifyDelegationCredential(mockValidVC);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe(
        "Could not resolve issuer DID: did:web:example.com:issuer"
      );
      expect(result.stage).toBe("complete");
      expect(result.checks?.signatureValid).toBe(false);
    });

    it("should fail when verification method not found", async () => {
      await setupDefaultContractsMocks();
      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [], // Empty array
      });

      const result = await verifier.verifyDelegationCredential(mockValidVC);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe(
        "Verification method did:web:example.com:issuer#key-1 not found"
      );
      expect(result.checks?.signatureValid).toBe(false);
    });

    it("should fail when verification method missing public key", async () => {
      await setupDefaultContractsMocks();
      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            // Missing publicKeyJwk
          },
        ],
      });

      const result = await verifier.verifyDelegationCredential(mockValidVC);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Verification method missing publicKeyJwk");
      expect(result.checks?.signatureValid).toBe(false);
    });

    it("should succeed when signature verification passes", async () => {
      await setupDefaultContractsMocks();
      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });

      mockSignatureVerifier.mockResolvedValue({ valid: true });
      mockStatusListResolver.checkStatus.mockResolvedValue(false);

      const result = await verifier.verifyDelegationCredential(mockValidVC);

      expect(result.valid).toBe(true);
      expect(result.stage).toBe("complete");
      expect(result.checks?.signatureValid).toBe(true);
      expect(result.checks?.statusValid).toBe(true);
      expect(result.checks?.basicValid).toBe(true);
    });

    it("should fail when signature verification fails", async () => {
      await setupDefaultContractsMocks();
      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });

      mockSignatureVerifier.mockResolvedValue({
        valid: false,
        reason: "Invalid signature",
      });
      mockStatusListResolver.checkStatus.mockResolvedValue(false);

      const result = await verifier.verifyDelegationCredential(mockValidVC);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Invalid signature");
      expect(result.checks?.signatureValid).toBe(false);
    });
  });

  describe("verifyDelegationCredential - Status Checking", () => {
    it("should skip status checking when skipStatus is true", async () => {
      await setupDefaultContractsMocks();
      const vcWithoutStatus = { ...mockValidVC };
      delete vcWithoutStatus.credentialStatus;

      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: true });
      mockStatusListResolver.checkStatus.mockResolvedValue(true); // Revoked - should not be called

      const result = await verifier.verifyDelegationCredential(
        vcWithoutStatus,
        {
          skipStatus: true,
        }
      );

      expect(result.valid).toBe(true);
      expect(result.checks?.statusValid).toBe(true); // Skipped = treated as valid
      expect(mockStatusListResolver.checkStatus).not.toHaveBeenCalled();
    });

    it("should skip status checking when no status entry exists", async () => {
      await setupDefaultContractsMocks();
      const vcWithoutStatus = { ...mockValidVC };
      delete vcWithoutStatus.credentialStatus;

      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: true });

      const result = await verifier.verifyDelegationCredential(vcWithoutStatus);

      expect(result.valid).toBe(true);
      expect(result.checks?.statusValid).toBe(true);
      expect(mockStatusListResolver.checkStatus).not.toHaveBeenCalled();
    });

    it("should fail closed when no status resolver available but credential has credentialStatus", async () => {
      await setupDefaultContractsMocks();
      const verifierWithoutResolver = new DelegationCredentialVerifier({
        didResolver: mockDidResolver,
        signatureVerifier: mockSignatureVerifier,
        // No statusListResolver
      });

      const vcWithStatus = {
        ...mockValidVC,
        credentialStatus: {
          id: "https://example.com/status#123",
          type: "StatusList2021Entry" as const,
          statusPurpose: "revocation" as const,
          statusListIndex: "123",
          statusListCredential: "https://example.com/status",
        },
      };

      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: true });

      const result =
        await verifierWithoutResolver.verifyDelegationCredential(vcWithStatus);

      expect(result.valid).toBe(false);
      expect(result.checks?.statusValid).toBe(false);
      expect(result.reason).toContain("no status list resolver is configured");
    });

    it("should fail when credential is revoked", async () => {
      await setupDefaultContractsMocks();
      const vcWithStatus = {
        ...mockValidVC,
        credentialStatus: {
          id: "https://example.com/status#123",
          type: "StatusList2021Entry" as const,
          statusPurpose: "revocation" as const,
          statusListIndex: "123",
          statusListCredential: "https://example.com/status",
        },
      };

      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: true });
      mockStatusListResolver.checkStatus.mockResolvedValue(true); // Revoked

      const result = await verifier.verifyDelegationCredential(vcWithStatus);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe(
        "Credential revoked via StatusList2021 (revocation)"
      );
      expect(result.checks?.statusValid).toBe(false);
    });

    it("should succeed when credential is not revoked", async () => {
      await setupDefaultContractsMocks();
      const vcWithStatus = {
        ...mockValidVC,
        credentialStatus: {
          id: "https://example.com/status#123",
          type: "StatusList2021Entry" as const,
          statusPurpose: "revocation" as const,
          statusListIndex: "123",
          statusListCredential: "https://example.com/status",
        },
      };

      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: true });
      mockStatusListResolver.checkStatus.mockResolvedValue(false); // Not revoked

      const result = await verifier.verifyDelegationCredential(vcWithStatus);

      expect(result.valid).toBe(true);
      expect(result.checks?.statusValid).toBe(true);
    });
  });

  describe("verifyDelegationCredential - Caching", () => {
    it("should return cached result when available", async () => {
      await setupDefaultContractsMocks();
      // First call - should verify and cache
      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: true });
      mockStatusListResolver.checkStatus.mockResolvedValue(false);

      const result1 = await verifier.verifyDelegationCredential(mockValidVC);
      expect(result1.valid).toBe(true);
      expect(result1.cached).toBeUndefined();

      // Second call - should return cached result
      mockSignatureVerifier.mockClear();
      mockStatusListResolver.checkStatus.mockClear();

      const result2 = await verifier.verifyDelegationCredential(mockValidVC);
      expect(result2.valid).toBe(true);
      expect(result2.cached).toBe(true);

      // Verifiers should not be called again
      expect(mockSignatureVerifier).not.toHaveBeenCalled();
      expect(mockStatusListResolver.checkStatus).not.toHaveBeenCalled();
    });

    it("should skip cache when skipCache is true", async () => {
      await setupDefaultContractsMocks();
      // First call
      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: true });
      mockStatusListResolver.checkStatus.mockResolvedValue(false);

      await verifier.verifyDelegationCredential(mockValidVC);

      // Second call with skipCache
      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: false }); // Different result
      mockStatusListResolver.checkStatus.mockResolvedValue(false);

      const result = await verifier.verifyDelegationCredential(mockValidVC, {
        skipCache: true,
      });

      expect(result.valid).toBe(false); // Should get new result, not cached
      expect(result.cached).toBeUndefined();
    });

    it("should not cache failed verifications", async () => {
      // First call - fails
      const contractsMock = await setupDefaultContractsMocks();
      contractsMock.isDelegationCredentialExpired.mockReturnValue(true);

      const result1 = await verifier.verifyDelegationCredential(mockValidVC);
      expect(result1.valid).toBe(false);

      // Reset for second call
      contractsMock.isDelegationCredentialExpired.mockReturnValue(false);
      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: true });
      mockStatusListResolver.checkStatus.mockResolvedValue(false);

      // Second call - should verify again (not cached)
      const result2 = await verifier.verifyDelegationCredential(mockValidVC);
      expect(result2.valid).toBe(true);
      expect(result2.cached).toBeUndefined(); // Should not be cached
    });
  });

  describe("issuer handling", () => {
    it("should handle issuer as object with id property", async () => {
      await setupDefaultContractsMocks();
      const vcWithObjectIssuer = {
        ...mockValidVC,
        issuer: {
          id: "did:web:example.com:issuer",
          name: "Example Issuer"
        },
      };

      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: true });
      mockStatusListResolver.checkStatus.mockResolvedValue(false);

      const result = await verifier.verifyDelegationCredential(vcWithObjectIssuer);

      expect(result.valid).toBe(true);
      expect(mockDidResolver.resolve).toHaveBeenCalledWith("did:web:example.com:issuer");
    });

    it("should handle missing verificationMethod in proof", async () => {
      await setupDefaultContractsMocks();
      const vcWithoutVerificationMethod = {
        ...mockValidVC,
        proof: {
          type: "Ed25519Signature2020",
          created: "2024-01-01T00:00:00Z",
          // Missing verificationMethod
          proofPurpose: "assertionMethod",
          proofValue: "mock-proof-value",
        },
      } as any;

      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [],
      });

      const result = await verifier.verifyDelegationCredential(vcWithoutVerificationMethod);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Proof missing verificationMethod");
    });
  });

  describe("cache expiry", () => {
    it("should expire cached entries after TTL", async () => {
      await setupDefaultContractsMocks();
      // Create verifier with very short TTL (10ms)
      const shortTtlVerifier = new DelegationCredentialVerifier({
        didResolver: mockDidResolver as DIDResolver,
        statusListResolver: mockStatusListResolver as StatusListResolver,
        signatureVerifier: mockSignatureVerifier,
        cacheTtl: 10,
      });

      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: true });
      mockStatusListResolver.checkStatus.mockResolvedValue(false);

      // First verification
      const result1 = await shortTtlVerifier.verifyDelegationCredential(mockValidVC);
      expect(result1.valid).toBe(true);
      expect(result1.cached).toBeUndefined();

      // Wait for cache to expire
      await new Promise((resolve) => setTimeout(resolve, 15));

      // Clear mock call history
      mockSignatureVerifier.mockClear();
      mockStatusListResolver.checkStatus.mockClear();

      // Second verification - cache should have expired
      const result2 = await shortTtlVerifier.verifyDelegationCredential(mockValidVC);
      expect(result2.cached).toBeUndefined(); // Should not be from cache

      // Verifiers should be called again since cache expired
      expect(mockSignatureVerifier).toHaveBeenCalled();
    });
  });

  describe("cache management", () => {
    it("should clear all cache entries", async () => {
      await setupDefaultContractsMocks();
      // Add to cache
      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: true });
      mockStatusListResolver.checkStatus.mockResolvedValue(false);

      await verifier.verifyDelegationCredential(mockValidVC);

      // Clear cache
      verifier.clearCache();

      // Next call should verify again
      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: false }); // Different result

      const result = await verifier.verifyDelegationCredential(mockValidVC);
      expect(result.valid).toBe(false);
      expect(result.cached).toBeUndefined();
    });

    it("should clear specific cache entry", async () => {
      await setupDefaultContractsMocks();
      // Add to cache
      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: true });
      mockStatusListResolver.checkStatus.mockResolvedValue(false);

      await verifier.verifyDelegationCredential(mockValidVC);

      // Clear specific entry
      verifier.clearCacheEntry("urn:delegation:123");

      // Next call should verify again
      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: false });

      const result = await verifier.verifyDelegationCredential(mockValidVC);
      expect(result.valid).toBe(false);
      expect(result.cached).toBeUndefined();
    });
  });

  describe("performance metrics", () => {
    it("should include timing metrics in results", async () => {
      await setupDefaultContractsMocks();
      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: true });
      mockStatusListResolver.checkStatus.mockResolvedValue(false);

      const result = await verifier.verifyDelegationCredential(mockValidVC);

      expect(result.metrics).toBeDefined();
      expect(result.metrics?.totalMs).toBeGreaterThanOrEqual(0);
      expect(result.metrics?.basicCheckMs).toBeGreaterThanOrEqual(0);
      expect(result.metrics?.signatureCheckMs).toBeGreaterThanOrEqual(0);
      expect(result.metrics?.statusCheckMs).toBeGreaterThanOrEqual(0);
    });

    it("should report zero timing for skipped checks", async () => {
      await setupDefaultContractsMocks();
      const result = await verifier.verifyDelegationCredential(mockValidVC, {
        skipSignature: true,
        skipStatus: true,
      });

      expect(result.metrics?.signatureCheckMs).toBe(0);
      expect(result.metrics?.statusCheckMs).toBe(0);
    });
  });

  describe("error handling", () => {
    it("should handle DID resolver errors gracefully", async () => {
      await setupDefaultContractsMocks();
      mockDidResolver.resolve.mockRejectedValue(new Error("Network timeout"));

      const result = await verifier.verifyDelegationCredential(mockValidVC);

      expect(result.valid).toBe(false);
      expect(result.reason).toContain(
        "Signature verification error: Network timeout"
      );
    });

    it("should handle status list resolver errors gracefully", async () => {
      await setupDefaultContractsMocks();
      const vcWithStatus = {
        ...mockValidVC,
        credentialStatus: {
          id: "https://example.com/status#123",
          type: "StatusList2021Entry" as const,
          statusPurpose: "revocation" as const,
          statusListIndex: "123",
          statusListCredential: "https://example.com/status",
        },
      };

      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: true });
      mockStatusListResolver.checkStatus.mockRejectedValue(
        new Error("Status list unavailable")
      );

      const result = await verifier.verifyDelegationCredential(vcWithStatus);

      expect(result.valid).toBe(false);
      expect(result.reason).toContain(
        "Status check error: Status list unavailable"
      );
    });

    it("should handle signature verifier errors gracefully", async () => {
      await setupDefaultContractsMocks();
      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });

      mockSignatureVerifier.mockRejectedValue(
        new Error("Signature algorithm unsupported")
      );
      mockStatusListResolver.checkStatus.mockResolvedValue(false);

      const result = await verifier.verifyDelegationCredential(mockValidVC);

      expect(result.valid).toBe(false);
      expect(result.reason).toContain(
        "Signature verification error: Signature algorithm unsupported"
      );
    });
  });

  describe("findVerificationMethod", () => {
    // This is a private method, but we can test it indirectly through the main verification flow
    it("should find verification method by ID", async () => {
      await setupDefaultContractsMocks();
      const didDoc = {
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
          {
            id: "did:web:example.com:issuer#key-2",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "other-key" },
          },
        ],
      };

      mockDidResolver.resolve.mockResolvedValue(didDoc);
      mockSignatureVerifier.mockResolvedValue({ valid: true });
      mockStatusListResolver.checkStatus.mockResolvedValue(false);

      const result = await verifier.verifyDelegationCredential(mockValidVC);

      expect(result.valid).toBe(true);
      expect(mockSignatureVerifier).toHaveBeenCalledWith(mockValidVC, {
        kty: "OKP",
        crv: "Ed25519",
        x: "mock-key",
      });
    });
  });

  describe("E2E: StatusList2021 missing storage → verifier rejects", () => {
    it("should return valid: false when status list resolver throws (missing storage)", async () => {
      await setupDefaultContractsMocks();
      const vcWithStatus = {
        ...mockValidVC,
        credentialStatus: {
          id: "https://example.com/status#123",
          type: "StatusList2021Entry" as const,
          statusPurpose: "revocation" as const,
          statusListIndex: "123",
          statusListCredential: "https://example.com/status",
        },
      };

      mockDidResolver.resolve.mockResolvedValue({
        id: "did:web:example.com:issuer",
        verificationMethod: [
          {
            id: "did:web:example.com:issuer#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:example.com:issuer",
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mock-key" },
          },
        ],
      });
      mockSignatureVerifier.mockResolvedValue({ valid: true });

      // Simulate StatusList2021Manager.checkStatus throwing on missing storage
      mockStatusListResolver.checkStatus.mockRejectedValue(
        new Error("Status list not found: https://example.com/status — cannot determine revocation status")
      );

      const result = await verifier.verifyDelegationCredential(vcWithStatus);

      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Status list not found");
      expect(result.reason).toContain("cannot determine revocation status");
      expect(result.checks?.statusValid).toBe(false);
    });
  });
});
