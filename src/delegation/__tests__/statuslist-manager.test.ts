/**
 * Tests for StatusList2021Manager
 *
 * Covers:
 * - Status entry allocation
 * - Status updates (revoke/restore)
 * - Status checking
 * - Status list creation
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  StatusList2021Manager,
  createStatusListManager,
  type StatusListStorageProvider,
  type StatusListIdentityProvider,
} from "../statuslist-manager.js";
import type { VCSigningFunction } from "../vc-issuer.js";
import type { CompressionFunction, DecompressionFunction } from "../bitstring.js";
import type {
  StatusList2021Credential,
  CredentialStatus,
} from "../../types/protocol.js";

describe("StatusList2021Manager", () => {
  let mockStorage: StatusListStorageProvider;
  let mockIdentity: StatusListIdentityProvider;
  let mockSigningFunction: VCSigningFunction;
  let mockCompressor: CompressionFunction;
  let mockDecompressor: DecompressionFunction;

  // Create a simple bitstring representation for testing
  const createEncodedList = (size: number = 16): string => {
    // Create a simple base64url encoded "bitstring" for testing
    // This represents an empty list (all zeros)
    const bytes = new Uint8Array(Math.ceil(size / 8));
    return Buffer.from(bytes).toString("base64url");
  };

  const createStatusListCredential = (
    id: string,
    purpose: "revocation" | "suspension",
    encodedList?: string
  ): StatusList2021Credential => ({
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/vc/status-list/2021/v1",
    ],
    id,
    type: ["VerifiableCredential", "StatusList2021Credential"],
    issuer: "did:key:z6MkIssuer",
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: `${id}#list`,
      type: "StatusList2021",
      statusPurpose: purpose,
      encodedList: encodedList || createEncodedList(),
    },
    proof: {
      type: "Ed25519Signature2020",
      created: new Date().toISOString(),
      verificationMethod: "did:key:z6MkIssuer#z6MkIssuer",
      proofPurpose: "assertionMethod",
      proofValue: "mock-proof-value",
    },
  });

  beforeEach(() => {
    mockStorage = {
      getStatusList: vi.fn().mockResolvedValue(null),
      setStatusList: vi.fn().mockResolvedValue(undefined),
      allocateIndex: vi.fn().mockResolvedValue(0),
    };

    mockIdentity = {
      getDid: vi.fn().mockReturnValue("did:key:z6MkTestIssuer"),
      getKeyId: vi.fn().mockReturnValue("did:key:z6MkTestIssuer#z6MkTestIssuer"),
    };

    mockSigningFunction = vi.fn().mockResolvedValue({
      type: "Ed25519Signature2020",
      created: new Date().toISOString(),
      verificationMethod: "did:key:z6MkTestIssuer#z6MkTestIssuer",
      proofPurpose: "assertionMethod",
      proofValue: "mock-signature",
    });

    // Simple mock compressor/decompressor (just passes through for testing)
    mockCompressor = {
      compress: vi.fn().mockImplementation(async (data: Uint8Array) => data),
    };

    mockDecompressor = {
      decompress: vi.fn().mockImplementation(async (data: Uint8Array) => data),
    };
  });

  describe("constructor and configuration", () => {
    it("should use default configuration values", () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      expect(manager.getStatusListBaseUrl()).toBe("https://status.example.com");
      expect(manager.getDefaultListSize()).toBe(131072); // 128K
    });

    it("should accept custom configuration values", () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor,
        {
          statusListBaseUrl: "https://custom.example.com/status",
          defaultListSize: 65536,
        }
      );

      expect(manager.getStatusListBaseUrl()).toBe(
        "https://custom.example.com/status"
      );
      expect(manager.getDefaultListSize()).toBe(65536);
    });
  });

  describe("allocateStatusEntry", () => {
    it("should allocate a revocation status entry", async () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      vi.mocked(mockStorage.allocateIndex).mockResolvedValue(42);

      const entry = await manager.allocateStatusEntry("revocation");

      expect(entry).toEqual({
        id: "https://status.example.com/revocation/v1#42",
        type: "StatusList2021Entry",
        statusPurpose: "revocation",
        statusListIndex: "42",
        statusListCredential: "https://status.example.com/revocation/v1",
      });

      expect(mockStorage.allocateIndex).toHaveBeenCalledWith(
        "https://status.example.com/revocation/v1"
      );
    });

    it("should allocate a suspension status entry", async () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      vi.mocked(mockStorage.allocateIndex).mockResolvedValue(100);

      const entry = await manager.allocateStatusEntry("suspension");

      expect(entry).toEqual({
        id: "https://status.example.com/suspension/v1#100",
        type: "StatusList2021Entry",
        statusPurpose: "suspension",
        statusListIndex: "100",
        statusListCredential: "https://status.example.com/suspension/v1",
      });
    });

    it("should create status list if it doesn't exist", async () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      vi.mocked(mockStorage.getStatusList).mockResolvedValue(null);

      await manager.allocateStatusEntry("revocation");

      // Should check if status list exists
      expect(mockStorage.getStatusList).toHaveBeenCalled();
      // Should create new status list
      expect(mockStorage.setStatusList).toHaveBeenCalledWith(
        "https://status.example.com/revocation/v1",
        expect.objectContaining({
          type: ["VerifiableCredential", "StatusList2021Credential"],
          credentialSubject: expect.objectContaining({
            type: "StatusList2021",
            statusPurpose: "revocation",
          }),
        })
      );
    });

    it("should not create status list if it already exists", async () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      const existingCredential = createStatusListCredential(
        "https://status.example.com/revocation/v1",
        "revocation"
      );
      vi.mocked(mockStorage.getStatusList).mockResolvedValue(
        existingCredential
      );

      await manager.allocateStatusEntry("revocation");

      // Should check if exists
      expect(mockStorage.getStatusList).toHaveBeenCalled();
      // Should NOT create new one
      expect(mockStorage.setStatusList).not.toHaveBeenCalled();
    });
  });

  describe("updateStatus", () => {
    it("should revoke a credential by setting its status bit", async () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      const statusListId = "https://status.example.com/revocation/v1";
      const existingCredential = createStatusListCredential(
        statusListId,
        "revocation"
      );
      vi.mocked(mockStorage.getStatusList).mockResolvedValue(
        existingCredential
      );

      const credentialStatus: CredentialStatus = {
        id: `${statusListId}#5`,
        type: "StatusList2021Entry",
        statusPurpose: "revocation",
        statusListIndex: "5",
        statusListCredential: statusListId,
      };

      await manager.updateStatus(credentialStatus, true);

      // Should save updated status list
      expect(mockStorage.setStatusList).toHaveBeenCalledWith(
        statusListId,
        expect.objectContaining({
          credentialSubject: expect.objectContaining({
            encodedList: expect.any(String),
          }),
          proof: expect.any(Object),
        })
      );
    });

    it("should restore a credential by clearing its status bit", async () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      const statusListId = "https://status.example.com/revocation/v1";
      // Create a credential where bit 5 is already set
      const bytes = new Uint8Array(2);
      bytes[0] = 0b00000100; // Bit 5 is set (MSB-first: 0x80 >> 5)
      const encodedList = Buffer.from(bytes).toString("base64url");
      const existingCredential = createStatusListCredential(
        statusListId,
        "revocation",
        encodedList
      );
      vi.mocked(mockStorage.getStatusList).mockResolvedValue(
        existingCredential
      );

      const credentialStatus: CredentialStatus = {
        id: `${statusListId}#5`,
        type: "StatusList2021Entry",
        statusPurpose: "revocation",
        statusListIndex: "5",
        statusListCredential: statusListId,
      };

      await manager.updateStatus(credentialStatus, false);

      // Should re-sign and save
      expect(mockSigningFunction).toHaveBeenCalled();
      expect(mockStorage.setStatusList).toHaveBeenCalled();
    });

    it("should throw error if status list not found", async () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      vi.mocked(mockStorage.getStatusList).mockResolvedValue(null);

      const credentialStatus: CredentialStatus = {
        id: "https://status.example.com/revocation/v1#5",
        type: "StatusList2021Entry",
        statusPurpose: "revocation",
        statusListIndex: "5",
        statusListCredential: "https://status.example.com/revocation/v1",
      };

      await expect(
        manager.updateStatus(credentialStatus, true)
      ).rejects.toThrow("Status list not found");
    });
  });

  describe("checkStatus", () => {
    it("should return false for non-revoked credential", async () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      const statusListId = "https://status.example.com/revocation/v1";
      // Empty bitstring (all zeros)
      const existingCredential = createStatusListCredential(
        statusListId,
        "revocation"
      );
      vi.mocked(mockStorage.getStatusList).mockResolvedValue(
        existingCredential
      );

      const credentialStatus: CredentialStatus = {
        id: `${statusListId}#5`,
        type: "StatusList2021Entry",
        statusPurpose: "revocation",
        statusListIndex: "5",
        statusListCredential: statusListId,
      };

      const isRevoked = await manager.checkStatus(credentialStatus);

      expect(isRevoked).toBe(false);
    });

    it("should return true for revoked credential", async () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      const statusListId = "https://status.example.com/revocation/v1";
      // Create bitstring with bit 5 set
      const bytes = new Uint8Array(2);
      bytes[0] = 0b00000100; // Bit 5 is set (MSB-first: 0x80 >> 5)
      const encodedList = Buffer.from(bytes).toString("base64url");
      const existingCredential = createStatusListCredential(
        statusListId,
        "revocation",
        encodedList
      );
      vi.mocked(mockStorage.getStatusList).mockResolvedValue(
        existingCredential
      );

      const credentialStatus: CredentialStatus = {
        id: `${statusListId}#5`,
        type: "StatusList2021Entry",
        statusPurpose: "revocation",
        statusListIndex: "5",
        statusListCredential: statusListId,
      };

      const isRevoked = await manager.checkStatus(credentialStatus);

      expect(isRevoked).toBe(true);
    });

    it("throws (fail-closed) when the list statusPurpose ≠ the credential's (wrong-list bypass)", async () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      const statusListId = "https://status.example.com/revocation/v1";
      // A SUSPENSION list (all-clear at index 5) is resolved for a REVOCATION credential. Pre-fix,
      // the clear bit read as "not revoked" — a fail-OPEN bypass. It must throw instead.
      const wrongPurposeList = createStatusListCredential(statusListId, "suspension");
      vi.mocked(mockStorage.getStatusList).mockResolvedValue(wrongPurposeList);

      const credentialStatus: CredentialStatus = {
        id: `${statusListId}#5`,
        type: "StatusList2021Entry",
        statusPurpose: "revocation",
        statusListIndex: "5",
        statusListCredential: statusListId,
      };

      await expect(manager.checkStatus(credentialStatus)).rejects.toThrow(/statusPurpose mismatch/);
    });

    it("should throw if status list doesn't exist (fail closed)", async () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      vi.mocked(mockStorage.getStatusList).mockResolvedValue(null);

      const credentialStatus: CredentialStatus = {
        id: "https://status.example.com/revocation/v1#5",
        type: "StatusList2021Entry",
        statusPurpose: "revocation",
        statusListIndex: "5",
        statusListCredential: "https://status.example.com/revocation/v1",
      };

      await expect(
        manager.checkStatus(credentialStatus)
      ).rejects.toThrow("Status list not found");
    });
  });

  describe("getRevokedIndices", () => {
    it("should return empty array if status list doesn't exist", async () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      vi.mocked(mockStorage.getStatusList).mockResolvedValue(null);

      const indices = await manager.getRevokedIndices(
        "https://status.example.com/revocation/v1"
      );

      expect(indices).toEqual([]);
    });

    it("should return indices of set bits", async () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      const statusListId = "https://status.example.com/revocation/v1";
      // Create bitstring with bits 0, 2, and 5 set
      const bytes = new Uint8Array(2);
      bytes[0] = 0b10100100; // Bits 0, 2, 5 are set (MSB-first: 0x80 >> i)
      const encodedList = Buffer.from(bytes).toString("base64url");
      const existingCredential = createStatusListCredential(
        statusListId,
        "revocation",
        encodedList
      );
      vi.mocked(mockStorage.getStatusList).mockResolvedValue(
        existingCredential
      );

      const indices = await manager.getRevokedIndices(statusListId);

      expect(indices).toContain(0);
      expect(indices).toContain(2);
      expect(indices).toContain(5);
    });
  });

  describe("createStatusListManager factory", () => {
    it("should create a StatusList2021Manager instance", () => {
      const manager = createStatusListManager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor,
        {
          statusListBaseUrl: "https://factory.example.com/status",
        }
      );

      expect(manager).toBeInstanceOf(StatusList2021Manager);
      expect(manager.getStatusListBaseUrl()).toBe(
        "https://factory.example.com/status"
      );
    });

    it("should work without options", () => {
      const manager = createStatusListManager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      expect(manager).toBeInstanceOf(StatusList2021Manager);
      expect(manager.getStatusListBaseUrl()).toBe("https://status.example.com");
    });
  });

  describe("checkStatus fail-closed behavior", () => {
    it("should throw with the status list URL in the error message", async () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      vi.mocked(mockStorage.getStatusList).mockResolvedValue(null);

      const statusListUrl = "https://status.example.com/revocation/v1";
      const credentialStatus: CredentialStatus = {
        id: `${statusListUrl}#5`,
        type: "StatusList2021Entry",
        statusPurpose: "revocation",
        statusListIndex: "5",
        statusListCredential: statusListUrl,
      };

      await expect(manager.checkStatus(credentialStatus)).rejects.toThrow(
        statusListUrl
      );
    });

    it("should throw when storage provider rejects", async () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      vi.mocked(mockStorage.getStatusList).mockRejectedValue(
        new Error("Redis connection refused")
      );

      const credentialStatus: CredentialStatus = {
        id: "https://status.example.com/revocation/v1#5",
        type: "StatusList2021Entry",
        statusPurpose: "revocation",
        statusListIndex: "5",
        statusListCredential: "https://status.example.com/revocation/v1",
      };

      await expect(manager.checkStatus(credentialStatus)).rejects.toThrow(
        "Redis connection refused"
      );
    });

    it("should still return false for non-revoked credential with valid storage", async () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      const statusListId = "https://status.example.com/revocation/v1";
      const existingCredential = createStatusListCredential(
        statusListId,
        "revocation"
      );
      vi.mocked(mockStorage.getStatusList).mockResolvedValue(existingCredential);

      const credentialStatus: CredentialStatus = {
        id: `${statusListId}#3`,
        type: "StatusList2021Entry",
        statusPurpose: "revocation",
        statusListIndex: "3",
        statusListCredential: statusListId,
      };

      const isRevoked = await manager.checkStatus(credentialStatus);
      expect(isRevoked).toBe(false);
    });

    it("should still return true for revoked credential with valid storage", async () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        mockCompressor,
        mockDecompressor
      );

      const statusListId = "https://status.example.com/revocation/v1";
      const bytes = new Uint8Array(2);
      bytes[0] = 0b00010000; // Bit 3 set (MSB-first: 0x80 >> 3)
      const encodedList = Buffer.from(bytes).toString("base64url");
      const existingCredential = createStatusListCredential(
        statusListId,
        "revocation",
        encodedList
      );
      vi.mocked(mockStorage.getStatusList).mockResolvedValue(existingCredential);

      const credentialStatus: CredentialStatus = {
        id: `${statusListId}#3`,
        type: "StatusList2021Entry",
        statusPurpose: "revocation",
        statusListIndex: "3",
        statusListCredential: statusListId,
      };

      const isRevoked = await manager.checkStatus(credentialStatus);
      expect(isRevoked).toBe(true);
    });
  });
});
