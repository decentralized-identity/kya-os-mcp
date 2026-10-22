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
import {
  BitstringManager,
  type CompressionFunction,
  type DecompressionFunction,
} from "../bitstring.js";
import { MemoryStatusListStorage } from "../storage/memory-statuslist-storage.js";
import type {
  StatusList2021Credential,
  CredentialStatus,
  Proof,
} from "../../types/protocol.js";
import { gzipSync } from "node:zlib";
import { statusListGzipCodec } from "../../utils/statuslist-gzip.js";
import { createRevocationChecker } from "../../card/revocation.js";

/** The `encodedList` of a raw bitstring, GZIP'd independently of the codec under test. */
const encodedListOf = (bytes: Uint8Array): string =>
  `u${Buffer.from(gzipSync(bytes)).toString("base64url")}`;

describe("StatusList2021Manager", () => {
  let mockStorage: StatusListStorageProvider;
  let mockIdentity: StatusListIdentityProvider;
  let mockSigningFunction: VCSigningFunction;

  // An empty list (all zeros) for testing
  const createEncodedList = (size: number = 16): string =>
    encodedListOf(new Uint8Array(Math.ceil(size / 8)));

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
  });

  describe("constructor and configuration", () => {
    it("should use default configuration values", () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        statusListGzipCodec,
        statusListGzipCodec
      );

      expect(manager.getStatusListBaseUrl()).toBe("https://status.example.com");
      expect(manager.getDefaultListSize()).toBe(131072); // 128K
    });

    it("should accept custom configuration values", () => {
      const manager = new StatusList2021Manager(
        mockStorage,
        mockIdentity,
        mockSigningFunction,
        statusListGzipCodec,
        statusListGzipCodec,
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
        statusListGzipCodec,
        statusListGzipCodec
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
        statusListGzipCodec,
        statusListGzipCodec
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
        statusListGzipCodec,
        statusListGzipCodec
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
        statusListGzipCodec,
        statusListGzipCodec
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
        statusListGzipCodec,
        statusListGzipCodec
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
        statusListGzipCodec,
        statusListGzipCodec
      );

      const statusListId = "https://status.example.com/revocation/v1";
      // Create a credential where bit 5 is already set
      const bytes = new Uint8Array(2);
      bytes[0] = 0b00000100; // Bit 5 is set (MSB-first: 0x80 >> 5)
      const encodedList = encodedListOf(bytes);
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
        statusListGzipCodec,
        statusListGzipCodec
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
        statusListGzipCodec,
        statusListGzipCodec
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
        statusListGzipCodec,
        statusListGzipCodec
      );

      const statusListId = "https://status.example.com/revocation/v1";
      // Create bitstring with bit 5 set
      const bytes = new Uint8Array(2);
      bytes[0] = 0b00000100; // Bit 5 is set (MSB-first: 0x80 >> 5)
      const encodedList = encodedListOf(bytes);
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
        statusListGzipCodec,
        statusListGzipCodec
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
        statusListGzipCodec,
        statusListGzipCodec
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
        statusListGzipCodec,
        statusListGzipCodec
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
        statusListGzipCodec,
        statusListGzipCodec
      );

      const statusListId = "https://status.example.com/revocation/v1";
      // Create bitstring with bits 0, 2, and 5 set
      const bytes = new Uint8Array(2);
      bytes[0] = 0b10100100; // Bits 0, 2, 5 are set (MSB-first: 0x80 >> i)
      const encodedList = encodedListOf(bytes);
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
        statusListGzipCodec,
        statusListGzipCodec,
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
        statusListGzipCodec,
        statusListGzipCodec
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
        statusListGzipCodec,
        statusListGzipCodec
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
        statusListGzipCodec,
        statusListGzipCodec
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
        statusListGzipCodec,
        statusListGzipCodec
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
        statusListGzipCodec,
        statusListGzipCodec
      );

      const statusListId = "https://status.example.com/revocation/v1";
      const bytes = new Uint8Array(2);
      bytes[0] = 0b00010000; // Bit 3 set (MSB-first: 0x80 >> 3)
      const encodedList = encodedListOf(bytes);
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

describe("StatusList2021Manager over memory storage", () => {
  const identity = { getDid: () => "did:web:issuer.example", getKeyId: () => "did:web:issuer.example#k" };
  const proof: Proof = { type: "Ed25519Signature2020", proofValue: "x" };
  const options = { statusListBaseUrl: "https://status.example", defaultListSize: 1024 };

  it("does not let a racing first allocation replace a list that has since recorded a revocation", async () => {
    // Hold back the second signature over a still-empty list: before list
    // creation was serialized, that was the racing allocation's fresh list,
    // and releasing it after the revocation below overwrote the revoked bit.
    const emptyList = await new BitstringManager(options.defaultListSize, statusListGzipCodec, statusListGzipCodec).encode();
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let emptySignatures = 0;
    const sign: VCSigningFunction = async (canonical) => {
      if (canonical.includes(emptyList) && ++emptySignatures === 2) await held;
      return proof;
    };
    const manager = new StatusList2021Manager(new MemoryStatusListStorage(), identity, sign, statusListGzipCodec, statusListGzipCodec, options);

    const first = manager.allocateStatusEntry("revocation");
    const second = manager.allocateStatusEntry("revocation");
    const entry = await first;
    await manager.updateStatus(entry, true);
    expect(await manager.checkStatus(entry)).toBe(true);

    release();
    await second;
    expect(await manager.checkStatus(entry)).toBe(true);
  });

  it("rejects a non-canonical statusListIndex on update instead of flipping another credential's bit", async () => {
    const manager = new StatusList2021Manager(new MemoryStatusListStorage(), identity, async () => proof, statusListGzipCodec, statusListGzipCodec, options);
    const entry = await manager.allocateStatusEntry("revocation");
    const other = { ...entry, statusListIndex: "5" };

    for (const statusListIndex of ["5abc", " 5", "0x5", "5.0", ""]) {
      await expect(manager.updateStatus({ ...entry, statusListIndex }, true)).rejects.toThrow(/statusListIndex/);
    }
    expect(await manager.checkStatus(other)).toBe(false);
    expect(await manager.getRevokedIndices(entry.statusListCredential)).toEqual([]);
  });

  it("refuses to allocate an index the list cannot hold", async () => {
    const manager = new StatusList2021Manager(new MemoryStatusListStorage(), identity, async () => proof, statusListGzipCodec, statusListGzipCodec, {
      ...options,
      defaultListSize: 16,
    });
    const entries = [];
    for (let i = 0; i < 16; i++) entries.push(await manager.allocateStatusEntry("revocation"));
    expect(entries.at(-1)?.statusListIndex).toBe("15");

    await expect(manager.allocateStatusEntry("revocation")).rejects.toThrow(
      "Status list https://status.example/revocation/v1 is full: index 16 is outside its 16 entries",
    );
  });
});

describe("StatusList2021Manager status lists are GZIP", () => {
  const identity = { getDid: () => "did:web:issuer.example", getKeyId: () => "did:web:issuer.example#k" };
  const sign: VCSigningFunction = async () => ({ type: "Ed25519Signature2020", proofValue: "x" });
  const passThrough: CompressionFunction & DecompressionFunction = {
    compress: async (data) => data,
    decompress: async (data) => data,
  };

  /** Revoke entries `revoked` of `count` allocated through `manager`. */
  async function allocate(manager: StatusList2021Manager, count: number, revoked: number[]) {
    const entries: CredentialStatus[] = [];
    for (let i = 0; i < count; i++) entries.push(await manager.allocateStatusEntry("revocation"));
    for (const index of revoked) await manager.updateStatus(entries[index]!, true);
    return entries;
  }

  it("a default-constructed manager publishes lists the card revocation checker reads the same way", async () => {
    const storage = new MemoryStatusListStorage();
    const manager = createStatusListManager(storage, identity, sign);
    const entries = await allocate(manager, 4, [1]);

    const list = await storage.getStatusList(entries[0]!.statusListCredential);
    expect(list?.credentialSubject.encodedList.startsWith("uH4sI")).toBe(true); // multibase u + GZIP magic
    const check = createRevocationChecker({
      fetch: async () => ({ ok: true, status: 200, json: async () => list }),
    });
    for (const [index, entry] of entries.entries()) {
      const revoked = index === 1;
      expect(await manager.checkStatus(entry)).toBe(revoked);
      expect(await check(entry)).toEqual({ revoked, fresh: true });
    }
  });

  it("a pass-through reader of a GZIP list throws instead of reading revoked entries as live", async () => {
    const storage = new MemoryStatusListStorage();
    const entries = await allocate(createStatusListManager(storage, identity, sign), 4, [0, 1, 2]);

    // Read as bits, the GZIP header `1f 8b` leaves indices 0-2 clear.
    const reader = new StatusList2021Manager(storage, identity, sign, statusListGzipCodec, passThrough);
    for (const entry of entries.slice(0, 3)) {
      await expect(reader.checkStatus(entry)).rejects.toThrow(/input unchanged/);
    }
    await expect(reader.getRevokedIndices(entries[0]!.statusListCredential)).rejects.toThrow(/input unchanged/);
  });

  it("refuses to publish a list with a compressor that does not GZIP", async () => {
    const storage = new MemoryStatusListStorage();
    const manager = new StatusList2021Manager(storage, identity, sign, passThrough, statusListGzipCodec);

    await expect(manager.allocateStatusEntry("revocation")).rejects.toThrow(/not GZIP/);
    expect(await storage.getStatusList(`${manager.getStatusListBaseUrl()}/revocation/v1`)).toBeNull();
  });
});
