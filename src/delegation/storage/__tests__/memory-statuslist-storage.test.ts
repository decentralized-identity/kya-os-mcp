import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStatusListStorage } from "../memory-statuslist-storage.js";
import type { StatusList2021Credential } from "../../../types/protocol.js";

describe("MemoryStatusListStorage", () => {
  let storage: MemoryStatusListStorage;

  const mockStatusListCredential: StatusList2021Credential = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/vc/status-list/2021/v1",
    ],
    id: "https://example.com/status/revocation/v1",
    type: ["VerifiableCredential", "StatusList2021Credential"],
    issuer: "did:web:example.com",
    issuanceDate: "2024-01-01T00:00:00Z",
    credentialSubject: {
      id: "https://example.com/status/revocation/v1#list",
      type: "StatusList2021",
      statusPurpose: "revocation",
      encodedList: "H4sIAAAAAAAAA2NgGAWjYBSMglEwCkYBqwAA0kEQVAEAAA==",
    },
    proof: {
      type: "Ed25519Signature2020",
      created: "2024-01-01T00:00:00Z",
      verificationMethod: "did:web:example.com#key-1",
      proofPurpose: "assertionMethod",
      proofValue: "mock-proof",
    },
  };

  beforeEach(() => {
    storage = new MemoryStatusListStorage();
  });

  describe("getStatusList", () => {
    it("should return null for non-existent status list", async () => {
      const result = await storage.getStatusList("non-existent");
      expect(result).toBeNull();
    });

    it("should return stored status list", async () => {
      await storage.setStatusList(
        "https://example.com/status/revocation/v1",
        mockStatusListCredential
      );

      const result = await storage.getStatusList(
        "https://example.com/status/revocation/v1"
      );

      expect(result).toEqual(mockStatusListCredential);
    });
  });

  describe("setStatusList", () => {
    it("should store status list", async () => {
      await storage.setStatusList(
        "https://example.com/status/revocation/v1",
        mockStatusListCredential
      );

      const result = await storage.getStatusList(
        "https://example.com/status/revocation/v1"
      );
      expect(result).toEqual(mockStatusListCredential);
    });

    it("should overwrite existing status list", async () => {
      await storage.setStatusList(
        "https://example.com/status/revocation/v1",
        mockStatusListCredential
      );

      const updatedCredential = {
        ...mockStatusListCredential,
        issuanceDate: "2024-01-02T00:00:00Z",
      };

      await storage.setStatusList(
        "https://example.com/status/revocation/v1",
        updatedCredential
      );

      const result = await storage.getStatusList(
        "https://example.com/status/revocation/v1"
      );
      expect(result?.issuanceDate).toBe("2024-01-02T00:00:00Z");
    });

    it("should store multiple status lists independently", async () => {
      const revocationCredential = mockStatusListCredential;
      const suspensionCredential = {
        ...mockStatusListCredential,
        id: "https://example.com/status/suspension/v1",
        credentialSubject: {
          ...mockStatusListCredential.credentialSubject,
          id: "https://example.com/status/suspension/v1#list",
          statusPurpose: "suspension" as const,
        },
      };

      await storage.setStatusList(
        "https://example.com/status/revocation/v1",
        revocationCredential
      );
      await storage.setStatusList(
        "https://example.com/status/suspension/v1",
        suspensionCredential
      );

      const revocation = await storage.getStatusList(
        "https://example.com/status/revocation/v1"
      );
      const suspension = await storage.getStatusList(
        "https://example.com/status/suspension/v1"
      );

      expect(revocation?.credentialSubject.statusPurpose).toBe("revocation");
      expect(suspension?.credentialSubject.statusPurpose).toBe("suspension");
    });
  });

  describe("allocateIndex", () => {
    it("should allocate sequential indices starting from 0", async () => {
      const statusListId = "https://example.com/status/revocation/v1";

      const index1 = await storage.allocateIndex(statusListId);
      const index2 = await storage.allocateIndex(statusListId);
      const index3 = await storage.allocateIndex(statusListId);

      expect(index1).toBe(0);
      expect(index2).toBe(1);
      expect(index3).toBe(2);
    });

    it("should allocate indices independently per status list", async () => {
      const list1 = "https://example.com/status/revocation/v1";
      const list2 = "https://example.com/status/suspension/v1";

      const index1 = await storage.allocateIndex(list1);
      const index2 = await storage.allocateIndex(list2);
      const index3 = await storage.allocateIndex(list1);

      expect(index1).toBe(0);
      expect(index2).toBe(0); // Independent counter
      expect(index3).toBe(1);
    });

    it("should continue from previous allocation after clear", async () => {
      const statusListId = "https://example.com/status/revocation/v1";

      await storage.allocateIndex(statusListId);
      await storage.allocateIndex(statusListId);
      storage.clear();

      const index = await storage.allocateIndex(statusListId);
      expect(index).toBe(0); // Starts fresh after clear
    });
  });

  describe("getIndexCount", () => {
    it("should return 0 for new status list", () => {
      const count = storage.getIndexCount("https://example.com/status/new");
      expect(count).toBe(0);
    });

    it("should return current allocation count", async () => {
      const statusListId = "https://example.com/status/revocation/v1";

      await storage.allocateIndex(statusListId);
      expect(storage.getIndexCount(statusListId)).toBe(1);

      await storage.allocateIndex(statusListId);
      expect(storage.getIndexCount(statusListId)).toBe(2);
    });
  });

  describe("clear", () => {
    it("should remove all status lists", async () => {
      await storage.setStatusList(
        "https://example.com/status/revocation/v1",
        mockStatusListCredential
      );

      storage.clear();

      const result = await storage.getStatusList(
        "https://example.com/status/revocation/v1"
      );
      expect(result).toBeNull();
    });

    it("should reset index counters", async () => {
      const statusListId = "https://example.com/status/revocation/v1";

      await storage.allocateIndex(statusListId);
      await storage.allocateIndex(statusListId);

      storage.clear();

      expect(storage.getIndexCount(statusListId)).toBe(0);
    });
  });

  describe("setEntryOwner and getEntryOwner", () => {
    it("record the delegation each entry of each list was allocated to", async () => {
      const revocation = "https://example.com/status/revocation/v1";
      const suspension = "https://example.com/status/suspension/v1";

      await storage.setEntryOwner(revocation, 0, "delegation-1");
      await storage.setEntryOwner(suspension, 0, "delegation-2");

      expect(await storage.getEntryOwner(revocation, 0)).toBe("delegation-1");
      expect(await storage.getEntryOwner(suspension, 0)).toBe("delegation-2");
      expect(await storage.getEntryOwner(revocation, 1)).toBeNull();
      expect(await storage.getEntryOwner("https://example.com/status/other", 0)).toBeNull();
    });

    it("forget every owner on clear", async () => {
      const revocation = "https://example.com/status/revocation/v1";
      await storage.setEntryOwner(revocation, 0, "delegation-1");

      storage.clear();

      expect(await storage.getEntryOwner(revocation, 0)).toBeNull();
    });
  });

  describe("getAllStatusListIds", () => {
    it("should return empty array when no status lists", () => {
      const ids = storage.getAllStatusListIds();
      expect(ids).toEqual([]);
    });

    it("should return all stored status list IDs", async () => {
      await storage.setStatusList(
        "https://example.com/status/revocation/v1",
        mockStatusListCredential
      );
      await storage.setStatusList("https://example.com/status/suspension/v1", {
        ...mockStatusListCredential,
        id: "https://example.com/status/suspension/v1",
      });

      const ids = storage.getAllStatusListIds();
      expect(ids).toContain("https://example.com/status/revocation/v1");
      expect(ids).toContain("https://example.com/status/suspension/v1");
      expect(ids.length).toBe(2);
    });
  });
});
