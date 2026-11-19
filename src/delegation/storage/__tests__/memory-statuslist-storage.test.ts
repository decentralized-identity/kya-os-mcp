import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStatusListStorage } from "../memory-statuslist-storage.js";
import { OwnMapStore } from "../../__tests__/helpers/status-list-writers.js";
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

  describe("conditional write", () => {
    const statusListId = "https://example.com/status/revocation/v1";
    const updated = { ...mockStatusListCredential, issuanceDate: "2024-01-02T00:00:00Z" };

    it("reads no list and no etag where none is stored", async () => {
      expect(await storage.getStatusListWithEtag(statusListId)).toBeNull();
    });

    it("creates a list for a null etag only while none is stored", async () => {
      expect(await storage.setStatusListIfMatch(statusListId, mockStatusListCredential, null)).toBe(true);
      expect(await storage.setStatusListIfMatch(statusListId, updated, null)).toBe(false);

      expect((await storage.getStatusListWithEtag(statusListId))?.credential).toEqual(mockStatusListCredential);
      expect(await storage.getStatusListVersionCount(statusListId)).toBe(1);
    });

    it("stores a list over the etag it was read with, and refuses that etag once another write lands", async () => {
      await storage.setStatusList(statusListId, mockStatusListCredential);
      const read = await storage.getStatusListWithEtag(statusListId);
      const other = await storage.getStatusListWithEtag(statusListId);

      expect(await storage.setStatusListIfMatch(statusListId, updated, read!.etag)).toBe(true);
      expect(await storage.setStatusListIfMatch(statusListId, mockStatusListCredential, other!.etag)).toBe(false);

      const stored = await storage.getStatusListWithEtag(statusListId);
      expect(stored?.credential).toEqual(updated);
      expect(stored?.etag).not.toBe(read!.etag);
      expect(await storage.getStatusListVersionCount(statusListId)).toBe(2);
    });

    it("gives a write through setStatusList a new etag too", async () => {
      await storage.setStatusList(statusListId, mockStatusListCredential);
      const read = await storage.getStatusListWithEtag(statusListId);
      await storage.setStatusList(statusListId, mockStatusListCredential);

      expect(await storage.setStatusListIfMatch(statusListId, updated, read!.etag)).toBe(false);
      expect(await storage.getStatusList(statusListId)).toEqual(mockStatusListCredential);
    });

    it("refuses a non-null etag where no list is stored, and never gives an etag again after clear", async () => {
      expect(await storage.setStatusListIfMatch(statusListId, updated, "1")).toBe(false);

      await storage.setStatusList(statusListId, mockStatusListCredential);
      const beforeClear = await storage.getStatusListWithEtag(statusListId);
      storage.clear();
      await storage.setStatusList(statusListId, mockStatusListCredential);

      expect(await storage.setStatusListIfMatch(statusListId, updated, beforeClear!.etag)).toBe(false);
    });

    it("reads and writes through a subclass's getStatusList and setStatusList", async () => {
      const calls: string[] = [];
      class Recording extends MemoryStatusListStorage {
        override async getStatusList(id: string) {
          calls.push("get");
          return super.getStatusList(id);
        }
        override async setStatusList(id: string, credential: StatusList2021Credential) {
          calls.push("set");
          await super.setStatusList(id, credential);
        }
      }
      const recording = new Recording();

      expect(await recording.setStatusListIfMatch(statusListId, mockStatusListCredential, null)).toBe(true);
      const read = await recording.getStatusListWithEtag(statusListId);
      expect(await recording.setStatusListIfMatch(statusListId, updated, read!.etag)).toBe(true);
      expect(await recording.setStatusListIfMatch(statusListId, updated, read!.etag)).toBe(false);

      // A creation first reads that no list is stored, through the subclass, since one that keeps
      // its lists elsewhere may hold one this class has no etag for.
      expect(calls).toEqual(["get", "set", "get", "set"]);
      expect(read?.credential).toEqual(mockStatusListCredential);
    });

    describe("of a subclass that keeps its lists elsewhere, with no super", () => {
      it("reads a stored list with an etag, and never creates a list over it", async () => {
        const own = new OwnMapStore();
        await own.setStatusList(statusListId, mockStatusListCredential);

        const read = await own.getStatusListWithEtag(statusListId);

        expect(read?.credential).toEqual(mockStatusListCredential);
        expect(typeof read?.etag).toBe("string");
        expect(read?.etag).not.toBe("");
        expect(await own.setStatusListIfMatch(statusListId, updated, null)).toBe(false);
        expect(await own.getStatusList(statusListId)).toEqual(mockStatusListCredential);
      });

      it("stores over the etag a list was read with, and refuses it once the list changed", async () => {
        const own = new OwnMapStore();
        await own.setStatusList(statusListId, mockStatusListCredential);
        const read = await own.getStatusListWithEtag(statusListId);
        const other = await own.getStatusListWithEtag(statusListId);

        expect(await own.setStatusListIfMatch(statusListId, updated, read!.etag)).toBe(true);
        expect(await own.setStatusListIfMatch(statusListId, mockStatusListCredential, other!.etag)).toBe(false);
        expect(await own.getStatusList(statusListId)).toEqual(updated);
      });

      it("names a list by what it holds, so an etag matches only the same list", async () => {
        const own = new OwnMapStore();
        await own.setStatusList(statusListId, mockStatusListCredential);
        const first = await own.getStatusListWithEtag(statusListId);
        await own.setStatusList(statusListId, updated);
        const changed = await own.getStatusListWithEtag(statusListId);
        await own.setStatusList(statusListId, mockStatusListCredential);
        const again = await own.getStatusListWithEtag(statusListId);

        expect(changed!.etag).not.toBe(first!.etag);
        expect(again!.etag).toBe(first!.etag);
      });
    });

    it("works through a Proxy, as a wrapper that logs or measures it makes one", async () => {
      const proxied = new Proxy(new MemoryStatusListStorage(), {});

      expect(await proxied.setStatusListIfMatch(statusListId, mockStatusListCredential, null)).toBe(true);
      const read = await proxied.getStatusListWithEtag(statusListId);
      expect(await proxied.setStatusListIfMatch(statusListId, updated, read!.etag)).toBe(true);
      expect(await proxied.setStatusListIfMatch(statusListId, mockStatusListCredential, read!.etag)).toBe(false);
      await proxied.setStatusList(statusListId, mockStatusListCredential);
      proxied.clear();

      expect(proxied.getAllStatusListIds()).toEqual([]);
    });

    it("keeps a conditional write atomic when a subclass's setStatusList waits before it stores", async () => {
      class Slow extends MemoryStatusListStorage {
        override async setStatusList(id: string, credential: StatusList2021Credential) {
          await new Promise((resolve) => setImmediate(resolve));
          await super.setStatusList(id, credential);
        }
      }
      const slow = new Slow();
      await slow.setStatusList(statusListId, mockStatusListCredential);
      const read = await slow.getStatusListWithEtag(statusListId);

      const [first, second] = await Promise.all([
        slow.setStatusListIfMatch(statusListId, updated, read!.etag),
        slow.setStatusListIfMatch(statusListId, { ...updated, issuanceDate: "2024-01-03T00:00:00Z" }, read!.etag),
      ]);

      expect([first, second]).toEqual([true, false]);
      expect((await slow.getStatusList(statusListId))?.issuanceDate).toBe(updated.issuanceDate);
      expect(await slow.getStatusListVersionCount(statusListId)).toBe(2);
    });

    it("hands back copies, so a change to what was read is not stored", async () => {
      await storage.setStatusList(statusListId, mockStatusListCredential);
      const read = await storage.getStatusListWithEtag(statusListId);
      read!.credential.issuanceDate = "mutated";

      expect((await storage.getStatusList(statusListId))?.issuanceDate).toBe(mockStatusListCredential.issuanceDate);
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
