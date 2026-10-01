import { describe, it, expect, beforeEach, vi, Mock } from "vitest";
import {
  CascadingRevocationManager,
  createCascadingRevocationManager,
  type RevocationEvent,
  type CascadingRevocationOptions,
} from "../cascading-revocation.js";
import {
  DelegationGraphManager,
  type DelegationNode,
} from "../delegation-graph.js";
import { StatusList2021Manager } from "../statuslist-manager.js";
import { MemoryDelegationGraphStorage } from "../storage/memory-graph-storage.js";
import { MemoryStatusListStorage } from "../storage/memory-statuslist-storage.js";
import type { CredentialStatus } from "../../types/protocol.js";
import { gzipSync, gunzipSync } from "node:zlib";

describe("CascadingRevocationManager", () => {
  let mockGraph: DelegationGraphManager;
  let mockStatusList: StatusList2021Manager;
  let revocationManager: CascadingRevocationManager;

  // Mock storage for graph
  const createMockGraphStorage = () => {
    const nodes = new Map<string, DelegationNode>();

    return {
      getNode: vi.fn(async (id: string) => nodes.get(id) || null),
      setNode: vi.fn(async (node: DelegationNode) => {
        nodes.set(node.id, { ...node });
      }),
      getChildren: vi.fn(async (id: string) => {
        const node = nodes.get(id);
        if (!node) return [];
        return node.children
          .map((childId) => nodes.get(childId))
          .filter((n): n is DelegationNode => n !== undefined);
      }),
      getChain: vi.fn(async (id: string) => {
        const chain: DelegationNode[] = [];
        let currentId: string | null = id;
        while (currentId) {
          const node = nodes.get(currentId);
          if (!node) break;
          chain.unshift(node);
          currentId = node.parentId;
        }
        return chain;
      }),
      getDescendants: vi.fn(async (id: string) => {
        const descendants: DelegationNode[] = [];
        const queue: string[] = [id];
        const visited = new Set<string>();

        while (queue.length > 0) {
          const currentId = queue.shift()!;
          if (visited.has(currentId)) continue;
          visited.add(currentId);

          const node = nodes.get(currentId);
          if (!node) continue;

          for (const childId of node.children) {
            if (!visited.has(childId)) {
              queue.push(childId);
              const childNode = nodes.get(childId);
              if (childNode) {
                descendants.push(childNode);
              }
            }
          }
        }
        return descendants;
      }),
      deleteNode: vi.fn(async (id: string) => {
        nodes.delete(id);
      }),
    };
  };

  beforeEach(() => {
    vi.clearAllMocks();

    // Create mock graph with storage
    const graphStorage = createMockGraphStorage();
    mockGraph = new DelegationGraphManager(graphStorage as any);

    // Create mock status list manager
    mockStatusList = {
      checkStatus: vi.fn().mockResolvedValue(false),
      updateStatus: vi.fn().mockResolvedValue(undefined),
    } as any;

    revocationManager = new CascadingRevocationManager(
      mockGraph,
      mockStatusList
    );
  });

  describe("constructor", () => {
    it("should create revocation manager with graph and status list", () => {
      const manager = new CascadingRevocationManager(mockGraph, mockStatusList);
      expect(manager).toBeInstanceOf(CascadingRevocationManager);
    });
  });

  describe("createCascadingRevocationManager", () => {
    it("should create a revocation manager instance", () => {
      const manager = createCascadingRevocationManager(
        mockGraph,
        mockStatusList
      );
      expect(manager).toBeInstanceOf(CascadingRevocationManager);
    });
  });

  describe("revokeDelegation", () => {
    it("should revoke a single delegation with no children", async () => {
      // Register a root delegation
      const node = await mockGraph.registerDelegation({
        id: "del-001",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#123",
      });

      const events = await revocationManager.revokeDelegation("del-001");

      expect(events).toHaveLength(1);
      expect(events[0].delegationId).toBe("del-001");
      expect(events[0].isRoot).toBe(true);
      expect(events[0].timestamp).toBeGreaterThan(0);
    });

    it("should cascade revocation to all descendants", async () => {
      // Create tree: root -> child1, child2 -> grandchild
      await mockGraph.registerDelegation({
        id: "del-root",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#root",
      });

      await mockGraph.registerDelegation({
        id: "del-child1",
        parentId: "del-root",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
        credentialStatusId: "https://example.com/status#child1",
      });

      await mockGraph.registerDelegation({
        id: "del-child2",
        parentId: "del-root",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject3",
        credentialStatusId: "https://example.com/status#child2",
      });

      await mockGraph.registerDelegation({
        id: "del-grandchild",
        parentId: "del-child1",
        issuerDid: "did:web:example.com:subject2",
        subjectDid: "did:web:example.com:subject4",
        credentialStatusId: "https://example.com/status#grandchild",
      });

      const events = await revocationManager.revokeDelegation("del-root");

      // Should revoke root + 3 descendants
      expect(events.length).toBeGreaterThanOrEqual(4);
      expect(events[0].delegationId).toBe("del-root");
      expect(events[0].isRoot).toBe(true);

      // Check that descendants were revoked
      const revokedIds = events.map((e) => e.delegationId);
      expect(revokedIds).toContain("del-child1");
      expect(revokedIds).toContain("del-child2");
      expect(revokedIds).toContain("del-grandchild");
    });

    it("should call onRevoke hook for each revocation", async () => {
      await mockGraph.registerDelegation({
        id: "del-root",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#root",
      });

      await mockGraph.registerDelegation({
        id: "del-child",
        parentId: "del-root",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
        credentialStatusId: "https://example.com/status#child",
      });

      const onRevokeHook = vi.fn().mockResolvedValue(undefined);

      const events = await revocationManager.revokeDelegation("del-root", {
        onRevoke: onRevokeHook,
      });

      expect(onRevokeHook).toHaveBeenCalledTimes(events.length);
      expect(onRevokeHook).toHaveBeenCalledWith(
        expect.objectContaining({
          delegationId: "del-root",
          isRoot: true,
        })
      );
    });

    it("should include reason in revocation events", async () => {
      await mockGraph.registerDelegation({
        id: "del-001",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#123",
      });

      const events = await revocationManager.revokeDelegation("del-001", {
        reason: "Security breach",
      });

      expect(events[0].reason).toBe("Security breach");
    });

    it("should set cascaded reason for descendants", async () => {
      await mockGraph.registerDelegation({
        id: "del-root",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#root",
      });

      await mockGraph.registerDelegation({
        id: "del-child",
        parentId: "del-root",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
        credentialStatusId: "https://example.com/status#child",
      });

      const events = await revocationManager.revokeDelegation("del-root", {
        reason: "Root revoked",
      });

      const childEvent = events.find((e) => e.delegationId === "del-child");
      expect(childEvent).toBeDefined();
      expect(childEvent?.reason).toContain("Cascaded from del-root");
      expect(childEvent?.parentId).toBe("del-root");
      expect(childEvent?.isRoot).toBe(false);
    });

    it("should throw error if delegation not found", async () => {
      await expect(
        revocationManager.revokeDelegation("non-existent")
      ).rejects.toThrow("Delegation not found");
    });

    it("should respect maxDepth option", async () => {
      // Create a deep chain (depth 0, 1, 2, 3, 4 = 5 levels)
      let parentId: string | null = null;
      for (let i = 0; i < 5; i++) {
        const id = `del-${i}`;
        await mockGraph.registerDelegation({
          id,
          parentId,
          issuerDid: `did:web:example.com:issuer${i}`,
          subjectDid: `did:web:example.com:subject${i + 1}`,
          credentialStatusId: `https://example.com/status#${i}`,
        });
        parentId = id;
      }

      // Should work with default maxDepth (100)
      await expect(
        revocationManager.revokeDelegation("del-0")
      ).resolves.toBeDefined();

      // Check depth of deepest node (del-4 has depth 4, which exceeds maxDepth 2)
      await expect(
        revocationManager.revokeDelegation("del-4", { maxDepth: 2 })
      ).rejects.toThrow("exceeds maximum");
    });

    it("should skip actual revocation in dry run mode", async () => {
      await mockGraph.registerDelegation({
        id: "del-001",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#123",
      });

      const events = await revocationManager.revokeDelegation("del-001", {
        dryRun: true,
      });

      expect(events).toHaveLength(1);
      expect(events[0].delegationId).toBe("del-001");
      // In dry run, updateStatus should not be called
      expect(mockStatusList.updateStatus).not.toHaveBeenCalled();
    });
  });

  describe("restoreDelegation", () => {
    it("should restore a revoked delegation", async () => {
      await mockGraph.registerDelegation({
        id: "del-001",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#123",
      });

      const event = await revocationManager.restoreDelegation("del-001");

      expect(event.delegationId).toBe("del-001");
      expect(event.isRoot).toBe(true);
      expect(event.reason).toBe("Restored");
      expect(mockStatusList.updateStatus).toHaveBeenCalled();
    });

    it("should throw error if delegation not found", async () => {
      await expect(
        revocationManager.restoreDelegation("non-existent")
      ).rejects.toThrow("Delegation not found");
    });

    it("should not cascade restore to children", async () => {
      await mockGraph.registerDelegation({
        id: "del-root",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#0", // Use numeric index
      });

      await mockGraph.registerDelegation({
        id: "del-child",
        parentId: "del-root",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
        credentialStatusId: "https://example.com/status#1", // Use numeric index
      });

      // Clear any previous calls
      vi.clearAllMocks();

      // Restore root - should not restore child
      const event = await revocationManager.restoreDelegation("del-root");

      expect(event.delegationId).toBe("del-root");
      // Should only call updateStatus once (for root, not child)
      // Note: updateStatus is only called if credentialStatusId exists and parses correctly
      const updateStatusMock = mockStatusList.updateStatus as Mock;
      if (updateStatusMock.mock.calls.length > 0) {
        expect(mockStatusList.updateStatus).toHaveBeenCalledTimes(1);
      }
    });
  });

  describe("isRevoked", () => {
    it("should return false for non-revoked delegation", async () => {
      await mockGraph.registerDelegation({
        id: "del-001",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#123",
      });

      mockStatusList.checkStatus = vi.fn().mockResolvedValue(false);

      const result = await revocationManager.isRevoked("del-001");

      expect(result.revoked).toBe(false);
    });

    it("should return true for directly revoked delegation", async () => {
      await mockGraph.registerDelegation({
        id: "del-001",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#123",
      });

      mockStatusList.checkStatus = vi.fn().mockResolvedValue(true);

      const result = await revocationManager.isRevoked("del-001");

      expect(result.revoked).toBe(true);
      expect(result.reason).toBe("Directly revoked");
      expect(result.revokedAncestor).toBeUndefined();
    });

    it("should return true if ancestor is revoked", async () => {
      await mockGraph.registerDelegation({
        id: "del-root",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#0", // Use numeric index
      });

      await mockGraph.registerDelegation({
        id: "del-child",
        parentId: "del-root",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
        credentialStatusId: "https://example.com/status#1", // Use numeric index
      });

      // Root is revoked (index 0), child is not
      mockStatusList.checkStatus = vi
        .fn()
        .mockImplementation(async (status: CredentialStatus) => {
          // parseCredentialStatus parses "#0" -> statusListIndex "0"
          if (
            status.statusListIndex === "0" ||
            status.id === "https://example.com/status#0"
          ) {
            return true;
          }
          return false;
        });

      const result = await revocationManager.isRevoked("del-child");

      expect(result.revoked).toBe(true);
      expect(result.reason).toBe("Ancestor revoked");
      expect(result.revokedAncestor).toBe("del-root");
    });

    it("should check chain from root to delegation", async () => {
      await mockGraph.registerDelegation({
        id: "del-root",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#0", // Use numeric index
      });

      await mockGraph.registerDelegation({
        id: "del-child",
        parentId: "del-root",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
        credentialStatusId: "https://example.com/status#1", // Use numeric index
      });

      mockStatusList.checkStatus = vi.fn().mockResolvedValue(false);

      await revocationManager.isRevoked("del-child");

      // Should check both root and child (if they have credentialStatusId)
      expect(mockStatusList.checkStatus).toHaveBeenCalled();
    });
  });

  describe("validateDelegation", () => {
    it("should return valid for non-revoked delegation", async () => {
      await mockGraph.registerDelegation({
        id: "del-001",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#123",
      });

      mockStatusList.checkStatus = vi.fn().mockResolvedValue(false);

      // Mock validateChain to return valid
      vi.spyOn(mockGraph, "validateChain").mockResolvedValue({ valid: true });

      const result = await revocationManager.validateDelegation("del-001");

      expect(result.valid).toBe(true);
    });

    it("should return invalid if delegation is revoked", async () => {
      await mockGraph.registerDelegation({
        id: "del-001",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#123",
      });

      mockStatusList.checkStatus = vi.fn().mockResolvedValue(true);

      const result = await revocationManager.validateDelegation("del-001");

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Delegation is revoked");
    });

    it("should return invalid if ancestor is revoked", async () => {
      await mockGraph.registerDelegation({
        id: "del-root",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#0", // Use numeric index
      });

      await mockGraph.registerDelegation({
        id: "del-child",
        parentId: "del-root",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
        credentialStatusId: "https://example.com/status#1", // Use numeric index
      });

      // Mock checkStatus to return true for root's credentialStatus (index 0)
      mockStatusList.checkStatus = vi
        .fn()
        .mockImplementation(async (status: CredentialStatus) => {
          // parseCredentialStatus parses "#0" -> statusListIndex "0"
          if (
            status.statusListIndex === "0" ||
            status.id === "https://example.com/status#0"
          ) {
            return true;
          }
          return false;
        });

      const result = await revocationManager.validateDelegation("del-child");

      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Ancestor");
    });

    it("should return invalid if chain validation fails", async () => {
      await mockGraph.registerDelegation({
        id: "del-001",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#123",
      });

      mockStatusList.checkStatus = vi.fn().mockResolvedValue(false);
      vi.spyOn(mockGraph, "validateChain").mockResolvedValue({
        valid: false,
        reason: "Invalid chain structure",
      });

      const result = await revocationManager.validateDelegation("del-001");

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Invalid chain structure");
    });
  });

  describe("getRevokedInSubtree", () => {
    it("should return empty array if no revocations", async () => {
      await mockGraph.registerDelegation({
        id: "del-root",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#root",
      });

      mockStatusList.checkStatus = vi.fn().mockResolvedValue(false);

      const revoked = await revocationManager.getRevokedInSubtree("del-root");

      expect(revoked).toEqual([]);
    });

    it("should return all revoked delegations in subtree", async () => {
      await mockGraph.registerDelegation({
        id: "del-root",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#0", // Use numeric index
      });

      await mockGraph.registerDelegation({
        id: "del-child1",
        parentId: "del-root",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
        credentialStatusId: "https://example.com/status#1", // Use numeric index
      });

      await mockGraph.registerDelegation({
        id: "del-child2",
        parentId: "del-root",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject3",
        credentialStatusId: "https://example.com/status#2", // Use numeric index
      });

      // child1 is revoked (index 1), root and child2 are not
      mockStatusList.checkStatus = vi
        .fn()
        .mockImplementation(async (status: CredentialStatus) => {
          // parseCredentialStatus parses "#1" -> statusListIndex "1"
          if (
            status.statusListIndex === "1" ||
            status.id === "https://example.com/status#1"
          ) {
            return true;
          }
          return false;
        });

      const revoked = await revocationManager.getRevokedInSubtree("del-root");

      expect(revoked).toContain("del-child1");
      expect(revoked).not.toContain("del-root");
      expect(revoked).not.toContain("del-child2");
    });
  });
});

describe("CascadingRevocationManager over the memory graph and status list", () => {
  const gzip = {
    compress: async (d: Uint8Array) => new Uint8Array(gzipSync(d)),
    decompress: async (d: Uint8Array) => new Uint8Array(gunzipSync(d)),
  };
  const UUID_STATUS_ID = "urn:uuid:4b1c0c56-7f0e-4c32-9b8e-0b1a2c3d4e5f";

  function stack() {
    const graphStorage = new MemoryDelegationGraphStorage();
    const graph = new DelegationGraphManager(graphStorage);
    const statusList = new StatusList2021Manager(
      new MemoryStatusListStorage(),
      { getDid: () => "did:web:issuer.example", getKeyId: () => "did:web:issuer.example#k" },
      async () => ({ type: "Ed25519Signature2020", proofValue: "x" }),
      gzip,
      gzip,
      { statusListBaseUrl: "https://status.example", defaultListSize: 1024 },
    );
    return { graph, graphStorage, statusList, revocation: new CascadingRevocationManager(graph, statusList) };
  }

  it("marks the subtree revoked in the graph even when no node has a status list entry", async () => {
    const { graph, graphStorage, revocation } = stack();
    await graph.registerDelegation({ id: "p", parentId: null, issuerDid: "did:user", subjectDid: "did:a" });
    await graph.registerDelegation({ id: "c", parentId: "p", issuerDid: "did:a", subjectDid: "did:b" });

    const events = await revocation.revokeDelegation("p");

    expect(events.map((e) => e.delegationId)).toEqual(["p", "c"]);
    expect((await graphStorage.getNode("p"))?.revoked).toBe(true);
    expect((await graphStorage.getNode("c"))?.revoked).toBe(true);
    expect(await revocation.isRevoked("p")).toEqual({ revoked: true, reason: "Directly revoked", revokedAncestor: undefined });
    expect((await revocation.isRevoked("c")).revoked).toBe(true);
    expect(await revocation.getRevokedInSubtree("p")).toEqual(["p", "c"]);
  });

  it("flips the status bit of a structured credentialStatus entry, and restore clears both", async () => {
    const { graph, statusList, revocation } = stack();
    const entry = await statusList.allocateStatusEntry("revocation");
    await graph.registerDelegation({ id: "p", parentId: null, issuerDid: "did:user", subjectDid: "did:a", credentialStatus: entry });

    await revocation.revokeDelegation("p");
    expect(await statusList.checkStatus(entry)).toBe(true);

    await revocation.restoreDelegation("p");
    expect(await statusList.checkStatus(entry)).toBe(false);
    expect((await revocation.isRevoked("p")).revoked).toBe(false);
  });

  it("registers, revokes and reads as revoked a delegation whose status id names no list entry", async () => {
    const { graph, statusList, revocation } = stack();
    const updateStatus = vi.spyOn(statusList, "updateStatus");
    await graph.registerDelegation({
      id: "p",
      parentId: null,
      issuerDid: "did:user",
      subjectDid: "did:a",
      credentialStatusId: UUID_STATUS_ID,
    });
    await graph.registerDelegation({ id: "c", parentId: "p", issuerDid: "did:a", subjectDid: "did:b" });

    const events = await revocation.revokeDelegation("p");

    expect(events.map((e) => e.delegationId)).toEqual(["p", "c"]);
    expect(updateStatus).not.toHaveBeenCalled(); // there is no bit to flip
    expect((await graph.getNode("p"))?.revoked).toBe(true);
    expect((await revocation.isRevoked("p")).revoked).toBe(true);
    expect(await revocation.validateDelegation("c")).toEqual({ valid: false, reason: "Ancestor p is revoked" });
  });

  it("keeps a revoked delegation revoked when its id is registered again", async () => {
    const { graph, statusList, revocation } = stack();
    const entry = await statusList.allocateStatusEntry("revocation");
    const root = { id: "p", parentId: null, issuerDid: "did:user", subjectDid: "did:a", credentialStatusId: entry.id };
    await graph.registerDelegation(root);
    await graph.registerDelegation({ id: "c", parentId: "p", issuerDid: "did:a", subjectDid: "did:b" });
    await revocation.revokeDelegation("p");

    // A retry of the same registration changes nothing; dropping the status
    // reference, which used to replace the node, is refused.
    await graph.registerDelegation(root);
    await expect(graph.registerDelegation({ ...root, credentialStatusId: undefined })).rejects.toThrow(
      "Delegation p is already registered with a different credentialStatusId",
    );

    expect((await revocation.isRevoked("p")).revoked).toBe(true);
    expect(await revocation.isRevoked("c")).toEqual({ revoked: true, reason: "Ancestor revoked", revokedAncestor: "p" });
  });
});
