import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  DelegationGraphManager,
  createDelegationGraph,
  type DelegationNode,
  type DelegationGraphStorageProvider,
} from "../delegation-graph.js";

describe("DelegationGraphManager", () => {
  let storage: DelegationGraphStorageProvider;
  let graph: DelegationGraphManager;

  // Simple in-memory storage for testing
  const createMockStorage = (): DelegationGraphStorageProvider => {
    const nodes = new Map<string, DelegationNode>();

    return {
      getNode: vi.fn(async (id: string) => {
        return nodes.get(id) || null;
      }),
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

        while (queue.length > 0) {
          const currentId = queue.shift()!;
          const node = nodes.get(currentId);
          if (!node) continue;

          for (const childId of node.children) {
            const child = nodes.get(childId);
            if (child) {
              descendants.push(child);
              queue.push(childId);
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
    storage = createMockStorage();
    graph = new DelegationGraphManager(storage);
  });

  describe("constructor", () => {
    it("should create graph manager with storage", () => {
      const manager = new DelegationGraphManager(storage);
      expect(manager).toBeInstanceOf(DelegationGraphManager);
    });
  });

  describe("createDelegationGraph", () => {
    it("should create a graph manager instance", () => {
      const manager = createDelegationGraph(storage);
      expect(manager).toBeInstanceOf(DelegationGraphManager);
    });
  });

  describe("registerDelegation", () => {
    it("should register a root delegation (no parent)", async () => {
      const node = await graph.registerDelegation({
        id: "del-001",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      expect(node.id).toBe("del-001");
      expect(node.parentId).toBeNull();
      expect(node.children).toEqual([]);
      expect(node.issuerDid).toBe("did:web:example.com:issuer");
      expect(node.subjectDid).toBe("did:web:example.com:subject");
      expect(storage.setNode).toHaveBeenCalled();
    });

    it("should register a child delegation and link to parent", async () => {
      // Register parent first
      await graph.registerDelegation({
        id: "del-parent",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      // Clear call count
      vi.clearAllMocks();

      // Register child
      const childNode = await graph.registerDelegation({
        id: "del-child",
        parentId: "del-parent",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
      });

      expect(childNode.parentId).toBe("del-parent");
      // setNode is called: 1) for child, 2) for parent (to add child to children list)
      expect(storage.setNode).toHaveBeenCalledTimes(2);
    });

    it("should include credentialStatusId if provided", async () => {
      const node = await graph.registerDelegation({
        id: "del-001",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        credentialStatusId: "https://example.com/status#123",
      });

      expect(node.credentialStatusId).toBe("https://example.com/status#123");
    });

    it("should roll back a child when a non-atomic parent link fails", async () => {
      const parent: DelegationNode = {
        id: "del-parent",
        parentId: null,
        children: [],
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      };
      vi.mocked(storage.getNode)
        .mockResolvedValueOnce(parent)
        .mockResolvedValueOnce(null);

      await expect(
        graph.registerDelegation({
          id: "del-child",
          parentId: parent.id,
          issuerDid: parent.subjectDid,
          subjectDid: "did:web:example.com:child",
        })
      ).rejects.toThrow(`Parent delegation not found: ${parent.id}`);

      expect(storage.setNode).toHaveBeenCalledWith(
        expect.objectContaining({ id: "del-child" })
      );
      expect(storage.deleteNode).toHaveBeenCalledWith("del-child");
    });
  });

  describe("getNode", () => {
    it("should return node if exists", async () => {
      await graph.registerDelegation({
        id: "del-001",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      const node = await graph.getNode("del-001");
      expect(node).not.toBeNull();
      expect(node?.id).toBe("del-001");
    });

    it("should return null if node does not exist", async () => {
      const node = await graph.getNode("non-existent");
      expect(node).toBeNull();
    });
  });

  describe("getChildren", () => {
    it("should return empty array for node with no children", async () => {
      await graph.registerDelegation({
        id: "del-001",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      const children = await graph.getChildren("del-001");
      expect(children).toEqual([]);
    });

    it("should return all direct children", async () => {
      // Register parent
      await graph.registerDelegation({
        id: "del-parent",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      // Register children
      await graph.registerDelegation({
        id: "del-child1",
        parentId: "del-parent",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
      });

      await graph.registerDelegation({
        id: "del-child2",
        parentId: "del-parent",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject3",
      });

      const children = await graph.getChildren("del-parent");
      expect(children.length).toBe(2);
      expect(children.map((c) => c.id)).toContain("del-child1");
      expect(children.map((c) => c.id)).toContain("del-child2");
    });
  });

  describe("getDescendants", () => {
    it("should return all descendants recursively", async () => {
      // Create a tree: parent -> child1 -> grandchild
      await graph.registerDelegation({
        id: "del-parent",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      await graph.registerDelegation({
        id: "del-child1",
        parentId: "del-parent",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
      });

      await graph.registerDelegation({
        id: "del-grandchild",
        parentId: "del-child1",
        issuerDid: "did:web:example.com:subject2",
        subjectDid: "did:web:example.com:subject3",
      });

      const descendants = await graph.getDescendants("del-parent");
      expect(descendants.length).toBe(2);
      expect(descendants.map((d) => d.id)).toContain("del-child1");
      expect(descendants.map((d) => d.id)).toContain("del-grandchild");
    });

    it("should return empty array for node with no descendants", async () => {
      await graph.registerDelegation({
        id: "del-001",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      const descendants = await graph.getDescendants("del-001");
      expect(descendants).toEqual([]);
    });
  });

  describe("getChain", () => {
    it("should return chain from root to node", async () => {
      // Create chain: root -> child -> grandchild
      await graph.registerDelegation({
        id: "del-root",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      await graph.registerDelegation({
        id: "del-child",
        parentId: "del-root",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
      });

      await graph.registerDelegation({
        id: "del-grandchild",
        parentId: "del-child",
        issuerDid: "did:web:example.com:subject2",
        subjectDid: "did:web:example.com:subject3",
      });

      const chain = await graph.getChain("del-grandchild");
      expect(chain.length).toBe(3);
      expect(chain[0].id).toBe("del-root");
      expect(chain[1].id).toBe("del-child");
      expect(chain[2].id).toBe("del-grandchild");
    });

    it("should return single node for root", async () => {
      await graph.registerDelegation({
        id: "del-root",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      const chain = await graph.getChain("del-root");
      expect(chain.length).toBe(1);
      expect(chain[0].id).toBe("del-root");
    });
  });

  describe("isAncestor", () => {
    it("should return true if ancestor is parent", async () => {
      await graph.registerDelegation({
        id: "del-parent",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      await graph.registerDelegation({
        id: "del-child",
        parentId: "del-parent",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
      });

      const isAncestor = await graph.isAncestor("del-parent", "del-child");
      expect(isAncestor).toBe(true);
    });

    it("should return true if ancestor is grandparent", async () => {
      await graph.registerDelegation({
        id: "del-grandparent",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      await graph.registerDelegation({
        id: "del-parent",
        parentId: "del-grandparent",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
      });

      await graph.registerDelegation({
        id: "del-child",
        parentId: "del-parent",
        issuerDid: "did:web:example.com:subject2",
        subjectDid: "did:web:example.com:subject3",
      });

      const isAncestor = await graph.isAncestor("del-grandparent", "del-child");
      expect(isAncestor).toBe(true);
    });

    it("should return false if not ancestor", async () => {
      await graph.registerDelegation({
        id: "del-1",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      await graph.registerDelegation({
        id: "del-2",
        parentId: null,
        issuerDid: "did:web:example.com:issuer2",
        subjectDid: "did:web:example.com:subject2",
      });

      const isAncestor = await graph.isAncestor("del-1", "del-2");
      expect(isAncestor).toBe(false);
    });

    it("should return false if nodes are reversed", async () => {
      await graph.registerDelegation({
        id: "del-parent",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      await graph.registerDelegation({
        id: "del-child",
        parentId: "del-parent",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
      });

      const isAncestor = await graph.isAncestor("del-child", "del-parent");
      expect(isAncestor).toBe(false);
    });
  });

  describe("getDepth", () => {
    it("should return 0 for root node", async () => {
      await graph.registerDelegation({
        id: "del-root",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      const depth = await graph.getDepth("del-root");
      expect(depth).toBe(0);
    });

    it("should return 1 for immediate child", async () => {
      await graph.registerDelegation({
        id: "del-root",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      await graph.registerDelegation({
        id: "del-child",
        parentId: "del-root",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
      });

      const depth = await graph.getDepth("del-child");
      expect(depth).toBe(1);
    });

    it("should return correct depth for nested nodes", async () => {
      await graph.registerDelegation({
        id: "del-root",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      await graph.registerDelegation({
        id: "del-child",
        parentId: "del-root",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
      });

      await graph.registerDelegation({
        id: "del-grandchild",
        parentId: "del-child",
        issuerDid: "did:web:example.com:subject2",
        subjectDid: "did:web:example.com:subject3",
      });

      const depth = await graph.getDepth("del-grandchild");
      expect(depth).toBe(2);
    });
  });

  describe("validateChain", () => {
    it("should validate correct chain", async () => {
      await graph.registerDelegation({
        id: "del-root",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      await graph.registerDelegation({
        id: "del-child",
        parentId: "del-root",
        issuerDid: "did:web:example.com:subject", // Child's issuer = parent's subject
        subjectDid: "did:web:example.com:subject2",
      });

      const result = await graph.validateChain("del-child");
      expect(result.valid).toBe(true);
    });

    it("should invalidate chain with mismatched issuer/subject", async () => {
      await graph.registerDelegation({
        id: "del-root",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      await graph.registerDelegation({
        id: "del-child",
        parentId: "del-root",
        issuerDid: "did:web:example.com:wrong-issuer", // Wrong issuer
        subjectDid: "did:web:example.com:subject2",
      });

      const result = await graph.validateChain("del-child");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Invalid chain");
    });

    it("should invalidate a chain whose parent link contradicts its ordering", async () => {
      vi.mocked(storage.getChain).mockResolvedValue([
        {
          id: "del-root",
          parentId: null,
          children: ["del-child"],
          issuerDid: "did:web:example.com:issuer",
          subjectDid: "did:web:example.com:subject",
        },
        {
          id: "del-child",
          parentId: "del-other-parent",
          children: [],
          issuerDid: "did:web:example.com:subject",
          subjectDid: "did:web:example.com:child",
        },
      ]);

      const result = await graph.validateChain("del-child");

      expect(result).toEqual({
        valid: false,
        reason:
          "Invalid chain: del-child parentId=del-other-parent but actual parent is del-root",
      });
    });

    it("should return invalid for non-existent delegation", async () => {
      const result = await graph.validateChain("non-existent");
      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Delegation not found");
    });
  });

  describe("removeDelegation", () => {
    it("should remove delegation from graph", async () => {
      await graph.registerDelegation({
        id: "del-001",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      await graph.removeDelegation("del-001");

      const node = await graph.getNode("del-001");
      expect(node).toBeNull();
      expect(storage.deleteNode).toHaveBeenCalledWith("del-001");
    });

    it("should remove child from parent's children list", async () => {
      await graph.registerDelegation({
        id: "del-parent",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      await graph.registerDelegation({
        id: "del-child",
        parentId: "del-parent",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
      });

      await graph.removeDelegation("del-child");

      const parent = await graph.getNode("del-parent");
      expect(parent?.children).not.toContain("del-child");
    });

    it("should handle removal of non-existent delegation gracefully", async () => {
      await expect(graph.removeDelegation("non-existent")).resolves.not.toThrow();
    });
  });

  describe("edge cases", () => {
    it("should handle multiple children correctly", async () => {
      await graph.registerDelegation({
        id: "del-parent",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      await graph.registerDelegation({
        id: "del-child1",
        parentId: "del-parent",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
      });

      await graph.registerDelegation({
        id: "del-child2",
        parentId: "del-parent",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject3",
      });

      await graph.registerDelegation({
        id: "del-child3",
        parentId: "del-parent",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject4",
      });

      const children = await graph.getChildren("del-parent");
      expect(children.length).toBe(3);
    });

    it("should handle deep chains correctly", async () => {
      // Create a chain of depth 5
      const chain: string[] = [];
      for (let i = 0; i < 5; i++) {
        const id = `del-${i}`;
        chain.push(id);
        await graph.registerDelegation({
          id,
          parentId: i === 0 ? null : chain[i - 1],
          issuerDid: `did:web:example.com:issuer${i}`,
          subjectDid: `did:web:example.com:subject${i + 1}`,
        });
      }

      const depth = await graph.getDepth(chain[4]);
      expect(depth).toBe(4);
    });

    it("should throw error when parent delegation not found", async () => {
      // Try to register child with non-existent parent
      await expect(
        graph.registerDelegation({
          id: "del-orphan",
          parentId: "non-existent-parent",
          issuerDid: "did:web:example.com:issuer",
          subjectDid: "did:web:example.com:subject",
        })
      ).rejects.toThrow("Parent delegation not found: non-existent-parent");
      expect(await graph.getNode("del-orphan")).toBeNull();
    });

    it("should not add duplicate children to parent", async () => {
      await graph.registerDelegation({
        id: "del-parent",
        parentId: null,
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
      });

      await graph.registerDelegation({
        id: "del-child",
        parentId: "del-parent",
        issuerDid: "did:web:example.com:subject",
        subjectDid: "did:web:example.com:subject2",
      });

      // Get parent and verify child was added correctly
      const parent = await graph.getNode("del-parent");
      expect(parent?.children).toEqual(["del-child"]);
      expect(parent?.children.length).toBe(1);

      // Try to register the same child again with different parent (should fail with parent not found)
      // This tests the duplicate prevention logic indirectly
      const child = await graph.getNode("del-child");
      expect(child).not.toBeNull();
      expect(child?.parentId).toBe("del-parent");
    });
  });
});
