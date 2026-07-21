import { describe, it, expect, beforeEach } from "vitest";
import { MemoryDelegationGraphStorage } from "../memory-graph-storage.js";
import type { DelegationNode } from "../../delegation-graph.js";

describe("MemoryDelegationGraphStorage", () => {
  let storage: MemoryDelegationGraphStorage;

  const createMockNode = (
    id: string,
    parentId: string | null = null
  ): DelegationNode => ({
    id,
    parentId,
    issuerDid: `did:web:example.com:issuer${id}`,
    subjectDid: `did:web:example.com:subject${id}`,
    children: [],
    credentialStatusId: `https://example.com/status#${id}`,
  });

  beforeEach(() => {
    storage = new MemoryDelegationGraphStorage();
  });

  describe("getNode", () => {
    it("should return null for non-existent node", async () => {
      const result = await storage.getNode("non-existent");
      expect(result).toBeNull();
    });

    it("should return stored node", async () => {
      const node = createMockNode("del-001");
      await storage.setNode(node);

      const result = await storage.getNode("del-001");
      expect(result).toEqual(node);
    });
  });

  describe("setNode", () => {
    it("should store node", async () => {
      const node = createMockNode("del-001");
      await storage.setNode(node);

      const result = await storage.getNode("del-001");
      expect(result).toEqual(node);
    });

    it("should overwrite existing node", async () => {
      const node1 = createMockNode("del-001");
      await storage.setNode(node1);

      const node2 = {
        ...node1,
        issuerDid: "did:web:example.com:updated",
      };
      await storage.setNode(node2);

      const result = await storage.getNode("del-001");
      expect(result?.issuerDid).toBe("did:web:example.com:updated");
    });
  });

  describe("registerNodeAtomic", () => {
    it("should reject an orphan without retaining it", async () => {
      const orphan = createMockNode("del-orphan", "del-missing-parent");

      await expect(storage.registerNodeAtomic(orphan)).rejects.toThrow(
        "Parent delegation not found: del-missing-parent"
      );
      expect(await storage.getNode(orphan.id)).toBeNull();
    });

    it("should preserve a parent link when the child is registered again", async () => {
      const parent = createMockNode("del-parent");
      parent.children = ["del-child"];
      await storage.setNode(parent);

      await storage.registerNodeAtomic(createMockNode("del-child", parent.id));

      expect((await storage.getNode(parent.id))?.children).toEqual(["del-child"]);
      expect(await storage.getNode("del-child")).not.toBeNull();
    });
  });

  describe("getChildren", () => {
    it("should return empty array for node with no children", async () => {
      const node = createMockNode("del-001");
      await storage.setNode(node);

      const children = await storage.getChildren("del-001");
      expect(children).toEqual([]);
    });

    it("should return direct children only", async () => {
      const parent = createMockNode("del-parent");
      const child1 = createMockNode("del-child1", "del-parent");
      const child2 = createMockNode("del-child2", "del-parent");
      const grandchild = createMockNode("del-grandchild", "del-child1");

      parent.children = ["del-child1", "del-child2"];
      child1.children = ["del-grandchild"];

      await storage.setNode(parent);
      await storage.setNode(child1);
      await storage.setNode(child2);
      await storage.setNode(grandchild);

      const children = await storage.getChildren("del-parent");
      expect(children.length).toBe(2);
      expect(children.map((c) => c.id)).toContain("del-child1");
      expect(children.map((c) => c.id)).toContain("del-child2");
      expect(children.map((c) => c.id)).not.toContain("del-grandchild");
    });

    it("should return empty array for non-existent node", async () => {
      const children = await storage.getChildren("non-existent");
      expect(children).toEqual([]);
    });

    it("should filter out missing child nodes", async () => {
      const parent = createMockNode("del-parent");
      parent.children = ["del-child1", "del-missing", "del-child2"];

      const child1 = createMockNode("del-child1", "del-parent");
      const child2 = createMockNode("del-child2", "del-parent");

      await storage.setNode(parent);
      await storage.setNode(child1);
      await storage.setNode(child2);
      // del-missing is not stored

      const children = await storage.getChildren("del-parent");
      expect(children.length).toBe(2);
      expect(children.map((c) => c.id)).toContain("del-child1");
      expect(children.map((c) => c.id)).toContain("del-child2");
    });
  });

  describe("getChain", () => {
    it("should return single node for root", async () => {
      const root = createMockNode("del-root");
      await storage.setNode(root);

      const chain = await storage.getChain("del-root");
      expect(chain.length).toBe(1);
      expect(chain[0].id).toBe("del-root");
    });

    it("should return chain from root to node", async () => {
      const root = createMockNode("del-root");
      const child = createMockNode("del-child", "del-root");
      const grandchild = createMockNode("del-grandchild", "del-child");

      root.children = ["del-child"];
      child.children = ["del-grandchild"];

      await storage.setNode(root);
      await storage.setNode(child);
      await storage.setNode(grandchild);

      const chain = await storage.getChain("del-grandchild");
      expect(chain.length).toBe(3);
      expect(chain[0].id).toBe("del-root");
      expect(chain[1].id).toBe("del-child");
      expect(chain[2].id).toBe("del-grandchild");
    });

    it("should stop at missing parent", async () => {
      const child = createMockNode("del-child", "del-missing-parent");
      await storage.setNode(child);

      const chain = await storage.getChain("del-child");
      expect(chain.length).toBe(1);
      expect(chain[0].id).toBe("del-child");
    });

    it("should return empty array for non-existent node", async () => {
      const chain = await storage.getChain("non-existent");
      expect(chain).toEqual([]);
    });
  });

  describe("getDescendants", () => {
    it("should return empty array for leaf node", async () => {
      const leaf = createMockNode("del-leaf");
      await storage.setNode(leaf);

      const descendants = await storage.getDescendants("del-leaf");
      expect(descendants).toEqual([]);
    });

    it("should return all descendants", async () => {
      const root = createMockNode("del-root");
      const child1 = createMockNode("del-child1", "del-root");
      const child2 = createMockNode("del-child2", "del-root");
      const grandchild = createMockNode("del-grandchild", "del-child1");

      root.children = ["del-child1", "del-child2"];
      child1.children = ["del-grandchild"];

      await storage.setNode(root);
      await storage.setNode(child1);
      await storage.setNode(child2);
      await storage.setNode(grandchild);

      const descendants = await storage.getDescendants("del-root");
      expect(descendants.length).toBe(3);
      expect(descendants.map((d) => d.id)).toContain("del-child1");
      expect(descendants.map((d) => d.id)).toContain("del-child2");
      expect(descendants.map((d) => d.id)).toContain("del-grandchild");
    });

    it("should handle deep trees", async () => {
      const nodes: DelegationNode[] = [];
      for (let i = 0; i < 5; i++) {
        const parentId = i === 0 ? null : `del-${i - 1}`;
        const node = createMockNode(`del-${i}`, parentId);
        if (i > 0) {
          nodes[i - 1].children.push(`del-${i}`);
        }
        nodes.push(node);
        await storage.setNode(node);
      }

      const descendants = await storage.getDescendants("del-0");
      expect(descendants.length).toBe(4);
    });

    it("should prevent infinite loops", async () => {
      // Create a cycle (shouldn't happen in real usage, but test defensive code)
      const node1 = createMockNode("del-1");
      const node2 = createMockNode("del-2", "del-1");
      node1.children = ["del-2"];
      node2.children = ["del-1"]; // Cycle!

      await storage.setNode(node1);
      await storage.setNode(node2);

      const descendants = await storage.getDescendants("del-1");
      // Should return node2 only once, not loop infinitely
      expect(descendants.length).toBe(1);
      expect(descendants[0].id).toBe("del-2");
    });

    it("should return empty array for non-existent node", async () => {
      const descendants = await storage.getDescendants("non-existent");
      expect(descendants).toEqual([]);
    });
  });

  describe("deleteNode", () => {
    it("should delete node", async () => {
      const node = createMockNode("del-001");
      await storage.setNode(node);

      await storage.deleteNode("del-001");

      const result = await storage.getNode("del-001");
      expect(result).toBeNull();
    });

    it("should not throw when deleting non-existent node", async () => {
      await expect(storage.deleteNode("non-existent")).resolves.not.toThrow();
    });
  });

  describe("clear", () => {
    it("should remove all nodes", async () => {
      await storage.setNode(createMockNode("del-001"));
      await storage.setNode(createMockNode("del-002"));

      storage.clear();

      expect(await storage.getNode("del-001")).toBeNull();
      expect(await storage.getNode("del-002")).toBeNull();
    });
  });

  describe("getAllNodeIds", () => {
    it("should return empty array when no nodes", () => {
      const ids = storage.getAllNodeIds();
      expect(ids).toEqual([]);
    });

    it("should return all node IDs", async () => {
      await storage.setNode(createMockNode("del-001"));
      await storage.setNode(createMockNode("del-002"));
      await storage.setNode(createMockNode("del-003"));

      const ids = storage.getAllNodeIds();
      expect(ids).toContain("del-001");
      expect(ids).toContain("del-002");
      expect(ids).toContain("del-003");
      expect(ids.length).toBe(3);
    });
  });

  describe("getStats", () => {
    it("should return correct stats for empty storage", () => {
      const stats = storage.getStats();
      expect(stats.totalNodes).toBe(0);
      expect(stats.rootNodes).toBe(0);
      expect(stats.leafNodes).toBe(0);
      expect(stats.maxDepth).toBe(0);
    });

    it("should count root nodes correctly", async () => {
      await storage.setNode(createMockNode("del-root1"));
      await storage.setNode(createMockNode("del-root2"));

      const stats = storage.getStats();
      expect(stats.rootNodes).toBe(2);
    });

    it("should count leaf nodes correctly", async () => {
      const root = createMockNode("del-root");
      const child1 = createMockNode("del-child1", "del-root");
      const child2 = createMockNode("del-child2", "del-root");

      root.children = ["del-child1", "del-child2"];

      await storage.setNode(root);
      await storage.setNode(child1);
      await storage.setNode(child2);

      const stats = storage.getStats();
      expect(stats.leafNodes).toBe(2); // child1 and child2
    });

    it("should calculate max depth correctly", async () => {
      const root = createMockNode("del-root");
      const child = createMockNode("del-child", "del-root");
      const grandchild = createMockNode("del-grandchild", "del-child");

      root.children = ["del-child"];
      child.children = ["del-grandchild"];

      await storage.setNode(root);
      await storage.setNode(child);
      await storage.setNode(grandchild);

      const stats = storage.getStats();
      expect(stats.maxDepth).toBe(2); // root -> child -> grandchild (depth 2)
    });

    it("should handle multiple trees", async () => {
      // Tree 1: depth 1
      const root1 = createMockNode("del-root1");
      const child1 = createMockNode("del-child1", "del-root1");
      root1.children = ["del-child1"];

      // Tree 2: depth 2
      const root2 = createMockNode("del-root2");
      const child2 = createMockNode("del-child2", "del-root2");
      const grandchild2 = createMockNode("del-grandchild2", "del-child2");
      root2.children = ["del-child2"];
      child2.children = ["del-grandchild2"];

      await storage.setNode(root1);
      await storage.setNode(child1);
      await storage.setNode(root2);
      await storage.setNode(child2);
      await storage.setNode(grandchild2);

      const stats = storage.getStats();
      expect(stats.totalNodes).toBe(5);
      expect(stats.rootNodes).toBe(2);
      expect(stats.maxDepth).toBe(2); // Max depth across all trees
    });
  });
});
















