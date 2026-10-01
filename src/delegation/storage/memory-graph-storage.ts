/**
 * In-Memory Delegation Graph Storage Provider
 *
 * Memory-based implementation for testing and development.
 * NOT suitable for production (no persistence).
 *
 * SOLID: Implements DelegationGraphStorageProvider interface
 */

import type {
  AtomicDelegationGraphStorageProvider,
  DelegationGraphStorageProvider,
  DelegationNode,
} from '../delegation-graph.js';
import { registrationConflict } from '../delegation-registration.js';

/**
 * Memory-based Delegation Graph storage
 *
 * Stores delegation nodes in memory with efficient graph queries.
 * Useful for:
 * - Unit tests
 * - Integration tests
 * - Development/debugging
 * - Examples
 */
export class MemoryDelegationGraphStorage
  implements DelegationGraphStorageProvider, AtomicDelegationGraphStorageProvider
{
  private nodes = new Map<string, DelegationNode>();

  /**
   * Get a delegation node by ID
   */
  async getNode(delegationId: string): Promise<DelegationNode | null> {
    return this.nodes.get(delegationId) || null;
  }

  /**
   * Save a delegation node
   */
  async setNode(node: DelegationNode): Promise<void> {
    this.nodes.set(node.id, node);
  }

  /**
   * Performs parent validation, child insert, and parent link in one
   * serialization point. An id that is already stored is left untouched: a
   * repeat of the same registration is a no-op, and a conflicting one throws
   * rather than replace the node's revocation state and children.
   */
  async registerNodeAtomic(node: DelegationNode): Promise<void> {
    if (node.parentId === node.id) {
      throw new Error(`Delegation ${node.id} cannot be its own parent`);
    }
    const existing = this.nodes.get(node.id);
    if (existing !== undefined) {
      const conflict = registrationConflict(existing, node);
      if (conflict === undefined) {
        return;
      }
      throw new Error(`Delegation ${node.id} is already registered with a different ${conflict}`);
    }
    const parent = node.parentId === null ? null : this.nodes.get(node.parentId);
    if (node.parentId !== null && parent === undefined) {
      throw new Error(`Parent delegation not found: ${node.parentId}`);
    }
    const storedNode = { ...node, children: [...node.children] };
    if (parent !== null && parent !== undefined) {
      const storedParent = {
        ...parent,
        children: parent.children.includes(node.id)
          ? [...parent.children]
          : [...parent.children, node.id],
      };
      this.nodes.set(storedParent.id, storedParent);
    }
    this.nodes.set(storedNode.id, storedNode);
  }

  /**
   * Get all children of a delegation
   */
  async getChildren(delegationId: string): Promise<DelegationNode[]> {
    const parent = this.nodes.get(delegationId);
    if (!parent) return [];

    return parent.children
      .map((childId) => this.nodes.get(childId))
      .filter((node): node is DelegationNode => node !== undefined);
  }

  /**
   * Get the full chain from root to this delegation
   */
  async getChain(delegationId: string): Promise<DelegationNode[]> {
    return this.getChainSync(delegationId);
  }

  /**
   * Get all descendants (children, grandchildren, etc.)
   *
   * Uses BFS for efficiency.
   */
  async getDescendants(delegationId: string): Promise<DelegationNode[]> {
    const descendants: DelegationNode[] = [];
    const queue: string[] = [delegationId];
    const visited = new Set<string>();

    while (queue.length > 0) {
      const currentId = queue.shift()!;

      // Skip if already visited (prevent infinite loops)
      if (visited.has(currentId)) continue;
      visited.add(currentId);

      const node = this.nodes.get(currentId);
      if (!node) continue;

      // Add children to queue
      for (const childId of node.children) {
        if (!visited.has(childId)) {
          queue.push(childId);

          const childNode = this.nodes.get(childId);
          if (childNode) {
            descendants.push(childNode);
          }
        }
      }
    }

    return descendants;
  }

  /**
   * Delete a node
   */
  async deleteNode(delegationId: string): Promise<void> {
    this.nodes.delete(delegationId);
  }

  /**
   * Clear all data (for testing)
   */
  clear(): void {
    this.nodes.clear();
  }

  /**
   * Get all node IDs (for testing)
   */
  getAllNodeIds(): string[] {
    return Array.from(this.nodes.keys());
  }

  /**
   * Get graph statistics (for testing/debugging)
   */
  getStats(): {
    totalNodes: number;
    rootNodes: number;
    leafNodes: number;
    maxDepth: number;
  } {
    const nodes = Array.from(this.nodes.values());

    const rootNodes = nodes.filter((n) => n.parentId === null).length;
    const leafNodes = nodes.filter((n) => n.children.length === 0).length;

    // Calculate max depth
    let maxDepth = 0;
    for (const node of nodes) {
      const chain = this.getChainSync(node.id);
      maxDepth = Math.max(maxDepth, chain.length - 1);
    }

    return {
      totalNodes: nodes.length,
      rootNodes,
      leafNodes,
      maxDepth,
    };
  }

  /**
   * Walk parent links from `delegationId` up to the root, returning the chain
   * root first. Throws on a parent cycle instead of looping forever: a cycle
   * has no root, so no chain through it is valid.
   */
  private getChainSync(delegationId: string): DelegationNode[] {
    const chain: DelegationNode[] = [];
    const visited = new Set<string>();
    let currentId: string | null = delegationId;

    while (currentId) {
      if (visited.has(currentId)) {
        throw new Error(`Delegation graph has a parent cycle at ${currentId}`);
      }
      visited.add(currentId);

      const node = this.nodes.get(currentId);
      if (!node) break;

      chain.unshift(node); // Add to front (root first)
      currentId = node.parentId;
    }

    return chain;
  }
}
