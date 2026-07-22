/**
 * Delegation Graph Manager
 *
 * Tracks parent-child relationships between delegation credentials.
 * Critical for cascading revocation per Delegation-Revocation.md.
 *
 * Related Spec: KYA-OS §4.4, Delegation Chains
 */

export interface DelegationNode {
  id: string;
  parentId: string | null;
  children: string[];
  issuerDid: string;
  subjectDid: string;
  credentialStatusId?: string;
}

export interface DelegationGraphStorageProvider {
  getNode(delegationId: string): Promise<DelegationNode | null>;
  setNode(node: DelegationNode): Promise<void>;
  getChildren(delegationId: string): Promise<DelegationNode[]>;
  getChain(delegationId: string): Promise<DelegationNode[]>;
  getDescendants(delegationId: string): Promise<DelegationNode[]>;
  deleteNode(delegationId: string): Promise<void>;
}

/** Optional transaction seam for providers that can link parent and child atomically. */
export interface AtomicDelegationGraphStorageProvider extends DelegationGraphStorageProvider {
  registerNodeAtomic(node: DelegationNode): Promise<void>;
}

function supportsAtomicRegistration(
  storage: DelegationGraphStorageProvider,
): storage is AtomicDelegationGraphStorageProvider {
  return 'registerNodeAtomic' in storage &&
    typeof storage.registerNodeAtomic === 'function';
}

export class DelegationGraphManager {
  constructor(private storage: DelegationGraphStorageProvider) {}

  async registerDelegation(params: {
    id: string;
    parentId: string | null;
    issuerDid: string;
    subjectDid: string;
    credentialStatusId?: string;
  }): Promise<DelegationNode> {
    const node: DelegationNode = {
      id: params.id,
      parentId: params.parentId,
      children: [],
      issuerDid: params.issuerDid,
      subjectDid: params.subjectDid,
      credentialStatusId: params.credentialStatusId,
    };

    if (params.parentId) {
      const parent = await this.storage.getNode(params.parentId);
      if (!parent) {
        throw new Error(`Parent delegation not found: ${params.parentId}`);
      }
    }

    if (supportsAtomicRegistration(this.storage)) {
      await this.storage.registerNodeAtomic(node);
    } else {
      await this.storage.setNode(node);
      if (params.parentId) {
        try {
          await this.addChildToParent(params.parentId, params.id);
        } catch (error) {
          try {
            await this.storage.deleteNode(params.id);
          } catch (rollbackError) {
            throw new AggregateError(
              [error, rollbackError],
              'Delegation registration failed and its non-atomic rollback also failed',
              { cause: error },
            );
          }
          throw error;
        }
      }
    }

    return node;
  }

  private async addChildToParent(parentId: string, childId: string): Promise<void> {
    const parent = await this.storage.getNode(parentId);
    if (!parent) {
      throw new Error(`Parent delegation not found: ${parentId}`);
    }

    if (!parent.children.includes(childId)) {
      parent.children.push(childId);
      await this.storage.setNode(parent);
    }
  }

  async getNode(delegationId: string): Promise<DelegationNode | null> {
    return this.storage.getNode(delegationId);
  }

  async getChildren(delegationId: string): Promise<DelegationNode[]> {
    return this.storage.getChildren(delegationId);
  }

  async getDescendants(delegationId: string): Promise<DelegationNode[]> {
    return this.storage.getDescendants(delegationId);
  }

  async getChain(delegationId: string): Promise<DelegationNode[]> {
    return this.storage.getChain(delegationId);
  }

  async isAncestor(ancestorId: string, descendantId: string): Promise<boolean> {
    const chain = await this.getChain(descendantId);
    return chain.some((node) => node.id === ancestorId);
  }

  async getDepth(delegationId: string): Promise<number> {
    const chain = await this.getChain(delegationId);
    return chain.length - 1;
  }

  async validateChain(delegationId: string): Promise<{ valid: boolean; reason?: string }> {
    const chain = await this.getChain(delegationId);

    if (chain.length === 0) {
      return { valid: false, reason: 'Delegation not found' };
    }

    for (let i = 1; i < chain.length; i++) {
      const parent = chain[i - 1]!;
      const child = chain[i]!;

      if (child.issuerDid !== parent.subjectDid) {
        return {
          valid: false,
          reason: `Invalid chain: ${child.id} issued by ${child.issuerDid} but parent ${parent.id} subject is ${parent.subjectDid}`,
        };
      }

      if (child.parentId !== parent.id) {
        return {
          valid: false,
          reason: `Invalid chain: ${child.id} parentId=${child.parentId} but actual parent is ${parent.id}`,
        };
      }
    }

    return { valid: true };
  }

  async removeDelegation(delegationId: string): Promise<void> {
    const node = await this.storage.getNode(delegationId);
    if (!node) return;

    if (node.parentId) {
      const parent = await this.storage.getNode(node.parentId);
      if (parent) {
        parent.children = parent.children.filter((id) => id !== delegationId);
        await this.storage.setNode(parent);
      }
    }

    await this.storage.deleteNode(delegationId);
  }
}

export function createDelegationGraph(
  storage: DelegationGraphStorageProvider
): DelegationGraphManager {
  return new DelegationGraphManager(storage);
}
