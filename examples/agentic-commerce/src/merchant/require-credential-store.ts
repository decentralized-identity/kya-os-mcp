import type { GrantStore } from '@kya-os/mcp';

/** This demo re-presents the VC and checks its status on every protected call.
 * The SDK's optional no-paste grant cache cannot carry that status evidence.
 * Disable that cache through its provider seam, preserving the delegation gate. */
export const requireCredentialStore: GrantStore = {
  async bind() {},
  async getByAgent() { return []; },
  async getBySession() { return []; },
  async getById() { return undefined; },
  async revoke() {},
  async cleanup() {},
};
