/**
 * E2E Tests: StatusList2021 Revocation
 *
 * Validates the complete revocation lifecycle:
 *   1. Issue delegation with credentialStatus
 *   2. Verify it passes (not revoked)
 *   3. Revoke it via StatusList2021
 *   4. Verify it now fails (revoked)
 *   5. Verify missing status list fails closed (not open)
 *
 * Spec coverage: W3C StatusList2021, KYA-OS §4.2 (revocation)
 */

import { describe, it, expect, beforeAll } from "vitest";
import {
  NodeCryptoProvider,
  generateDidKeyFromBase64,
  DelegationCredentialIssuer,
  StatusList2021Manager,
  MemoryStatusListStorage,
  DelegationCredentialVerifier,
  createDidKeyResolver,
  base64urlEncodeFromBytes,
  type StatusListStorageProvider,
  type DelegationCredential,
  type CredentialStatus,
  type Proof,
} from "@kya-os/mcp";

const crypto = new NodeCryptoProvider();

// Simple passthrough compressor/decompressor for testing
const compressor = {
  compress: async (data: Uint8Array) => data,
};
const decompressor = {
  decompress: async (data: Uint8Array) => data,
};

describe("E2E: StatusList2021 revocation lifecycle", () => {
  let issuerDid: string;
  let issuerKid: string;
  let issuerPrivateKey: string;
  let issuer: DelegationCredentialIssuer;
  let statusListManager: StatusList2021Manager;
  let statusListStorage: MemoryStatusListStorage;
  let verifier: DelegationCredentialVerifier;

  beforeAll(async () => {
    // Generate issuer identity
    const keyPair = await crypto.generateKeyPair();
    issuerDid = generateDidKeyFromBase64(keyPair.publicKey);
    issuerKid = `${issuerDid}#${issuerDid.replace("did:key:", "")}`;
    issuerPrivateKey = keyPair.privateKey;

    // Signing function for VCs
    const signingFn = async (
      canonicalVC: string,
      _did: string,
      kid: string,
    ): Promise<Proof> => {
      const data = new TextEncoder().encode(canonicalVC);
      const sigBytes = await crypto.sign(data, issuerPrivateKey);
      return {
        type: "Ed25519Signature2020",
        created: new Date().toISOString(),
        verificationMethod: kid,
        proofPurpose: "assertionMethod",
        proofValue: base64urlEncodeFromBytes(sigBytes),
      };
    };

    // StatusList2021 manager with in-memory storage
    statusListStorage = new MemoryStatusListStorage();
    statusListManager = new StatusList2021Manager(
      statusListStorage,
      { getDid: () => issuerDid, getKeyId: () => issuerKid },
      signingFn,
      compressor,
      decompressor,
      { statusListBaseUrl: "https://status.test.example.com" },
    );

    // Delegation issuer
    issuer = new DelegationCredentialIssuer(
      {
        getDid: () => issuerDid,
        getKeyId: () => issuerKid,
        getPrivateKey: () => issuerPrivateKey,
      },
      signingFn,
    );

    // VC verifier with did:key resolver and statusListManager as resolver
    const didResolver = createDidKeyResolver();
    const signatureVerifier = async (
      vc: DelegationCredential,
      publicKeyJwk: unknown,
    ) => {
      // Simplified — trust signatures for this test since we're testing revocation
      return { valid: true };
    };

    verifier = new DelegationCredentialVerifier({
      didResolver,
      signatureVerifier,
      statusListResolver: statusListManager,
    });
  });

  async function issueDelegationWithStatus(
    scopes: string[],
  ): Promise<{ vc: DelegationCredential; credentialStatus: CredentialStatus }> {
    const credentialStatus =
      await statusListManager.allocateStatusEntry("revocation");

    const vc = await issuer.createAndIssueDelegation(
      {
        id: `delegation-sl-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        issuerDid,
        subjectDid: issuerDid,
        constraints: { scopes },
      },
      { credentialStatus },
    );

    return { vc, credentialStatus };
  }

  it("should verify a non-revoked credential with credentialStatus", async () => {
    const { vc } = await issueDelegationWithStatus(["read:data"]);

    const result = await verifier.verifyDelegationCredential(vc);

    expect(result.valid).toBe(true);
    expect(result.checks?.statusValid).toBe(true);
  });

  it("should reject a revoked credential", async () => {
    const { vc, credentialStatus } =
      await issueDelegationWithStatus(["write:data"]);

    // Verify it's valid first
    const beforeRevoke = await verifier.verifyDelegationCredential(vc);
    expect(beforeRevoke.valid).toBe(true);

    // Revoke it
    await statusListManager.updateStatus(credentialStatus, true);

    // Now it should fail
    const afterRevoke = await verifier.verifyDelegationCredential(vc, {
      skipCache: true,
    });
    expect(afterRevoke.valid).toBe(false);
    expect(afterRevoke.reason).toContain("revoked");
    expect(afterRevoke.checks?.statusValid).toBe(false);
  });

  it("should restore a revoked credential", async () => {
    const { vc, credentialStatus } =
      await issueDelegationWithStatus(["admin:panel"]);

    // Revoke
    await statusListManager.updateStatus(credentialStatus, true);
    const revoked = await verifier.verifyDelegationCredential(vc, {
      skipCache: true,
    });
    expect(revoked.valid).toBe(false);

    // Restore
    await statusListManager.updateStatus(credentialStatus, false);
    const restored = await verifier.verifyDelegationCredential(vc, {
      skipCache: true,
    });
    expect(restored.valid).toBe(true);
    expect(restored.checks?.statusValid).toBe(true);
  });

  it("should fail closed when status list is missing from storage", async () => {
    const { vc } = await issueDelegationWithStatus(["read:sensitive"]);

    // Verify valid first
    const before = await verifier.verifyDelegationCredential(vc);
    expect(before.valid).toBe(true);

    // Wipe storage — simulates storage outage
    statusListStorage.clear();

    // Should fail closed — missing status list != "not revoked"
    const after = await verifier.verifyDelegationCredential(vc, {
      skipCache: true,
    });
    expect(after.valid).toBe(false);
    expect(after.reason).toContain("Status list not found");
  });

  it("should handle multiple credentials on the same status list", async () => {
    // Clear storage for a clean state
    statusListStorage.clear();

    const cred1 = await issueDelegationWithStatus(["scope:a"]);
    const cred2 = await issueDelegationWithStatus(["scope:b"]);
    const cred3 = await issueDelegationWithStatus(["scope:c"]);

    // All should be valid
    expect((await verifier.verifyDelegationCredential(cred1.vc)).valid).toBe(true);
    expect((await verifier.verifyDelegationCredential(cred2.vc)).valid).toBe(true);
    expect((await verifier.verifyDelegationCredential(cred3.vc)).valid).toBe(true);

    // Revoke only cred2
    await statusListManager.updateStatus(cred2.credentialStatus, true);

    verifier.clearCache();

    // cred1 and cred3 should still be valid, cred2 revoked
    expect((await verifier.verifyDelegationCredential(cred1.vc)).valid).toBe(true);
    expect((await verifier.verifyDelegationCredential(cred2.vc)).valid).toBe(false);
    expect((await verifier.verifyDelegationCredential(cred3.vc)).valid).toBe(true);
  });
});
