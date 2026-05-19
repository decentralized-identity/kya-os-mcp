import { describe, it, expect, vi } from "vitest";
import { generateIdentity, withKyaOs } from "../with-kya-os-server.js";
import { NodeCryptoProvider } from "../../__tests__/utils/node-crypto-provider.js";

const crypto = new NodeCryptoProvider();

describe("generateIdentity", () => {
  it("should return did, kid, privateKey, and publicKey", async () => {
    const identity = await generateIdentity(crypto);

    expect(identity.did).toMatch(/^did:key:z6Mk/);
    expect(identity.kid).toMatch(/^did:key:z6Mk.+#z6Mk/);
    expect(identity.privateKey).toBeDefined();
    expect(identity.publicKey).toBeDefined();
  });

  it("should use spec-compliant did:key fragment (not #keys-1)", async () => {
    const identity = await generateIdentity(crypto);
    const fragment = identity.kid.split("#")[1];

    expect(fragment).not.toBe("keys-1");
    expect(fragment).toMatch(/^z6Mk/);
    expect(identity.kid).toBe(`${identity.did}#${identity.did.replace("did:key:", "")}`);
  });

  it("should generate unique identities each call", async () => {
    const a = await generateIdentity(crypto);
    const b = await generateIdentity(crypto);

    expect(a.did).not.toBe(b.did);
    expect(a.privateKey).not.toBe(b.privateKey);
  });
});

describe("withKyaOs", () => {
  it("should register _kyaos tool on server by default", async () => {
    const registerTool = vi.fn();
    const server = {
      connect: vi.fn().mockResolvedValue(undefined),
      registerTool,
    };

    await withKyaOs(server, { crypto });

    expect(registerTool).toHaveBeenCalledWith(
      "_kyaos",
      expect.objectContaining({ description: expect.any(String) }),
      expect.any(Function),
    );
  });

  it("should not register tool when handshakeExposure is 'none'", async () => {
    const registerTool = vi.fn();
    const server = {
      connect: vi.fn().mockResolvedValue(undefined),
      registerTool,
    };

    await withKyaOs(server, { crypto, handshakeExposure: "none" });

    expect(registerTool).not.toHaveBeenCalled();
  });

  it("should patch server.connect to wrap transport", async () => {
    const originalConnect = vi.fn().mockResolvedValue(undefined);
    const server = {
      connect: originalConnect,
      registerTool: vi.fn(),
    };

    await withKyaOs(server, { crypto });

    // server.connect should now be patched
    expect(server.connect).not.toBe(originalConnect);

    // Call the patched connect
    const mockTransport = {
      start: vi.fn().mockResolvedValue(undefined),
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
    };
    await server.connect(mockTransport);

    // Original connect should have been called with wrapped transport
    expect(originalConnect).toHaveBeenCalledTimes(1);
    // The argument should be the wrapped transport (not the original)
    const wrappedTransport = originalConnect.mock.calls[0][0];
    expect(wrappedTransport).not.toBe(mockTransport);
  });

  it("should not patch connect when proofAllTools is false", async () => {
    const originalConnect = vi.fn().mockResolvedValue(undefined);
    const server = {
      connect: originalConnect,
      registerTool: vi.fn(),
    };

    await withKyaOs(server, { crypto, proofAllTools: false });

    // connect should NOT be patched
    expect(server.connect).toBe(originalConnect);
  });

  it("should return KyaOsMiddleware instance", async () => {
    const server = {
      connect: vi.fn().mockResolvedValue(undefined),
      registerTool: vi.fn(),
    };

    const kyaos = await withKyaOs(server, { crypto });

    expect(kyaos).toBeDefined();
    expect(kyaos.wrapWithProof).toBeInstanceOf(Function);
    expect(kyaos.wrapWithDelegation).toBeInstanceOf(Function);
    expect(kyaos.handleKyaOs).toBeInstanceOf(Function);
  });
});
