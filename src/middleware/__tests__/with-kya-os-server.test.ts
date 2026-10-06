import { describe, it, expect, vi, afterEach } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { generateIdentity, withKyaOs } from "../with-kya-os-server.js";
import { NodeCryptoProvider } from "../../__tests__/utils/node-crypto-provider.js";
import { logger } from "../../logging/index.js";
import { KYA_OS_PROOF_META_KEY, LEGACY_PROOF_META_KEY } from "../../proof/index.js";
import { MemoryNonceCacheProvider } from "../../providers/memory.js";
import { RESPONSE_PROOF_PROFILE_ENVELOPE } from "../../types/protocol.js";

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

  it("threads emitLegacyProofKey through to the middleware (suppresses the legacy key)", async () => {
    const server = {
      connect: vi.fn().mockResolvedValue(undefined),
      registerTool: vi.fn(),
    };
    const identity = await generateIdentity(crypto);

    const kyaos = await withKyaOs(server, {
      crypto,
      identity,
      emitLegacyProofKey: false,
    });

    const hs = await kyaos.handleHandshake({
      nonce: "test-nonce",
      audience: identity.did,
      timestamp: Math.floor(Date.now() / 1000),
    });
    const sessionId = JSON.parse(hs.content[0].text).sessionId;

    const handler = kyaos.wrapWithProof("greet", async (args) => ({
      content: [{ type: "text", text: `Hello, ${args["name"]}!` }],
    }));
    const result = await handler({ name: "DIF" }, sessionId);

    // Proof is emitted under the namespaced key, but NOT the legacy bare key,
    // because emitLegacyProofKey: false was threaded through withKyaOs.
    expect(result._meta?.[KYA_OS_PROOF_META_KEY]).toBeDefined();
    expect(result._meta?.[LEGACY_PROOF_META_KEY]).toBeUndefined();
  });

  describe("replay protection and proof profile options", () => {
    const fakeServer = () => ({
      connect: vi.fn().mockResolvedValue(undefined),
      registerTool: vi.fn(),
    });

    it("shares an injected nonce cache, so a second replica rejects a replayed handshake", async () => {
      // One shared store stands in for Redis SET NX PX behind two replicas
      // serving the same identity.
      const nonceCache = new MemoryNonceCacheProvider();
      const identity = await generateIdentity(crypto);
      const replicaA = await withKyaOs(fakeServer(), { crypto, identity, nonceCache });
      const replicaB = await withKyaOs(fakeServer(), { crypto, identity, nonceCache });

      const handshake = {
        nonce: "replayed-nonce-0123456789",
        audience: identity.did,
        timestamp: Math.floor(Date.now() / 1000),
      };
      const first = JSON.parse((await replicaA.handleHandshake(handshake)).content[0]!.text);
      const replay = JSON.parse((await replicaB.handleHandshake(handshake)).content[0]!.text);

      expect(first.success).toBe(true);
      expect(replay.success).toBe(false);
      expect(replay.error.code).toBe("nonce_replay");
    });

    it("honors requireAtomicNonce by refusing a cache without an atomic consume()", async () => {
      class NonAtomicNonceCache extends MemoryNonceCacheProvider {}
      (NonAtomicNonceCache.prototype as { consume?: unknown }).consume = undefined;

      await expect(withKyaOs(fakeServer(), {
        crypto,
        nonceCache: new NonAtomicNonceCache(),
        requireAtomicNonce: true,
      })).rejects.toThrow(/requireAtomicNonce/);
    });

    it("mints envelope-profile proofs when responseProofProfile selects it", async () => {
      const kyaos = await withKyaOs(fakeServer(), {
        crypto,
        responseProofProfile: RESPONSE_PROOF_PROFILE_ENVELOPE,
      });

      const result = await kyaos.wrapWithProof("greet", async () => ({
        content: [{ type: "text", text: "Hello!" }],
      }))({});

      const meta = result._meta as Record<string, { meta: { prf?: string } }>;
      expect(meta[KYA_OS_PROOF_META_KEY]!.meta.prf).toBe(RESPONSE_PROOF_PROFILE_ENVELOPE);
    });
  });

  describe("on a server that is already connected", () => {
    const ALREADY_CONNECTED = /already connected/;
    const openServers: McpServer[] = [];

    /** A real SDK server with one app tool registered, as an app has before it connects. */
    function realServer(): McpServer {
      const server = new McpServer({ name: "fc-013", version: "1.0.0" });
      server.registerTool("greet", { description: "Say hello" }, async () => ({
        content: [{ type: "text", text: "Hello!" }],
      }));
      openServers.push(server);
      return server;
    }

    function alreadyConnectedWarnings(warn: ReturnType<typeof vi.spyOn>): unknown[][] {
      return warn.mock.calls.filter((call) => ALREADY_CONNECTED.test(String(call[0])));
    }

    afterEach(async () => {
      vi.restoreAllMocks();
      await Promise.all(openServers.splice(0).map((server) => server.close()));
    });

    it("warns that proofs will not reach the live connection when connect() ran first", async () => {
      const warn = vi.spyOn(logger, "warn").mockImplementation(() => undefined);
      const server = realServer();
      const [, serverTransport] = InMemoryTransport.createLinkedPair();
      await server.connect(serverTransport);

      await withKyaOs(server, { crypto });

      const warnings = alreadyConnectedWarnings(warn);
      expect(warnings).toHaveLength(1);
      expect(String(warnings[0]![0])).toMatch(/proofs will not be injected/i);
      expect(String(warnings[0]![0])).toMatch(/before server\.connect\(\)/);
    });

    it("warns before the SDK refuses to register _kyaos on a server connected with no tools", async () => {
      const warn = vi.spyOn(logger, "warn").mockImplementation(() => undefined);
      const server = new McpServer({ name: "fc-013-empty", version: "1.0.0" });
      openServers.push(server);
      const [, serverTransport] = InMemoryTransport.createLinkedPair();
      await server.connect(serverTransport);

      await expect(withKyaOs(server, { crypto })).rejects.toThrow(/after connecting/);

      expect(alreadyConnectedWarnings(warn)).toHaveLength(1);
    });

    it("does not warn when withKyaOs() runs before connect()", async () => {
      const warn = vi.spyOn(logger, "warn").mockImplementation(() => undefined);
      const server = realServer();

      await withKyaOs(server, { crypto });
      const [, serverTransport] = InMemoryTransport.createLinkedPair();
      await server.connect(serverTransport);

      expect(alreadyConnectedWarnings(warn)).toHaveLength(0);
    });

    it("falls back to server.server.transport on an SDK without isConnected()", async () => {
      const warn = vi.spyOn(logger, "warn").mockImplementation(() => undefined);
      const server = {
        connect: vi.fn().mockResolvedValue(undefined),
        registerTool: vi.fn(),
        server: { transport: { start: vi.fn(), send: vi.fn(), close: vi.fn() } },
      };

      await withKyaOs(server, { crypto });

      expect(alreadyConnectedWarnings(warn)).toHaveLength(1);
    });

    it("neither crashes nor warns on a server with no isConnected() and no inner transport", async () => {
      const warn = vi.spyOn(logger, "warn").mockImplementation(() => undefined);
      const server = {
        connect: vi.fn().mockResolvedValue(undefined),
        registerTool: vi.fn(),
      };

      await expect(withKyaOs(server, { crypto })).resolves.toBeDefined();

      expect(alreadyConnectedWarnings(warn)).toHaveLength(0);
    });
  });
});
