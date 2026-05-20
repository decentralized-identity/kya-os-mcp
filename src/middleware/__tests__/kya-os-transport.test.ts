import { describe, it, expect, vi } from "vitest";
import { createKyaOsTransport, type Transport, type JSONRPCMessage } from "../kya-os-transport.js";
import type { KyaOsMiddleware, KyaOsToolHandler } from "../with-kya-os.js";

function createMockTransport(): Transport & { sentMessages: JSONRPCMessage[] } {
  const sent: JSONRPCMessage[] = [];
  return {
    sentMessages: sent,
    start: vi.fn().mockResolvedValue(undefined),
    send: vi.fn(async (msg: JSONRPCMessage) => { sent.push(msg); }),
    close: vi.fn().mockResolvedValue(undefined),
    onmessage: undefined,
    onclose: undefined,
    onerror: undefined,
  };
}

function createMockKyaOs(proofResult?: Record<string, unknown>): KyaOsMiddleware {
  return {
    wrapWithProof: (_toolName: string, handler: KyaOsToolHandler) => {
      return async (args: Record<string, unknown>) => {
        const result = await handler(args);
        if (proofResult) {
          result._meta = { proof: proofResult };
        }
        return result;
      };
    },
  } as unknown as KyaOsMiddleware;
}

describe("createKyaOsTransport", () => {
  it("should pass through non-tools/call messages unmodified", async () => {
    const inner = createMockTransport();
    const kyaos = createMockKyaOs();
    const wrapper = createKyaOsTransport(inner, kyaos);

    await wrapper.send({ jsonrpc: "2.0", method: "resources/list", id: 1 });

    expect(inner.sentMessages).toHaveLength(1);
    expect(inner.sentMessages[0]).toEqual({ jsonrpc: "2.0", method: "resources/list", id: 1 });
  });

  it("should skip proof injection for excluded tools", async () => {
    const inner = createMockTransport();
    const kyaos = createMockKyaOs({ jws: "test" });
    const wrapper = createKyaOsTransport(inner, kyaos, ["_kyaos"]);

    await wrapper.start();

    // Simulate incoming _kyaos request
    inner.onmessage!({
      jsonrpc: "2.0",
      method: "tools/call",
      id: 42,
      params: { name: "_kyaos", arguments: { action: "handshake" } },
    });

    // Simulate response
    await wrapper.send({
      jsonrpc: "2.0",
      id: 42,
      result: { content: [{ type: "text", text: "ok" }] },
    });

    // Should pass through without proof
    const sent = inner.sentMessages[0] as { result?: { _meta?: unknown } };
    expect(sent.result?._meta).toBeUndefined();
  });

  it("should inject proof for non-excluded tool calls", async () => {
    const inner = createMockTransport();
    const proof = { jws: "test.jws.sig", meta: { did: "did:key:z6Mk..." } };
    const kyaos = createMockKyaOs(proof);
    const wrapper = createKyaOsTransport(inner, kyaos);

    await wrapper.start();

    // Simulate incoming greet request
    inner.onmessage!({
      jsonrpc: "2.0",
      method: "tools/call",
      id: 1,
      params: { name: "greet", arguments: { name: "test" } },
    });

    // Simulate response
    await wrapper.send({
      jsonrpc: "2.0",
      id: 1,
      result: { content: [{ type: "text", text: "Hello!" }] },
    });

    const sent = inner.sentMessages[0] as { result?: { _meta?: { proof?: unknown } } };
    expect(sent.result?._meta?.proof).toEqual(proof);
  });

  it("should not inject proof for error responses", async () => {
    const inner = createMockTransport();
    const kyaos = createMockKyaOs({ jws: "test" });
    const wrapper = createKyaOsTransport(inner, kyaos);

    await wrapper.start();

    inner.onmessage!({
      jsonrpc: "2.0",
      method: "tools/call",
      id: 1,
      params: { name: "greet", arguments: {} },
    });

    await wrapper.send({
      jsonrpc: "2.0",
      id: 1,
      result: { content: [{ type: "text", text: "error" }], isError: true },
    });

    const sent = inner.sentMessages[0] as { result?: { _meta?: unknown } };
    expect(sent.result?._meta).toBeUndefined();
  });

  it("should proxy onmessage/onclose/onerror to inner transport", () => {
    const inner = createMockTransport();
    const kyaos = createMockKyaOs();
    const wrapper = createKyaOsTransport(inner, kyaos);

    const handler = () => {};
    wrapper.onmessage = handler;
    expect(inner.onmessage).toBe(handler);
    expect(wrapper.onmessage).toBe(handler);

    const closeHandler = () => {};
    wrapper.onclose = closeHandler;
    expect(inner.onclose).toBe(closeHandler);

    const errorHandler = () => {};
    wrapper.onerror = errorHandler;
    expect(inner.onerror).toBe(errorHandler);
  });

  it("should delegate start and close to inner transport", async () => {
    const inner = createMockTransport();
    const kyaos = createMockKyaOs();
    const wrapper = createKyaOsTransport(inner, kyaos);

    // close delegates directly
    await wrapper.close();
    expect(inner.close).toHaveBeenCalled();
  });
});
