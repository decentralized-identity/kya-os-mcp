import { describe, it, expect, vi } from "vitest";
import { createKyaOsTransport, type Transport, type JSONRPCMessage } from "../kya-os-transport.js";
import {
  createKyaOsMiddleware,
  type KyaOsMiddleware,
  type KyaOsToolHandler,
} from "../with-kya-os.js";
import { NodeCryptoProvider } from "../../__tests__/utils/node-crypto-provider.js";
import { generateDidKeyFromBase64 } from "../../utils/did-helpers.js";
import { DelegationCredentialIssuer } from "../../delegation/vc-issuer.js";
import {
  KYA_OS_PROOF_META_KEY,
  LEGACY_NAMESPACED_PROOF_META_KEY,
  LEGACY_PROOF_META_KEY,
  ProofGenerator,
} from "../../proof/generator.js";
import { LIFECYCLE_STAMP_META_KEY } from "../with-kya-os.session.js";
import { base64urlEncodeFromBytes } from "../../utils/base64.js";
import type { AuditTrailService } from "../../audit/service.js";
import type { DelegationCredential, Proof } from "../../types/protocol.js";

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

  it("keeps handler _meta keys when proof injection fails", async () => {
    const inner = createMockTransport();
    const kyaos = {
      wrapWithProof: () => async () => {
        throw new Error("signer unavailable");
      },
    } as unknown as KyaOsMiddleware;
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
      result: { content: [{ type: "text", text: "Hello!" }], _meta: { traceparent: "00-abc-01" } },
    });

    const sent = inner.sentMessages[0] as { result: { _meta: Record<string, unknown> } };
    expect(sent.result._meta.traceparent).toBe("00-abc-01");
    expect(sent.result._meta.proofError).toBeDefined();
  });

  it("marks a result without _meta unproven when the middleware throws a non-Error", async () => {
    const inner = createMockTransport();
    const kyaos = {
      wrapWithProof: () => async () => {
        throw "signer unavailable";
      },
    } as unknown as KyaOsMiddleware;
    const wrapper = createKyaOsTransport(inner, kyaos);
    await wrapper.start();
    inner.onmessage!({
      jsonrpc: "2.0", method: "tools/call", id: 2, params: { name: "greet", arguments: {} },
    });

    await wrapper.send({ jsonrpc: "2.0", id: 2, result: { content: [{ type: "text", text: "Hi" }] } });

    expect(inner.sentMessages[0]).toEqual({
      jsonrpc: "2.0",
      id: 2,
      result: {
        content: [{ type: "text", text: "Hi" }],
        _meta: { proofError: "Proof generation failed — response is unproven" },
      },
    });
  });

  it("lets a JSON-RPC error answer a pending call", async () => {
    const inner = createMockTransport();
    const kyaos = createMockKyaOs({ jws: "proof" });
    const wrapper = createKyaOsTransport(inner, kyaos);
    await wrapper.start();
    inner.onmessage!({
      jsonrpc: "2.0", method: "tools/call", id: 4, params: { name: "greet", arguments: {} },
    });

    const failure = { jsonrpc: "2.0", id: 4, error: { code: -32603, message: "internal" } };
    await wrapper.send(failure);
    // The error consumed the call, so a stray result with its id is not proved.
    const stray = { jsonrpc: "2.0", id: 4, result: { content: [{ type: "text", text: "late" }] } };
    await wrapper.send(stray);

    expect(inner.sentMessages).toEqual([failure, stray]);
  });
});

describe("createKyaOsTransport with the KYA-OS middleware", () => {
  const crypto = new NodeCryptoProvider();
  const consent = { scopeId: "cart:write", consentUrl: "https://consent.example/authorize" };

  async function middleware(
    record?: Pick<AuditTrailService, "record">["record"],
  ): Promise<KyaOsMiddleware> {
    const keyPair = await crypto.generateKeyPair();
    const did = generateDidKeyFromBase64(keyPair.publicKey);
    return createKyaOsMiddleware({
      identity: {
        did,
        kid: `${did}#${did.replace("did:key:", "")}`,
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
      },
      autoSession: true,
      ...(record === undefined ? {} : { audit: { record } }),
    }, crypto);
  }

  function auditEvents() {
    const events: string[] = [];
    const record: Pick<AuditTrailService, "record">["record"] = async (event) => {
      events.push(`${event.eventType}:${event.outcome}`);
      return { status: "pending", event: event as never };
    };
    return { events, record };
  }

  async function issueVC(scopes: string[]): Promise<DelegationCredential> {
    const keyPair = await crypto.generateKeyPair();
    const did = generateDidKeyFromBase64(keyPair.publicKey);
    const kid = `${did}#${did.replace("did:key:", "")}`;
    const sign = async (canonicalVC: string, _issuerDid: string, keyId: string): Promise<Proof> => ({
      type: "Ed25519Signature2020",
      created: new Date().toISOString(),
      verificationMethod: keyId,
      proofPurpose: "assertionMethod",
      proofValue: base64urlEncodeFromBytes(
        await crypto.sign(new TextEncoder().encode(canonicalVC), keyPair.privateKey),
      ),
    });
    return new DelegationCredentialIssuer(
      { getDid: () => did, getKeyId: () => kid, getPrivateKey: () => keyPair.privateKey },
      sign,
    ).createAndIssueDelegation({
      id: `del-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      issuerDid: did,
      subjectDid: did,
      constraints: { scopes, notAfter: Math.floor(Date.now() / 1000) + 3600 },
    });
  }

  /** A transport wrapper around a mock transport, connected as withKyaOs connects one. */
  async function connect(kyaos: KyaOsMiddleware) {
    const inner = createMockTransport();
    const wrapper = createKyaOsTransport(inner, kyaos);
    await wrapper.start();
    /** Drive one tools/call through the wrapper the way McpServer would. */
    const roundTrip = async (
      toolName: string,
      args: Record<string, unknown>,
      // What McpServer hands to send() after it dispatched the tool.
      result: Record<string, unknown>,
    ): Promise<Record<string, unknown>> => {
      inner.onmessage!({
        jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: toolName, arguments: args },
      });
      // The SDK validates the handler result into a fresh object before send().
      await wrapper.send({ jsonrpc: "2.0", id: 7, result: structuredClone(result) });
      return (inner.sentMessages.at(-1) as { result: Record<string, unknown> }).result;
    };
    return { inner, wrapper, roundTrip };
  }

  type ProofMeta = { meta: { outcome?: string; scopeId?: string } };
  const proofOf = (result: Record<string, unknown>) =>
    (result._meta as Record<string, ProofMeta> | undefined)?.[KYA_OS_PROOF_META_KEY];

  it("proves an unwrapped tool's result, keeping its own _meta keys", async () => {
    const { roundTrip } = await connect(await middleware());
    const sent = await roundTrip("greet", { name: "DIF" }, {
      content: [{ type: "text", text: "Hello!" }],
      _meta: { traceparent: "00-abc-01" },
    });

    expect(proofOf(sent)).toBeDefined();
    expect((sent._meta as Record<string, unknown>).traceparent).toBe("00-abc-01");
  });

  it("keeps a signed needs_authorization outcome instead of re-signing it as allowed", async () => {
    const kyaos = await middleware();
    const { roundTrip } = await connect(kyaos);
    const gated = kyaos.wrapWithDelegation("checkout", consent, async () => ({
      content: [{ type: "text", text: "ran" }],
    }));
    const challenge = await gated({ item: "x" });
    expect(proofOf(challenge)?.meta.outcome).toBe("needs_authorization");

    const sent = await roundTrip("checkout", { item: "x" }, challenge);

    // Sent as the gate returned it, less the private lifecycle stamp.
    const { [LIFECYCLE_STAMP_META_KEY]: stamp, ...challengeMeta } =
      challenge._meta as Record<string, unknown>;
    expect(stamp).toEqual(expect.any(String));
    expect(sent).toEqual({ ...challenge, _meta: challengeMeta });
  });

  it("records a challenged call once, with no lifecycle for the call that never ran", async () => {
    const { events, record } = auditEvents();
    const kyaos = await middleware(record);
    const { roundTrip } = await connect(kyaos);
    const gated = kyaos.wrapWithDelegation("checkout", consent, async () => ({
      content: [{ type: "text", text: "ran" }],
    }));
    const challenge = await gated({});
    const recorded = [...events];

    await roundTrip("checkout", {}, challenge);

    expect(recorded).toContain("tool.call.challenged:challenged");
    expect(events).toEqual(recorded);
  });

  it("keeps the scope-bearing proof of a delegated call and records its lifecycle once", async () => {
    const { events, record } = auditEvents();
    const kyaos = await middleware(record);
    const { roundTrip } = await connect(kyaos);
    const handler = kyaos.wrapWithDelegation(
      "checkout",
      consent,
      kyaos.wrapWithProof("checkout", async () => ({ content: [{ type: "text", text: "ran" }] })),
    );
    const result = await handler({ _kyaos_delegation: await issueVC(["cart:write"]) });
    expect(proofOf(result)?.meta.scopeId).toBe("cart:write");
    const recorded = [...events];

    const sent = await roundTrip("checkout", {}, result);

    expect(proofOf(sent)?.meta.scopeId).toBe("cart:write");
    expect(events).toEqual(recorded);
  });

  it("does not re-audit an error result a wrapper already recorded", async () => {
    const { events, record } = auditEvents();
    const kyaos = await middleware(record);
    const { roundTrip } = await connect(kyaos);
    const result = await kyaos.wrapWithProof("pay", async () => ({
      content: [{ type: "text", text: "declined" }],
      isError: true,
    }))({});
    expect(events).toEqual(["tool.call.started:unknown", "tool.call.failed:failed"]);

    const sent = await roundTrip("pay", {}, result);

    expect(sent.content).toEqual(result.content);
    expect(sent.isError).toBe(true);
    expect(events).toEqual(["tool.call.started:unknown", "tool.call.failed:failed"]);
  });

  it("still proves a tool response after a server request reuses its numeric id", async () => {
    const kyaos = await middleware();
    const inner = createMockTransport();
    const wrapper = createKyaOsTransport(inner, kyaos);
    await wrapper.start();
    inner.onmessage!({
      jsonrpc: "2.0", id: 0, method: "tools/call", params: { name: "ask", arguments: {} },
    });

    // Mid-call, the server asks the client something; request ids are
    // numbered per direction, so its first id is also 0.
    const elicitation = {
      jsonrpc: "2.0", id: 0, method: "elicitation/create", params: { message: "ok?" },
    };
    await wrapper.send(elicitation);
    await wrapper.send({ jsonrpc: "2.0", id: 0, result: { content: [{ type: "text", text: "done" }] } });

    expect(inner.sentMessages[0]).toEqual(elicitation);
    expect(proofOf((inner.sentMessages[1] as { result: Record<string, unknown> }).result)).toBeDefined();
  });

  it("forgets a cancelled call", async () => {
    const kyaos = await middleware();
    const inner = createMockTransport();
    const wrapper = createKyaOsTransport(inner, kyaos);
    await wrapper.start();
    inner.onmessage!({
      jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "slow", arguments: {} },
    });
    inner.onmessage!({
      jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 5, reason: "user" },
    });

    // A late response for the cancelled id is no longer treated as that call's.
    const late = { jsonrpc: "2.0", id: 5, result: { content: [{ type: "text", text: "late" }] } };
    await wrapper.send(late);

    expect(inner.sentMessages[0]).toEqual(late);
  });

  /** A proof another KYA-OS server minted, as a relayed upstream result carries it. */
  async function upstreamProof() {
    const keyPair = await crypto.generateKeyPair();
    const did = generateDidKeyFromBase64(keyPair.publicKey);
    const now = Math.floor(Date.now() / 1000);
    return new ProofGenerator(
      {
        did,
        kid: `${did}#${did.replace("did:key:", "")}`,
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
      },
      crypto,
    ).generateProof({ method: "relay", params: {} }, { data: [] }, {
      sessionId: "upstream",
      audience: did,
      nonce: "upstream-nonce",
      timestamp: now,
      createdAt: now,
      lastActivity: now,
      ttlMinutes: 30,
      identityState: "anonymous",
    });
  }

  const signerOf = (result: Record<string, unknown>, key = KYA_OS_PROOF_META_KEY) =>
    ((result._meta as Record<string, { meta: { did: string } } | undefined>)[key])?.meta.did;

  it.each([
    ["an audit marker", { "org.kya-os/audit": {} }],
    ["a terminal audit marker", { "org.kya-os/audit": { terminal: true, outcome: "denied" } }],
    ["a proof error", { proofError: "unproven upstream" }],
    ["a guessed lifecycle stamp", { [LIFECYCLE_STAMP_META_KEY]: "guessed" }],
  ])("proves and audits a relayed result that carries %s", async (_label, spoofed) => {
    const { events, record } = auditEvents();
    const kyaos = await middleware(record);
    const { roundTrip } = await connect(kyaos);

    const sent = await roundTrip("relay", { q: 1 }, {
      content: [{ type: "text", text: "from upstream" }],
      _meta: { traceparent: "00-abc-01", ...spoofed },
    });

    expect(signerOf(sent)).toBe(kyaos.identity.did);
    expect(events).toEqual([
      "tool.call.started:unknown", "proof.generated:succeeded", "tool.call.completed:succeeded",
    ]);
    const meta = sent._meta as Record<string, unknown>;
    expect(meta.traceparent).toBe("00-abc-01");
    for (const key of Object.keys(spoofed)) expect(Object.hasOwn(meta, key)).toBe(false);
  });

  it("replaces a relayed upstream proof with this server's own", async () => {
    const kyaos = await middleware();
    const { roundTrip } = await connect(kyaos);
    const foreign = await upstreamProof();

    const sent = await roundTrip("relay", {}, {
      content: [{ type: "text", text: "from upstream" }],
      _meta: {
        [KYA_OS_PROOF_META_KEY]: foreign,
        [LEGACY_NAMESPACED_PROOF_META_KEY]: foreign,
        [LEGACY_PROOF_META_KEY]: foreign,
      },
    });

    expect(signerOf(sent)).toBe(kyaos.identity.did);
    expect(signerOf(sent, LEGACY_PROOF_META_KEY)).toBe(kyaos.identity.did);
    expect(Object.hasOwn(sent._meta as object, LEGACY_NAMESPACED_PROOF_META_KEY)).toBe(false);
  });

  it("passes a wrapped result through once, without the outcome members its handler set", async () => {
    const { events, record } = auditEvents();
    const kyaos = await middleware(record);
    const { roundTrip } = await connect(kyaos);
    const result = await kyaos.wrapWithProof("relay", async () => ({
      content: [{ type: "text", text: "from upstream" }],
      _meta: { traceparent: "00-abc-01", proofError: "forged", "org.kya-os/audit": { terminal: true } },
    }))({});
    const recorded = [...events];

    const sent = await roundTrip("relay", {}, result);

    expect(recorded).toEqual([
      "tool.call.started:unknown", "proof.generated:succeeded", "tool.call.completed:succeeded",
    ]);
    expect(events).toEqual(recorded);
    expect(proofOf(sent)).toEqual(proofOf(result));
    const meta = sent._meta as Record<string, unknown>;
    expect(meta.traceparent).toBe("00-abc-01");
    expect(Object.hasOwn(meta, "proofError")).toBe(false);
    expect(Object.hasOwn(meta, "org.kya-os/audit")).toBe(false);
  });

  it("never sends the lifecycle stamp", async () => {
    const kyaos = await middleware();
    const { inner, wrapper, roundTrip } = await connect(kyaos);
    const wrapped = await kyaos.wrapWithProof("greet", async () => ({
      content: [{ type: "text", text: "Hello!" }],
    }))({});
    const stamp = (wrapped._meta as Record<string, unknown>)[LIFECYCLE_STAMP_META_KEY];
    expect(stamp).toEqual(expect.any(String));

    await roundTrip("greet", {}, wrapped); // the wrapper's own result, passed through
    await roundTrip("greet", {}, { content: [{ type: "text", text: "Hello!" }] }); // proved here
    await roundTrip("greet", {}, { content: [{ type: "text", text: "no" }], isError: true });
    // A result that answers no tracked call, such as an excluded tool's.
    await wrapper.send({ jsonrpc: "2.0", id: 99, result: structuredClone(wrapped) });

    expect(inner.sentMessages).toHaveLength(4);
    expect(JSON.stringify(inner.sentMessages)).not.toContain(stamp as string);
    expect(JSON.stringify(inner.sentMessages)).not.toContain(LIFECYCLE_STAMP_META_KEY);
  });

  it("removes a lifecycle stamp even behind a custom middleware", async () => {
    const inner = createMockTransport();
    const wrapper = createKyaOsTransport(inner, createMockKyaOs());
    await wrapper.start();

    await wrapper.send({
      jsonrpc: "2.0",
      id: 3,
      result: {
        content: [{ type: "text", text: "Hello!" }],
        _meta: { traceparent: "00-abc-01", [LIFECYCLE_STAMP_META_KEY]: "token" },
      },
    });

    expect(inner.sentMessages[0]).toEqual({
      jsonrpc: "2.0",
      id: 3,
      result: { content: [{ type: "text", text: "Hello!" }], _meta: { traceparent: "00-abc-01" } },
    });
  });
});
