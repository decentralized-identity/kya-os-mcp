import { describe, it, expect } from "vitest";
import {
  buildAuditRecord,
  MemoryAuditLogProvider,
  NoopAuditLogProvider,
} from "../audit-log.js";
import type { AuditContext, AuditEventContext } from "../../types/protocol.js";

const ctx: AuditContext = {
  identity: { did: "did:key:zAlice", kid: "did:key:zAlice#keys-1" },
  session: { sessionId: "kyaos_123", audience: "did:web:server.example" },
  requestHash: "sha256:" + "a".repeat(64),
  responseHash: "sha256:" + "b".repeat(64),
  verified: "yes",
  scopeId: "calendar:read",
};

describe("buildAuditRecord", () => {
  it("maps an AuditContext to a frozen audit.v1 record", () => {
    const rec = buildAuditRecord(ctx);
    expect(rec.version).toBe("audit.v1");
    expect(rec.session).toBe("kyaos_123");
    expect(rec.audience).toBe("did:web:server.example");
    expect(rec.did).toBe("did:key:zAlice");
    expect(rec.kid).toBe("did:key:zAlice#keys-1");
    expect(rec.reqHash).toBe(ctx.requestHash);
    expect(rec.resHash).toBe(ctx.responseHash);
    expect(rec.verified).toBe("yes");
    expect(rec.scope).toBe("calendar:read");
    expect(typeof rec.ts).toBe("number");
  });

  it("uses '-' for scope when scopeId is absent", () => {
    const { scopeId: _omit, ...noScope } = ctx;
    expect(buildAuditRecord(noScope).scope).toBe("-");
  });
});

describe("MemoryAuditLogProvider", () => {
  it("stores a built record on logAuditRecord", async () => {
    const p = new MemoryAuditLogProvider();
    await p.logAuditRecord(ctx);
    expect(p.records).toHaveLength(1);
    expect(p.records[0]?.session).toBe("kyaos_123");
    expect(p.records[0]?.version).toBe("audit.v1");
  });

  it("deduplicates audit records per session (one record per session)", async () => {
    const p = new MemoryAuditLogProvider();
    await p.logAuditRecord(ctx);
    await p.logAuditRecord({ ...ctx, requestHash: "sha256:" + "c".repeat(64) }); // same session
    expect(p.records).toHaveLength(1);

    await p.logAuditRecord({
      ...ctx,
      session: { sessionId: "kyaos_999", audience: ctx.session.audience },
    });
    expect(p.records).toHaveLength(2);
  });

  it("logEvent records every event without session dedup", async () => {
    const p = new MemoryAuditLogProvider();
    const ev: AuditEventContext = {
      eventType: "consent:approved",
      identity: ctx.identity,
      session: ctx.session,
    };
    await p.logEvent(ev);
    await p.logEvent(ev);
    expect(p.events).toHaveLength(2);
  });
});

describe("NoopAuditLogProvider", () => {
  it("is a no-op that resolves without error", async () => {
    const p = new NoopAuditLogProvider();
    await expect(p.logAuditRecord(ctx)).resolves.toBeUndefined();
    await expect(
      p.logEvent({ eventType: "x", identity: ctx.identity, session: ctx.session }),
    ).resolves.toBeUndefined();
  });
});
