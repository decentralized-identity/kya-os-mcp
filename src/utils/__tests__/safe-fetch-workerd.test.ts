/**
 * Workerd/Cloudflare-Worker bundle safety for the SSRF-hardened fetch.
 *
 * `@kya-os/mcp` is imported into Cloudflare Workers to run the VC-JWT / Entity
 * Card verification path (card resolution + status-list revocation), which
 * builds a `SafeFetch`. `@kya-os/mcp@1.10.0` broke those Worker bundles at build
 * time: `safe-fetch-transports.ts` STATICALLY imported `node:dns/promises` and
 * `node:https` at the module top level, so importing anything that transitively
 * loads it required node built-ins that workerd doesn't provide.
 *
 * These tests pin the fix: the module must load node built-ins LAZILY (only when
 * a node code path actually runs), and a Worker-shaped configuration (injected
 * DNS seam + `fetchTransport`, or trusted origins) must complete a request
 * WITHOUT ever touching node:dns. The SSRF policy is unchanged — that stays
 * covered by `safe-fetch.test.ts`.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect, vi } from "vitest";
import {
  createSafeFetch,
  defaultLookup,
  fetchTransport,
  selectDefaultTransport,
} from "../safe-fetch.js";
import type { DnsAddress, RawResponse, TransportInit } from "../safe-fetch.js";

const TRANSPORTS_SRC = fileURLToPath(
  new URL("../safe-fetch-transports.ts", import.meta.url),
);

const transportInit = (over: Partial<TransportInit> = {}): TransportInit => ({
  signal: new AbortController().signal,
  hostname: "example.com",
  pinnedAddress: "93.184.216.34",
  family: 4,
  maxBytes: 1_048_576,
  ...over,
});

describe("workerd bundle safety — no static node built-in imports", () => {
  it("safe-fetch-transports.ts has no top-level runtime `node:` import", () => {
    const src = readFileSync(TRANSPORTS_SRC, "utf8");
    // Top-level runtime imports only (ignore `import type`, which is erased and
    // never reaches the bundle). A match here means the module would require a
    // node built-in at load time — the exact break for workerd/browser bundles.
    const offending = src
      .split("\n")
      .filter((line) => /^\s*import\s+(?!type\b)[^;]*from\s+['"]node:/.test(line));
    expect(offending).toEqual([]);
  });
});

describe("worker runtime path — a request completes without node:dns", () => {
  it("uses the INJECTED dns seam (never node:dns) for a non-trusted origin", async () => {
    // A Worker injects its own DNS seam (e.g. DNS-over-HTTPS) and fetchTransport.
    // If the library reached for node:dns instead, this custom seam wouldn't run.
    const workerLookup = vi.fn(
      async (): Promise<DnsAddress[]> => [{ address: "93.184.216.34", family: 4 }],
    );
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(JSON.stringify({ card: true }), { status: 200 }));
    try {
      const safeFetch = createSafeFetch({
        lookup: workerLookup,
        transport: fetchTransport,
      });
      const res = await safeFetch("https://example.com/card.json");
      expect(workerLookup).toHaveBeenCalledWith("example.com");
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ card: true });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("selectDefaultTransport returns a SafeFetchTransport function", () => {
    expect(typeof selectDefaultTransport()).toBe("function");
  });

  it("auto-selects fetchTransport when node:https can't load (workerd)", async () => {
    // Simulate a runtime without node:https: the lazy loader's import rejects,
    // so the default transport must transparently fall back to global fetch.
    vi.resetModules();
    vi.doMock("node:https", () => {
      throw new Error("node:https is not available in workerd");
    });
    try {
      const { selectDefaultTransport: freshSelect } = await import(
        "../safe-fetch-transports.js"
      );
      const transport = freshSelect();
      const fetchSpy = vi
        .spyOn(globalThis, "fetch")
        .mockResolvedValue(new Response("ok", { status: 200 }));
      try {
        const raw: RawResponse = await transport(
          "https://example.com/x",
          transportInit(),
        );
        expect(fetchSpy).toHaveBeenCalled();
        expect(raw.status).toBe(200);
      } finally {
        fetchSpy.mockRestore();
      }
    } finally {
      vi.doUnmock("node:https");
      vi.resetModules();
    }
  });

  it("nodeHttpsTransport throws a clear error when node:https can't load", async () => {
    // The exported node transport, invoked directly in a runtime without
    // node:https, fails loudly rather than silently mis-fetching.
    vi.resetModules();
    vi.doMock("node:https", () => {
      throw new Error("node:https is not available in workerd");
    });
    try {
      const { nodeHttpsTransport } = await import("../safe-fetch-transports.js");
      await expect(
        nodeHttpsTransport("https://example.com/x", transportInit()),
      ).rejects.toThrow(/node:https is unavailable/);
    } finally {
      vi.doUnmock("node:https");
      vi.resetModules();
    }
  });
});

describe("buildPinnedLookup — pins both node:https lookup call-shapes to the validated IP", () => {
  it("returns an ARRAY for the { all: true } shape (Node ≥20 autoSelectFamily)", async () => {
    const { buildPinnedLookup } = await import("../safe-fetch-transports.js");
    const lookup = buildPinnedLookup("93.184.216.34", 4);
    const result = await new Promise<unknown>((resolve) => {
      // @ts-expect-error exercising the { all: true } overload the runtime uses
      lookup("example.com", { all: true }, (_e: unknown, addrs: unknown) => resolve(addrs));
    });
    expect(result).toEqual([{ address: "93.184.216.34", family: 4 }]);
  });

  it("returns the SCALAR 3-arg form otherwise", async () => {
    const { buildPinnedLookup } = await import("../safe-fetch-transports.js");
    const lookup = buildPinnedLookup("2606:2800:220:1::", 6);
    const result = await new Promise<[unknown, unknown]>((resolve) => {
      // @ts-expect-error exercising the scalar overload
      lookup("example.com", {}, (_e: unknown, address: unknown, family: unknown) =>
        resolve([address, family]),
      );
    });
    expect(result).toEqual(["2606:2800:220:1::", 6]);
  });
});

describe("defaultLookup — lazy node:dns", () => {
  it("resolves a hostname to at least one address (lazy-loads node:dns)", async () => {
    const addresses = await defaultLookup("localhost");
    expect(addresses.length).toBeGreaterThan(0);
    for (const a of addresses) {
      expect(typeof a.address).toBe("string");
      expect([4, 6]).toContain(a.family);
    }
  });

  it("throws a guiding error when node:dns can't load (workerd)", async () => {
    vi.resetModules();
    vi.doMock("node:dns/promises", () => {
      throw new Error("node:dns is not available in workerd");
    });
    try {
      const { defaultLookup: freshLookup } = await import(
        "../safe-fetch-transports.js"
      );
      await expect(freshLookup("example.com")).rejects.toThrow(
        /inject a `lookup` seam/,
      );
    } finally {
      vi.doUnmock("node:dns/promises");
      vi.resetModules();
    }
  });
});
