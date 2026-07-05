/**
 * Tests for the SSRF-hardened outbound fetch (safe-fetch).
 *
 * DNS + transport are injected seams, so the whole SSRF policy is exercised with mocks —
 * no real network or DNS is touched.
 *
 * @package @kya-os/mcp/utils/__tests__
 */

import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, it, expect, vi } from "vitest";
import {
  createSafeFetch,
  fetchTransport,
  isBlockedAddress,
  type DnsAddress,
  type DnsLookup,
  type RawResponse,
  type SafeFetchTransport,
  type TransportInit,
} from "../safe-fetch";

const PUBLIC_V4: DnsAddress = { address: "93.184.216.34", family: 4 };
const PUBLIC_V6: DnsAddress = { address: "2606:2800:220:1::", family: 6 };

const lookupReturning =
  (...addresses: DnsAddress[]): DnsLookup =>
  async () =>
    addresses;

const headers = (entries: Record<string, string> = {}): RawResponse["headers"] => ({
  get: (name: string) => entries[name.toLowerCase()] ?? null,
});

const rawResponse = (init: {
  status?: number;
  headers?: Record<string, string>;
  body?: string;
}): RawResponse => ({
  status: init.status ?? 200,
  headers: headers(init.headers),
  text: () => Promise.resolve(init.body ?? ""),
});

/** A transport that yields the given responses in order (repeating the last). */
const transportReturning = (...responses: RawResponse[]) => {
  let i = 0;
  return vi.fn(async (_url: string, _init: TransportInit): Promise<RawResponse> => {
    const response = responses[Math.min(i, responses.length - 1)];
    i += 1;
    return response ?? rawResponse({});
  });
};

const okJson = (value: unknown): RawResponse => rawResponse({ status: 200, body: JSON.stringify(value) });

describe("createSafeFetch", () => {
  describe("scheme + URL validation", () => {
    it("rejects non-https URLs", async () => {
      const fetch = createSafeFetch({
        lookup: lookupReturning(PUBLIC_V4),
        transport: transportReturning(okJson({})),
      });
      await expect(fetch("http://example.com/card.json")).rejects.toThrow(/only https/);
    });

    it("rejects file: and other schemes", async () => {
      const fetch = createSafeFetch({
        lookup: lookupReturning(PUBLIC_V4),
        transport: transportReturning(okJson({})),
      });
      await expect(fetch("file:///etc/passwd")).rejects.toThrow(/only https/);
    });

    it("rejects malformed URLs", async () => {
      const fetch = createSafeFetch({
        lookup: lookupReturning(PUBLIC_V4),
        transport: transportReturning(okJson({})),
      });
      await expect(fetch("not a url")).rejects.toThrow(/invalid URL/);
    });
  });

  describe("happy path", () => {
    it("returns a FetchLike-compatible response for a public host", async () => {
      const fetch = createSafeFetch({
        lookup: lookupReturning(PUBLIC_V4),
        transport: transportReturning(okJson({ hello: "world" })),
      });
      const res = await fetch("https://example.com/card.json");
      expect(res.ok).toBe(true);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ hello: "world" });
    });

    it("allows a public IPv6 address", async () => {
      const fetch = createSafeFetch({
        lookup: lookupReturning(PUBLIC_V6),
        transport: transportReturning(okJson({ v6: true })),
      });
      const res = await fetch("https://example.com/card.json");
      expect(await res.json()).toEqual({ v6: true });
    });

    it("reports ok:false for a non-2xx, non-redirect status", async () => {
      const fetch = createSafeFetch({
        lookup: lookupReturning(PUBLIC_V4),
        transport: transportReturning(rawResponse({ status: 404, body: "{}" })),
      });
      const res = await fetch("https://example.com/missing.json");
      expect(res.ok).toBe(false);
      expect(res.status).toBe(404);
    });
  });

  describe("DNS resolution + pinning (rebinding guard)", () => {
    it("resolves the host once and pins the connection to the validated address", async () => {
      let captured: TransportInit | undefined;
      const lookup = vi.fn(async (): Promise<DnsAddress[]> => [PUBLIC_V4, { address: "8.8.8.8", family: 4 }]);
      const transport = vi.fn(async (_url: string, init: TransportInit): Promise<RawResponse> => {
        captured = init;
        return okJson({});
      });
      const fetch = createSafeFetch({ lookup, transport });
      await fetch("https://example.com/card.json");
      expect(lookup).toHaveBeenCalledWith("example.com");
      expect(captured?.pinnedAddress).toBe(PUBLIC_V4.address);
      expect(captured?.family).toBe(4);
      expect(captured?.hostname).toBe("example.com");
    });

    it("rejects when ANY resolved address is non-public (split-horizon rebinding)", async () => {
      const transport = transportReturning(okJson({}));
      const fetch = createSafeFetch({
        lookup: lookupReturning(PUBLIC_V4, { address: "10.0.0.5", family: 4 }),
        transport,
      });
      await expect(fetch("https://example.com/card.json")).rejects.toThrow(/non-public/);
      expect(transport).not.toHaveBeenCalled();
    });

    it("rejects when DNS returns no addresses", async () => {
      const fetch = createSafeFetch({
        lookup: lookupReturning(),
        transport: transportReturning(okJson({})),
      });
      await expect(fetch("https://example.com/card.json")).rejects.toThrow(/no addresses/);
    });

    const blocked = [
      "10.0.0.1",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.1.1",
      "127.0.0.1",
      "169.254.169.254",
      "169.254.1.1",
      "0.0.0.0",
      "100.64.0.1",
      "224.0.0.1",
      "255.255.255.255",
      "::1",
      "::",
      "fd00::1",
      "fc00::1",
      "fe80::1",
    ];

    it.each(blocked)("denies a connection to %s", async (address) => {
      const family = address.includes(":") ? 6 : 4;
      const transport = transportReturning(okJson({}));
      const fetch = createSafeFetch({ lookup: lookupReturning({ address, family }), transport });
      await expect(fetch("https://example.com/card.json")).rejects.toThrow(/non-public/);
      expect(transport).not.toHaveBeenCalled();
    });
  });

  describe("redirect handling", () => {
    it("follows a same-origin redirect", async () => {
      const transport = transportReturning(
        rawResponse({ status: 302, headers: { location: "https://example.com/b" } }),
        okJson({ followed: true }),
      );
      const lookup = vi.fn(lookupReturning(PUBLIC_V4));
      const fetch = createSafeFetch({ lookup, transport });
      const res = await fetch("https://example.com/a");
      expect(await res.json()).toEqual({ followed: true });
      expect(transport).toHaveBeenCalledTimes(2);
      expect(lookup).toHaveBeenCalledTimes(2);
    });

    it("blocks a cross-origin redirect", async () => {
      const fetch = createSafeFetch({
        lookup: lookupReturning(PUBLIC_V4),
        transport: transportReturning(
          rawResponse({ status: 302, headers: { location: "https://evil.example.net/x" } }),
        ),
      });
      await expect(fetch("https://example.com/a")).rejects.toThrow(/cross-origin redirect blocked/);
    });

    it("blocks a redirect that downgrades to http", async () => {
      const fetch = createSafeFetch({
        lookup: lookupReturning(PUBLIC_V4),
        transport: transportReturning(
          rawResponse({ status: 301, headers: { location: "http://example.com/x" } }),
        ),
      });
      await expect(fetch("https://example.com/a")).rejects.toThrow(/non-https/);
    });

    it("rejects a 3xx without a Location header", async () => {
      const fetch = createSafeFetch({
        lookup: lookupReturning(PUBLIC_V4),
        transport: transportReturning(rawResponse({ status: 302 })),
      });
      await expect(fetch("https://example.com/a")).rejects.toThrow(/without a Location/);
    });

    it("rejects when the redirect cap is exceeded", async () => {
      const transport = transportReturning(
        rawResponse({ status: 302, headers: { location: "https://example.com/loop" } }),
      );
      const fetch = createSafeFetch({ lookup: lookupReturning(PUBLIC_V4), transport, maxRedirects: 1 });
      await expect(fetch("https://example.com/a")).rejects.toThrow(/too many redirects/);
      expect(transport).toHaveBeenCalledTimes(2);
    });

    it("wraps a malformed redirect Location in a safe-fetch: error (not a raw TypeError)", async () => {
      const fetch = createSafeFetch({
        lookup: lookupReturning(PUBLIC_V4),
        transport: transportReturning(rawResponse({ status: 302, headers: { location: "https://[" } })),
      });
      // Fail-closed AND consistent with the module's error convention (prefixed, descriptive).
      await expect(fetch("https://example.com/a")).rejects.toThrow(
        /safe-fetch: redirect location is not a valid URL/,
      );
    });
  });

  describe("size cap", () => {
    it("rejects when the declared content-length exceeds the cap", async () => {
      const fetch = createSafeFetch({
        lookup: lookupReturning(PUBLIC_V4),
        transport: transportReturning(rawResponse({ headers: { "content-length": "5000" }, body: "{}" })),
        maxBytes: 100,
      });
      await expect(fetch("https://example.com/big.json")).rejects.toThrow(/content-length .* exceeds cap/);
    });

    it("rejects when the actual body exceeds the cap (no/lying content-length)", async () => {
      const fetch = createSafeFetch({
        lookup: lookupReturning(PUBLIC_V4),
        transport: transportReturning(rawResponse({ body: "x".repeat(200) })),
        maxBytes: 50,
      });
      await expect(fetch("https://example.com/big.json")).rejects.toThrow(/body exceeds size cap/);
    });
  });

  describe("timeout", () => {
    it("aborts a request that exceeds the timeout", async () => {
      const transport: SafeFetchTransport = (_url, init) =>
        new Promise<RawResponse>((_resolve, reject) => {
          init.signal.addEventListener("abort", () => reject(init.signal.reason));
        });
      const fetch = createSafeFetch({ lookup: lookupReturning(PUBLIC_V4), transport, timeoutMs: 5 });
      await expect(fetch("https://example.com/slow.json")).rejects.toThrow(/timed out/);
    });
  });
});

describe("first-party origin escape hatch (config)", () => {
  it("rejects a non-https first-party origin (fail closed)", () => {
    expect(() => createSafeFetch({ allowOrigins: ["http://example.com"] })).toThrow(/must be https/);
  });

  it("rejects an unparseable first-party origin (fail closed)", () => {
    expect(() => createSafeFetch({ firstPartyOrigin: "not a url" })).toThrow(/invalid first-party origin/);
  });
});

describe("fetch transport keeps the SSRF screen", () => {
  it.each(["169.254.169.254", "10.0.0.1"])(
    "denies the non-public address %s before any fetch is issued",
    async (address) => {
      const spy = vi.fn(fetchTransport);
      const fetch = createSafeFetch({ lookup: lookupReturning({ address, family: 4 }), transport: spy });
      await expect(fetch("https://metadata.example/latest")).rejects.toThrow(/non-public/);
      expect(spy).not.toHaveBeenCalled();
    },
  );
});

/**
 * Integration coverage the mocked-transport suite CANNOT provide: drive the REAL `fetchTransport`
 * socket path (global `fetch` + `redirect: 'manual'` + `readCapped`) against a loopback server.
 * This is the class of failure that broke 100% of fetches in the Vercel Node serverless runtime on
 * 2026-07-02 — the pinned `node:https` path misbehaved there and the mocks never touched a real
 * socket, so nothing caught it. Plain HTTP (not HTTPS) is deliberate: `fetchTransport` is
 * scheme-agnostic — `assertHttpsUrl` enforces https ONE layer up (covered by the scheme tests) — so
 * a loopback HTTP server exercises the exact transport code with no cert, no `openssl` dependency,
 * and no TLS-verification bypass.
 */
describe("fetchTransport (real loopback server)", () => {
  let server: import("node:http").Server;
  let base = "";

  const init = (over: Partial<TransportInit> = {}): TransportInit => ({
    signal: new AbortController().signal,
    hostname: "127.0.0.1",
    pinnedAddress: "",
    family: 4,
    maxBytes: 1_048_576,
    ...over,
  });

  beforeAll(async () => {
    const http = await import("node:http");
    server = http.createServer((req, res) => {
      if (req.url === "/redirect") {
        res.writeHead(302, { location: `${base}/card.json` });
        res.end();
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ card: true }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("completes a GET over a real socket and returns the body", async () => {
    const raw = await fetchTransport(`${base}/card.json`, init());
    expect(raw.status).toBe(200);
    expect(JSON.parse(await raw.text())).toEqual({ card: true });
  });

  it("surfaces a 3xx raw (redirect: 'manual') instead of auto-following it", async () => {
    const raw = await fetchTransport(`${base}/redirect`, init());
    expect(raw.status).toBe(302);
    expect(raw.headers.get("location")).toBe(`${base}/card.json`);
  });

  it("enforces the byte cap mid-stream on a real body", async () => {
    await expect(fetchTransport(`${base}/card.json`, init({ maxBytes: 4 }))).rejects.toThrow(/exceeds size cap/);
  });
});

describe("first-party origin escape hatch (full createSafeFetch path)", () => {
  it("skips the SSRF screen and fetches plain by name — no lookup, global fetch used", async () => {
    const lookup = vi.fn(lookupReturning({ address: "127.0.0.1", family: 4 })); // would BLOCK if screened
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(JSON.stringify({ card: true }), { status: 200 }));
    try {
      const fetch = createSafeFetch({ lookup, allowOrigins: ["https://api.example.com"] });
      const res = await fetch("https://api.example.com/card.json");
      expect(lookup).not.toHaveBeenCalled();
      expect(fetchSpy).toHaveBeenCalledWith(
        "https://api.example.com/card.json",
        expect.objectContaining({ method: "GET", redirect: "manual" }),
      );
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ card: true });
    } finally {
      fetchSpy.mockRestore();
    }
  });
});

describe("isBlockedAddress", () => {
  const allowed = ["93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:2800:220:1::", "2002:0808:0808::"];
  it.each(allowed)("permits the public address %s", (address) => {
    expect(isBlockedAddress(address)).toBe(false);
  });

  const denied = [
    "10.0.0.1",
    "172.16.0.1",
    "192.168.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "0.0.0.0",
    "100.64.0.1",
    "224.0.0.1",
    "255.255.255.255",
    "::1",
    "::",
    "fd00::1",
    "fe80::1",
    "192.0.2.1", // RFC 5737 TEST-NET-1
    "198.51.100.1", // RFC 5737 TEST-NET-2
    "203.0.113.1", // RFC 5737 TEST-NET-3
    "2001:db8::1", // RFC 3849 documentation
    "100::1", // RFC 6666 discard-only
    // IPv6 transition ranges (also comprehensively locked in review-regressions.test.ts #6b):
    "64:ff9b::10.0.0.1", // NAT64 well-known /96 → RFC1918
    "64:ff9b:1::a9fe:a9fe", // NAT64 LOCAL-USE /48 → 169.254.169.254 cloud metadata
    "2002:0a00:0001::", // 6to4 embedding 10.0.0.1
    "2001:0:0:0:0:0:0:1", // Teredo 2001:0000::/32
    "fec0::1", // deprecated site-local
  ];
  it.each(denied)("denies the non-public address %s", (address) => {
    expect(isBlockedAddress(address)).toBe(true);
  });

  it("classifies IPv4-mapped IPv6 by the embedded v4", () => {
    expect(isBlockedAddress("::ffff:127.0.0.1")).toBe(true);
    expect(isBlockedAddress("::ffff:10.0.0.1")).toBe(true);
    expect(isBlockedAddress("::ffff:8.8.8.8")).toBe(false);
  });

  it("fails closed on unparseable input", () => {
    expect(isBlockedAddress("999.1.1.1")).toBe(true);
    expect(isBlockedAddress("garbage")).toBe(true);
    expect(isBlockedAddress("not:an:ip")).toBe(true);
  });
});
