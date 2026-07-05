/**
 * SSRF address policy — classify a resolved IP as public unicast or not.
 *
 * Pure, I/O-free RFC classification extracted from `./safe-fetch` so the "which addresses may we
 * connect to" decision is one cohesive, independently-testable unit. Every predicate FAILS CLOSED:
 * an unparseable literal classifies as blocked. IPv6 is classified by its 16 canonical bytes (not
 * its textual form), and every IPv4-bearing transition range (v4-mapped, NAT64, 6to4, v4-compatible)
 * folds down to its embedded v4 so a private tail cannot slip through a v6 wrapper.
 */

/** True if an IPv4 dotted-quad is NOT a public unicast address (fail-closed on parse error). */
function isBlockedIpv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return true;
  const octets = parts.map((part) => Number(part));
  if (octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return true;
  const [a, b, c] = octets;
  if (a === undefined || b === undefined || c === undefined) return true;
  if (a === 0 || a === 10 || a === 127) return true; // this-host, RFC1918 10/8, loopback 127/8
  if (a === 169 && b === 254) return true; // link-local 169.254/16 (incl. 169.254.169.254)
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918 172.16/12
  if (a === 192 && b === 168) return true; // RFC1918 192.168/16
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  if (a === 192 && b === 0 && c === 0) return true; // IETF protocol assignments 192.0.0/24
  if (a === 192 && b === 0 && c === 2) return true; // RFC 5737 TEST-NET-1 192.0.2/24 (documentation)
  if (a === 198 && b === 51 && c === 100) return true; // RFC 5737 TEST-NET-2 198.51.100/24 (documentation)
  if (a === 203 && b === 0 && c === 113) return true; // RFC 5737 TEST-NET-3 203.0.113/24 (documentation)
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking 198.18/15
  if (a >= 224) return true; // multicast 224/4, reserved 240/4, broadcast 255.255.255.255
  return false;
}

/**
 * Parse an IPv6 literal into its 16 bytes, or `null` when it is not well-formed. Expands `::`
 * and folds an embedded IPv4 tail, so classification never depends on the TEXTUAL form — `::1`,
 * `0:0:0:0:0:0:0:1`, and `0000:...:0001` all resolve to the same bytes (closing the string-match
 * bypass where an expanded loopback slipped through).
 */
function ipv6ToBytes(ip: string): Uint8Array | null {
  let text = ip.toLowerCase().split('%')[0] ?? ''; // drop any zone id
  // Fold a trailing dotted-quad (::ffff:1.2.3.4, ::1.2.3.4) into two hextets.
  const v4 = text.match(/:(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const o = [v4[1], v4[2], v4[3], v4[4]].map(Number);
    if (o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    const hi = (((o[0] ?? 0) << 8) | (o[1] ?? 0)).toString(16);
    const lo = (((o[2] ?? 0) << 8) | (o[3] ?? 0)).toString(16);
    text = `${text.slice(0, v4.index)}:${hi}:${lo}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return null; // more than one "::" is illegal
  const parse = (part: string): number[] | null => {
    if (part === '') return [];
    const out: number[] = [];
    for (const h of part.split(':')) {
      if (!/^[0-9a-f]{1,4}$/.test(h)) return null;
      out.push(parseInt(h, 16));
    }
    return out;
  };
  const head = parse(halves[0] ?? '');
  const tail = halves.length === 2 ? parse(halves[1] ?? '') : [];
  if (head === null || tail === null) return null;
  let hextets: number[];
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null; // "::" must stand in for at least one zero group
    hextets = [...head, ...Array<number>(fill).fill(0), ...tail];
  } else {
    hextets = head;
  }
  if (hextets.length !== 8) return null;
  const bytes = new Uint8Array(16);
  hextets.forEach((h, i) => {
    bytes[i * 2] = (h >> 8) & 0xff;
    bytes[i * 2 + 1] = h & 0xff;
  });
  return bytes;
}

/** True if an IPv6 literal is NOT a public unicast address (fail-closed on parse error). */
function isBlockedIpv6(ip: string): boolean {
  const b = ipv6ToBytes(ip);
  if (b === null) return true; // unparseable → fail-closed
  const embeddedV4 = (): boolean => isBlockedIpv4(`${b[12]}.${b[13]}.${b[14]}.${b[15]}`);
  // IPv4-mapped ::ffff:a.b.c.d — classify by the embedded v4 (loopback, RFC1918, metadata, …).
  if (b.subarray(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff) return embeddedV4();
  if (b.every((x) => x === 0)) return true; // :: unspecified
  if (b.subarray(0, 15).every((x) => x === 0) && b[15] === 1) return true; // ::1 loopback (any form)
  if (b[0] === 0xfe && (b[1]! & 0xc0) === 0x80) return true; // fe80::/10 link-local
  if ((b[0]! & 0xfe) === 0xfc) return true; // fc00::/7 ULA (fc00::/8 + fd00::/8)
  if (b[0] === 0xff) return true; // ff00::/8 multicast
  if (b[0] === 0xfe && (b[1]! & 0xc0) === 0xc0) return true; // fec0::/10 deprecated site-local
  // NAT64 well-known prefix 64:ff9b::/96 — the tail IS an IPv4 address the gateway routes to, so a
  // 64:ff9b::10.0.0.1 / 64:ff9b::a9fe:a9fe would reach RFC1918 / the metadata endpoint. Classify it.
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && b.subarray(4, 12).every((x) => x === 0)) {
    return embeddedV4();
  }
  // NAT64 LOCAL-USE prefix 64:ff9b:1::/48 (RFC 8215): operators derive /96 translation prefixes from
  // it, so the routed IPv4 sits in the low 32 bits — classify that (the /96 clause above matched only
  // the well-known prefix). A non-/96 embedding leaves bytes 12-15 zero → 0.0.0.0 → blocked (fail-closed).
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && b[4] === 0x00 && b[5] === 0x01) {
    return embeddedV4();
  }
  // 6to4 2002::/16 — bytes 2-5 embed the IPv4 of the 6to4 relay/host; classify that v4.
  if (b[0] === 0x20 && b[1] === 0x02) return isBlockedIpv4(`${b[2]}.${b[3]}.${b[4]}.${b[5]}`);
  // Teredo 2001:0000::/32 — the client IPv4 is obfuscated in the tail; block conservatively.
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && b[3] === 0x00) return true;
  // IPv4-compatible ::a.b.c.d (deprecated, non-routable) — classify the embedded v4, fail-closed.
  if (b.subarray(0, 12).every((x) => x === 0)) return embeddedV4();
  // 2001:db8::/32 — RFC 3849 documentation range (not public unicast, per the module contract).
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return true;
  // 100::/64 — RFC 6666 discard-only prefix (a routing black hole, never a real service).
  if (b[0] === 0x01 && b[1] === 0x00 && b.subarray(2, 8).every((x) => x === 0)) return true;
  return false; // global unicast
}

/** True if an address must NOT be connected to (classified by shape, not by trusting `family`). */
export function isBlockedAddress(address: string): boolean {
  return address.includes(':') ? isBlockedIpv6(address) : isBlockedIpv4(address);
}
