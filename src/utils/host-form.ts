/**
 * A URL's host as a resolver reads it, before any lookup: the IP literal it is, or the name it is
 * without the trailing dots a resolver ignores. The private-network rule (`./private-network-rule`)
 * and SafeFetch (`./safe-fetch`) refuse a host by this form alone, before any request or DNS lookup,
 * where no resolver's answer could make it public.
 */

import { isBlockedAddress } from './ip-classifier.js';

/** An IPv4 host as the URL parser writes one, whatever form the URL gave it in. */
const IPV4_HOST = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/** A host read before any lookup: the address of an IP literal, or a name without trailing dots. */
export type HostForm = { readonly literal: string } | { readonly name: string };

/**
 * `hostname`, as the URL parser writes it (lowercase, IDNA-mapped, percent-decoded, an IPv6 literal
 * in brackets), read before any lookup, or `undefined` when it does not parse once its trailing dots
 * are removed, as `1.2.3.4.5` does not. The parser keeps `127.0.0.1..` as a name, though a resolver
 * reads it as the address `127.0.0.1`, so the dots are removed and the rest parsed again.
 */
export function hostForm(hostname: string): HostForm | undefined {
  if (hostname.startsWith('[')) return { literal: hostname.slice(1, -1) };
  const host = withoutTrailingDots(hostname);
  if (host === undefined) return undefined;
  return IPV4_HOST.test(host) ? { literal: host } : { name: host };
}

/** `hostname` without its trailing dots, written as the URL parser writes a host, or `undefined` when that does not parse. */
function withoutTrailingDots(hostname: string): string | undefined {
  let end = hostname.length;
  while (hostname[end - 1] === '.') end--;
  if (end === hostname.length) return hostname;
  try {
    return new URL(`http://${hostname.slice(0, end)}/`).hostname;
  } catch {
    return undefined;
  }
}

/**
 * Whether `name`, a host name without trailing dots, is `localhost` or a name under it, which
 * RFC 6761 §6.3 has every resolver answer with the loopback address.
 */
export function isLoopbackName(name: string): boolean {
  return name === 'localhost' || name.endsWith('.localhost');
}

/**
 * Whether `hostname`, as the URL parser writes it, is non-public whatever any resolver answers: a
 * non-public IP literal, IPv4 or IPv6, classified as a resolved address is (`./ip-classifier`), or
 * a loopback name ({@link isLoopbackName}), with or without trailing dots.
 */
export function isNonPublicByForm(hostname: string): boolean {
  const form = hostForm(hostname);
  if (form === undefined) return false;
  return 'literal' in form ? isBlockedAddress(form.literal) : isLoopbackName(form.name);
}
