/**
 * A did:web DID is percent-decoded once, and its URL is read as the URL parser and the server read
 * it, which percent-decode again. A host or path segment that still holds a `%` after the one decode
 * would be decoded a second time there, so `%252E%252E` would become a dot-segment and
 * `example%252Ecom` the host `example.com`, and two DIDs would name one document. Such a DID names
 * no URL, and the resolver refuses it before any request.
 */

import { describe, expect, it, vi } from 'vitest';
import { createDidWebResolver, didWebToUrl, parseDidWeb } from '../did-web-resolver.js';
import type { FetchProvider } from '../../providers/base.js';
import type { DIDDocument } from '../vc-verifier.js';

/** A provider that serves `documents` by the path the URL parser reads from each URL it is asked for. */
function servingByPath(documents: Record<string, DIDDocument>): FetchProvider & { fetch: ReturnType<typeof vi.fn> } {
  return {
    resolveDID: vi.fn(),
    fetchStatusList: vi.fn(),
    fetchDelegationChain: vi.fn(),
    fetch: vi.fn(async (url: string) => {
      const document = documents[new URL(url).pathname];
      return document ? new Response(JSON.stringify(document)) : new Response('', { status: 404 });
    }),
  };
}

describe('a did:web DID decoded once', () => {
  it.each([
    ['a double-encoded dot-segment', 'did:web:example.com:bob:%252E%252E:alice'],
    ['a double-encoded single dot', 'did:web:example.com:bob:%252E:alice'],
    ['a double-encoded half dot-segment', 'did:web:example.com:bob:.%252e:alice'],
    ['a double-encoded slash', 'did:web:example.com:bob%252F..%252Falice'],
    ['a double-encoded percent sign', 'did:web:example.com:alice%2525'],
    ['a double-encoded host', 'did:web:example%252Ecom'],
    ['a double-encoded port separator', 'did:web:example.com%253A8443'],
  ])('names no URL with %s', (_name, did) => {
    expect(didWebToUrl(did)).toBeNull();
    expect(parseDidWeb(did)).toBeNull();
  });

  // The URL parser removes every tab, line feed and carriage return from a URL before it reads
  // it, so `.<TAB>.` would be read there as a dot-segment and a tab alone as an empty segment.
  it.each([
    ['a dot-segment split by a tab', 'did:web:example.com:bob:%2E%09%2E:alice'],
    ['a dot-segment split by a line feed', 'did:web:example.com:bob:.%0A.:alice'],
    ['a dot-segment split by a carriage return', 'did:web:example.com:bob:.%0D.:alice'],
    ['a single dot and a line feed', 'did:web:example.com:bob:.%0A'],
    ['a tab alone', 'did:web:example.com:bob:%09'],
    ['another control character', 'did:web:example.com:bob:a%00b'],
    ['a space', 'did:web:example.com:bob:a%20b'],
    ['a no-break space', 'did:web:example.com:bob:a%C2%A0b'],
  ])('names no URL with a path segment that holds %s', (_name, did) => {
    expect(didWebToUrl(did)).toBeNull();
    expect(parseDidWeb(did)).toBeNull();
  });

  it("does not resolve a DID that names bob's path from a document alice serves, through a tab", async () => {
    const did = 'did:web:example.com:bob:%2E%09%2E:alice';
    const provider = servingByPath({ '/alice/did.json': { id: did, verificationMethod: [] } });
    expect(await createDidWebResolver(provider).resolve(did)).toBeNull();
    expect(provider.fetch).not.toHaveBeenCalled();
  });

  it('still decodes what a DID encodes once: a port, an IP literal, a name and a segment', () => {
    expect(didWebToUrl('did:web:example.com%3A8443:users:alice')).toBe('https://example.com:8443/users/alice/did.json');
    expect(didWebToUrl('did:web:%5B%3A%3A1%5D')).toBe('https://[::1]/.well-known/did.json');
    expect(didWebToUrl('did:web:m%C3%BCnchen.example')).toBe('https://münchen.example/.well-known/did.json');
    expect(didWebToUrl('did:web:example.com:caf%C3%A9')).toBe('https://example.com/café/did.json');
  });

  it("does not resolve a DID that names bob's path from a document alice serves", async () => {
    const did = 'did:web:example.com:bob:%252E%252E:alice';
    const provider = servingByPath({ '/alice/did.json': { id: did, verificationMethod: [] } });
    expect(await createDidWebResolver(provider).resolve(did)).toBeNull();
    expect(provider.fetch).not.toHaveBeenCalled();
  });
});
