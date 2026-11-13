/**
 * Which request headers a redirect to another origin keeps (`../cors-safelisted-headers`): the
 * names and values the Fetch standard safelists, and the request's cache directives, which carry
 * no credential, and nothing else.
 */

import { describe, expect, it } from 'vitest';
import { corsSafelistedHeaders, crossOriginRequestHeaders } from '../cors-safelisted-headers.js';

const kept = (headers: Record<string, string>) => Object.fromEntries(corsSafelistedHeaders(headers));

describe('corsSafelistedHeaders', () => {
  it('keeps Accept, Accept-Language and Content-Language with safelisted values, and drops every other name', () => {
    expect(kept({
      Accept: 'application/did+ld+json;q=1,\tapplication/json', 'Accept-Language': 'en-US,en;q=0.9', 'Content-Language': 'de-DE, *',
      Authorization: 'Bearer secret', Cookie: 'a=b', 'X-Api-Key': 'key', 'Content-Type': 'text/plain', Range: 'bytes=0-1', constructor: 'x',
    })).toEqual({ accept: 'application/did+ld+json;q=1,\tapplication/json', 'accept-language': 'en-US,en;q=0.9', 'content-language': 'de-DE, *' });
  });

  it('keeps a value of 128 bytes, and drops one of 129', () => {
    for (const name of ['Accept', 'Accept-Language', 'Content-Language']) {
      expect(kept({ [name]: 'a'.repeat(128) })).toEqual({ [name.toLowerCase()]: 'a'.repeat(128) });
      expect(kept({ [name]: 'a'.repeat(129) })).toEqual({});
    }
  });

  it('drops an Accept value with a CORS-unsafe byte', () => {
    for (const unsafe of ['"', '(', ')', ':', '<', '>', '?', '@', '[', '\\', ']', '{', '}', '\x01', '\x1f', '\x7f']) {
      expect(kept({ Accept: `text/${unsafe}plain` })).toEqual({});
    }
  });

  it('drops a language value with a byte outside the safelisted set', () => {
    for (const value of ['de/x', 'en_US', 'fr\tCA', 'é']) {
      expect([kept({ 'Accept-Language': value }), kept({ 'Content-Language': value })]).toEqual([{}, {}]);
    }
  });
});

describe('crossOriginRequestHeaders', () => {
  it('keeps the CORS-safelisted headers, and Cache-Control and Pragma whatever their values, and drops every other name', () => {
    const headers = {
      Accept: 'application/json', 'Content-Language': 'de/x', 'Cache-Control': 'no-cache, max-age=0', PRAGMA: 'no-cache',
      Authorization: 'Bearer secret', Cookie: 'a=b', 'Proxy-Authorization': 'Basic x', 'X-Api-Key': 'key',
    };
    expect(Object.fromEntries(crossOriginRequestHeaders(headers))).toEqual({
      accept: 'application/json', 'cache-control': 'no-cache, max-age=0', pragma: 'no-cache',
    });
    expect(Object.fromEntries(crossOriginRequestHeaders(undefined))).toEqual({});
  });
});
