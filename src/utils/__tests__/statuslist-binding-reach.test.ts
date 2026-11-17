/**
 * A `statusListIssuers` binding no redirect reaches. SPEC.md §6.6 reads a binding on the bytes as
 * written, so `https://lists.internal:443/list` binds the status entries that name it so, and both
 * readers take it, as the conformance harness does. A redirect is matched as the URL parser writes
 * the URL it resolves to, though, which drops the `:443`, so no redirect reaches that binding. Each
 * reader says so once, when it is configured, naming the form a redirect reaches, and refuses
 * nothing. A binding that includes credentials, or does not parse, is one no read reaches at all.
 */

import { describe, expect, it, vi } from 'vitest';

const K = 'did:web:k.example';
const HOLDS = (binding: string) => `[kya-os] statusListIssuers["${K}"] holds "${binding}"`;
const REDIRECTS = (binding: string, canonical: string, hint = true) =>
  `${HOLDS(binding)}, which a status entry reaches as written but a redirect never does, since a redirect is matched as ` +
  `the URL parser writes it, "${canonical}"${hint ? ': bind that as well for a redirect to reach it.' : '.'}`;

/** A fresh copy of the package, so what it has said once is said again, and every line it warns. */
async function fresh() {
  vi.resetModules();
  const pkg = await import('../../index.js');
  const { createRevocationChecker } = await import('../../card/index.js');
  const warn = vi.spyOn(pkg.logger, 'warn').mockImplementation(() => undefined);
  return { ...pkg, createRevocationChecker, said: () => warn.mock.calls.map((call) => call.map(String).join(' ')) };
}

const UNREACHED = {
  [K]: [
    'https://lists.internal:443/list',
    'https://lists.internal:443',
    'https://Lists.Internal/list',
    'https://lists.internal/herd/./1',
    'https://lists.internal/herd/.',
    'https://user:secret@lists.internal/list',
    'https://lists.internal:99999/list',
  ],
};
const SAID = [
  REDIRECTS('https://lists.internal:443/list', 'https://lists.internal/list'),
  REDIRECTS('https://lists.internal:443', 'https://lists.internal'),
  REDIRECTS('https://Lists.Internal/list', 'https://lists.internal/list'),
  REDIRECTS('https://lists.internal/herd/./1', 'https://lists.internal/herd/1'),
  REDIRECTS('https://lists.internal/herd/.', 'https://lists.internal/herd/', false),
  `${HOLDS('https://user:secret@lists.internal/list')}, a URL that includes credentials, which every reader refuses before any request, so no read reaches it.`,
  `${HOLDS('https://lists.internal:99999/list')}, which does not parse as a URL, so no read reaches it.`,
];

describe('a statusListIssuers binding no redirect reaches', () => {
  it('is taken by RuntimeFetchProvider, which says once of each which form a redirect reaches', async () => {
    const { RuntimeFetchProvider, said } = await fresh();
    new RuntimeFetchProvider({ statusListIssuers: UNREACHED });
    new RuntimeFetchProvider({ statusListIssuers: UNREACHED });
    expect(said()).toEqual(SAID);
  });

  it('is taken by createRevocationChecker, which says the same once', async () => {
    const { createRevocationChecker, said } = await fresh();
    const checker = () => createRevocationChecker({ fetch: async () => ({ ok: false, status: 404, json: async () => null }), statusListIssuers: UNREACHED, verifyStatusList: async () => ({ verified: true }) as never });
    checker();
    checker();
    expect(said()).toEqual(SAID);
  });

  it('says nothing of a binding a redirect reaches as written, or of an http one, which no redirect reaches by design', async () => {
    const { RuntimeFetchProvider, said } = await fresh();
    new RuntimeFetchProvider({
      statusListIssuers: { [K]: ['https://lists.internal/list', 'https://lists.internal:8443', 'https://lists.internal/list?shard=1', 'http://Lists.Internal:80/list'] },
    });
    expect(said()).toEqual([]);
  });
});
