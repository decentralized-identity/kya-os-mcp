/**
 * How the status-list readers read a response: through the one bounded reader, so a status list
 * named by a credential costs at most 1 MiB of body and 5,000 ms, headers and body together, and a
 * non-2xx response is refused whatever its body says; and under the private-network rule, whatever
 * provider the resolver is given.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { CheqdStatusListResolver } from '../../integrations/cheqd/statuslist-resolver.js';
import { RuntimeFetchProvider } from '../../providers/runtime-fetch.js';
import { statusListGzipCodec } from '../../utils/statuslist-gzip.js';
import type { CryptoProvider, FetchProvider } from '../../providers/base.js';
import type { CredentialStatus } from '../../types/protocol.js';
import { LOCAL_HOST_NAMES } from '../../__tests__/utils/local-host-names.js';

/** The status-list limits SPEC §4.4.2 states. */
const CAP = 1_048_576;
const STATUS_LIST_TIMEOUT_MS = 5_000;
const LIST = 'https://status.example/list';
const entry: CredentialStatus = {
  id: `${LIST}#0`, type: 'StatusList2021Entry', statusPurpose: 'revocation', statusListIndex: '0', statusListCredential: LIST,
};
const list = JSON.stringify({
  '@context': ['https://www.w3.org/2018/credentials/v1'], id: LIST, type: ['VerifiableCredential', 'StatusList2021Credential'],
  issuer: 'did:web:issuer.example', issuanceDate: '2026-01-01T00:00:00Z',
  credentialSubject: { type: 'StatusList2021', statusPurpose: 'revocation', encodedList: 'H4sIAAAAAAAA' },
});
/** `list` padded with trailing whitespace to exactly `bytes` bytes: still valid JSON. */
const padded = (bytes: number) => list + ' '.repeat(bytes - list.length);

/** A body that sends nothing and never ends, with a spy on its cancellation. */
function stalled() {
  const cancel = vi.fn();
  return { cancel, response: new Response(new ReadableStream<Uint8Array>({ cancel })) };
}

const cheqd = (fetch: FetchProvider['fetch'], members: object = {}) => new CheqdStatusListResolver({
  fetchProvider: { fetch, ...members } as FetchProvider,
  didResolver: { resolve: async () => null },
  cryptoProvider: {} as CryptoProvider,
  expectedIssuerDid: 'did:web:issuer.example',
  decompressor: statusListGzipCodec,
  cacheTtlMs: 0,
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('CheqdStatusListResolver reads a list through the bounded reader', () => {
  it('reads a body of exactly the cap and refuses one byte more before parsing it', async () => {
    await expect(cheqd(async () => new Response(padded(CAP))).checkStatus(entry)).rejects.toThrow('Status list credential is unsigned');
    const parse = vi.spyOn(JSON, 'parse');
    try {
      await expect(cheqd(async () => new Response(padded(CAP + 1))).checkStatus(entry))
        .rejects.toThrow('Status list fetch byte limit exceeded');
      expect(parse).not.toHaveBeenCalled();
    } finally { parse.mockRestore(); }
  });

  it('waits 5,000 ms for a stalled body, and no longer, and cancels it', async () => {
    vi.useFakeTimers();
    const { cancel, response } = stalled();
    let outcome: string | undefined;
    const settled = cheqd(async () => response).checkStatus(entry).then(
      () => 'resolved', (error: Error) => error.message,
    ).then(value => { outcome = value; });
    await vi.advanceTimersByTimeAsync(STATUS_LIST_TIMEOUT_MS - 1);
    expect(outcome).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    expect(outcome).toBe('Status list fetch deadline exceeded');
    await settled;
    expect(cancel).toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('reports the deadline, not an AbortError, in a runtime whose abort signal carries no reason', async () => {
    vi.stubGlobal('AbortController', class extends AbortController {
      override abort(): void { super.abort(); }
    });
    vi.useFakeTimers();
    let outcome: string | undefined;
    const settled = cheqd(async () => stalled().response).checkStatus(entry).then(
      () => 'resolved', (error: Error) => error.message,
    ).then(value => { outcome = value; });
    await vi.advanceTimersByTimeAsync(STATUS_LIST_TIMEOUT_MS);
    expect(outcome).toBe('Status list fetch deadline exceeded');
    await settled;
  });

  it('refuses a non-2xx response even when its body is a valid list', async () => {
    await expect(cheqd(async () => new Response(list, { status: 500 })).checkStatus(entry))
      .rejects.toThrow(`Status list fetch failed: HTTP 500 for "${LIST}"`);
  });

  it('cancels a refused body and aborts its request, for a provider that frees its connection either way', async () => {
    const signals: AbortSignal[] = [];
    const answering = (response: () => Response) => async (_url: string, init?: RequestInit) => {
      signals.push(init!.signal!);
      return response();
    };
    const cancel = vi.fn();
    const failed = () => new Response(new ReadableStream<Uint8Array>({ cancel }), { status: 500 });
    await expect(cheqd(answering(failed)).checkStatus(entry)).rejects.toThrow('HTTP 500');
    expect(cancel).toHaveBeenCalledOnce();
    await expect(cheqd(answering(() => new Response(padded(CAP + 1)))).checkStatus(entry)).rejects.toThrow('byte limit');
    expect(signals.map(signal => signal.aborted)).toEqual([true, true]);
  });

  it('refuses a 2xx response that has no body, with its own reason', async () => {
    await expect(cheqd(async () => new Response(null)).checkStatus(entry)).rejects.toThrow('Status list fetch has no response body');
  });

  it('refuses invalid UTF-8 inside a JSON string', async () => {
    const bytes = new TextEncoder().encode(list.replace('H4sIAAAAAAAA', 'H4sIé'));
    const invalid = bytes.map(byte => byte === 0xa9 ? 0x29 : byte);
    await expect(cheqd(async () => new Response(invalid)).checkStatus(entry)).rejects.toThrow('not valid UTF-8');
  });
});

describe('CheqdStatusListResolver reads a list under the private-network rule, whatever its provider', () => {
  const at = (statusListCredential: string): CredentialStatus => ({ ...entry, statusListCredential });

  it("refuses a private IP-literal or local host name without a request, and honours the provider's allowPrivateNetworkHosts", async () => {
    const local = LOCAL_HOST_NAMES.map(name => `https://${name}/list`);
    for (const url of ['https://10.0.0.1/list', 'https://[::ffff:a9fe:a9fe]/latest', 'https://localhost/list', 'https://status.localhost./list', ...local]) {
      const fetch = vi.fn(async () => new Response(list));
      await expect(cheqd(fetch).checkStatus(at(url))).rejects.toThrow(`Request to "${new URL(url).host}" refused`);
      expect(fetch).not.toHaveBeenCalled();
    }
    const fetch = vi.fn(async () => new Response(list));
    await expect(cheqd(fetch, { allowPrivateNetworkHosts: true }).checkStatus(at('https://10.0.0.1/list')))
      .rejects.toThrow('Status list credential is unsigned');
    expect(fetch).toHaveBeenCalledOnce();
  });

  it('follows a redirect by hand, and refuses one to a private host or a local name without requesting it', async () => {
    const local = LOCAL_HOST_NAMES.map((name): [string, string] => [`https://${name}:8443/list`, `${name}:8443`]);
    for (const [location, host] of [['https://169.254.169.254/latest', '169.254.169.254'], ['https://localhost:8443/list', 'localhost:8443'], ...local]) {
      const fetch = vi.fn(async (_url: string, _init?: RequestInit) => new Response(null, { status: 302, headers: { location } }));
      await expect(cheqd(fetch).checkStatus(entry)).rejects.toThrow(`Redirect to "${host}" refused`);
      expect(fetch.mock.calls.map(([url, init]) => [url, init?.redirect])).toEqual([[LIST, 'manual']]);
    }
  });

  it('busts upstream caches after invalidateCache() at every origin a redirect leads to, as at the first', async () => {
    const CDN = 'https://cdn.example/list';
    const fetch = vi.fn(async (url: string, _init?: RequestInit) => url === LIST
      ? new Response(null, { status: 302, headers: { location: CDN } })
      : new Response(list));
    const resolver = cheqd(fetch);
    resolver.invalidateCache();
    await expect(resolver.checkStatus(entry)).rejects.toThrow('Status list credential is unsigned');
    const busting = { accept: 'application/json', 'cache-control': 'no-cache', pragma: 'no-cache' };
    expect(fetch.mock.calls.map(([url, init]) => [url, Object.fromEntries(new Headers(init?.headers))]))
      .toEqual([[LIST, busting], [CDN, busting]]);
  });
});

describe('RuntimeFetchProvider.fetchStatusList reads a list through the bounded reader', () => {
  it('returns a list of exactly the cap and null for one byte more, cancelling that body', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(padded(CAP))));
    expect(await new RuntimeFetchProvider().fetchStatusList(LIST)).toMatchObject({ id: LIST });
    const cancel = vi.fn();
    const over = new TextEncoder().encode(padded(CAP + 1));
    vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(over); }, cancel,
    }))));
    expect(await new RuntimeFetchProvider().fetchStatusList(LIST)).toBeNull();
    expect(cancel).toHaveBeenCalledOnce();
  });

  it('returns null for a stalled body after 5,000 ms, and no later', async () => {
    vi.useFakeTimers();
    const { cancel, response } = stalled();
    vi.stubGlobal('fetch', vi.fn(async () => response));
    let outcome: unknown = 'pending';
    const settled = new RuntimeFetchProvider().fetchStatusList(LIST).then(value => { outcome = value; });
    await vi.advanceTimersByTimeAsync(STATUS_LIST_TIMEOUT_MS - 1);
    expect(outcome).toBe('pending');
    await vi.advanceTimersByTimeAsync(1);
    expect(outcome).toBeNull();
    await settled;
    expect(cancel).toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });
});
