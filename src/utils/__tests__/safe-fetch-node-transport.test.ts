/**
 * The default transport, `nodeHttpsTransport`, against a stand-in for `node:https` that answers
 * through the callbacks and events the real module uses: what the transport asks for (a GET of
 * the URL, connected to the validated address, with the hostname as the TLS server name), the
 * response it hands back, and each way a read ends early. No TLS connection is made here.
 */

import { EventEmitter } from 'node:events';
import type { RequestOptions } from 'node:https';
import type { LookupFunction } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { RawResponse, TransportInit } from '../safe-fetch.js';

type Headers = Record<string, string | string[] | undefined>;

/** A response from the stand-in: its status line and headers, then the events the test emits. */
class StandInResponse extends EventEmitter {
  constructor(
    readonly statusCode: number | undefined,
    readonly headers: Headers,
  ) {
    super();
  }
}

/** A request to the stand-in, which answers once the transport ends it. */
class StandInRequest extends EventEmitter {
  destroyed = false;

  constructor(private readonly answer: () => void) {
    super();
  }

  end(): void {
    queueMicrotask(this.answer);
  }

  destroy(): this {
    this.destroyed = true;
    return this;
  }
}

interface Asked {
  url: string;
  options: RequestOptions;
  request: StandInRequest;
}

/** How the stand-in answers a request: with a response it then drives, or an error on the request. */
type Answer = (respond: (res: StandInResponse) => void, request: StandInRequest) => void;

/** The transport as it loads with `node:https` replaced by a stand-in that answers with `answer`. */
async function transportAnswering(answer: Answer) {
  const asked: Asked[] = [];
  const request = (url: string, options: RequestOptions, onResponse: (res: StandInResponse) => void) => {
    const req: StandInRequest = new StandInRequest(() => answer(onResponse, req));
    asked.push({ url, options, request: req });
    return req;
  };
  vi.resetModules();
  vi.doMock('node:https', () => ({ request }));
  const { nodeHttpsTransport } = await import('../safe-fetch-transports.js');
  return { asked, transport: nodeHttpsTransport };
}

/** An answer of `status` and `headers` whose body arrives as `chunks`, then ends. */
const replying =
  (status: number | undefined, headers: Headers, chunks: string[]): Answer =>
  (respond) => {
    const res = new StandInResponse(status, headers);
    respond(res);
    for (const chunk of chunks) res.emit('data', Buffer.from(chunk));
    res.emit('end');
  };

const init = (over: Partial<TransportInit> = {}): TransportInit => ({
  signal: new AbortController().signal,
  hostname: 'example.com',
  pinnedAddress: '93.184.216.34',
  family: 4,
  maxBytes: 1_048_576,
  ...over,
});

/** Where `lookup` sends a host name, asked in the shape `options` gives. */
function lookedUp(lookup: LookupFunction, options: { all?: boolean }): Promise<unknown> {
  return new Promise((resolve) => {
    (lookup as (host: string, options: object, cb: (...args: unknown[]) => void) => void)(
      'rebound.example',
      options,
      (_error, address, family) => resolve(options.all ? address : { address, family }),
    );
  });
}

afterEach(() => {
  vi.doUnmock('node:https');
  vi.resetModules();
});

describe('nodeHttpsTransport, against a stand-in for node:https', () => {
  it('asks for a GET of the URL, connected to the validated address, with the hostname as the server name', async () => {
    const { asked, transport } = await transportAnswering(replying(200, {}, []));
    const given = init();
    await transport('https://example.com/card.json', given);

    expect(asked).toHaveLength(1);
    const { url, options } = asked[0]!;
    expect(url).toBe('https://example.com/card.json');
    expect(options).toMatchObject({ method: 'GET', servername: 'example.com' });
    expect(options.signal).toBe(given.signal);
    const lookup = options.lookup as LookupFunction;
    expect(await lookedUp(lookup, {})).toEqual({ address: '93.184.216.34', family: 4 });
    expect(await lookedUp(lookup, { all: true })).toEqual([{ address: '93.184.216.34', family: 4 }]);
  });

  it('connects to a validated IPv6 address as one', async () => {
    const { asked, transport } = await transportAnswering(replying(200, {}, []));
    await transport('https://example.com/card.json', init({ pinnedAddress: '2606:2800:220:1::', family: 6 }));

    const lookup = asked[0]!.options.lookup as LookupFunction;
    expect(await lookedUp(lookup, { all: true })).toEqual([{ address: '2606:2800:220:1::', family: 6 }]);
  });

  it('hands back the status, the body in the order it came, and one value of each header', async () => {
    const headers = { 'content-type': 'application/json', 'set-cookie': ['a=1', 'b=2'], 'x-empty': [] };
    const { transport } = await transportAnswering(replying(203, headers, ['{"card":', 'true}']));
    const raw: RawResponse = await transport('https://example.com/card.json', init());

    expect(raw.status).toBe(203);
    expect(await raw.text()).toBe('{"card":true}');
    expect(raw.headers.get('Content-Type')).toBe('application/json');
    expect(raw.headers.get('set-cookie')).toBe('a=1');
    expect(raw.headers.get('x-empty')).toBeNull();
    expect(raw.headers.get('x-absent')).toBeNull();
  });

  it('sends the headers it is given, and hands back the body as the bytes that were sent', async () => {
    const sent = Buffer.from([0x7b, 0xff, 0x7d]);
    const { asked, transport } = await transportAnswering((respond) => {
      const res = new StandInResponse(200, {});
      respond(res);
      res.emit('data', sent);
      res.emit('end');
    });
    const raw = await transport('https://example.com/list', init({ headers: { accept: 'application/json' } }));

    expect(asked[0]!.options.headers).toEqual({ accept: 'application/json' });
    expect(Buffer.from((await raw.bytes!())).equals(sent)).toBe(true);
  });

  it('reads a response without a status code as status 0', async () => {
    const { transport } = await transportAnswering(replying(undefined, {}, ['ok']));
    expect((await transport('https://example.com/card.json', init())).status).toBe(0);
  });

  it('reads a body of exactly the cap, and refuses one a byte past it, ending the request', async () => {
    const atCap = await transportAnswering(replying(200, {}, ['abc', 'de']));
    expect(await (await atCap.transport('https://example.com/list', init({ maxBytes: 5 }))).text()).toBe('abcde');

    const past = await transportAnswering(replying(200, {}, ['abc', 'def']));
    await expect(past.transport('https://example.com/list', init({ maxBytes: 5 }))).rejects.toThrow(
      'safe-fetch: response body exceeds size cap 5',
    );
    expect(past.asked[0]!.request.destroyed).toBe(true);
  });

  it('rejects with the error the request raises', async () => {
    const refused = new Error('connect ECONNREFUSED 93.184.216.34:443');
    const { transport } = await transportAnswering((_respond, request) => request.emit('error', refused));
    await expect(transport('https://example.com/card.json', init())).rejects.toBe(refused);
  });

  it('rejects with the error the response raises mid-body', async () => {
    const reset = new Error('socket hang up');
    const { transport } = await transportAnswering((respond) => {
      const res = new StandInResponse(200, {});
      respond(res);
      res.emit('data', Buffer.from('par'));
      res.emit('error', reset);
    });
    await expect(transport('https://example.com/card.json', init())).rejects.toBe(reset);
  });
});
