/**
 * A host may publish several public addresses, one of them unreachable: a dead CDN node, or an AAAA
 * record on a host whose IPv6 egress is broken. The runtime's `fetch` tried the next address. A
 * pinned connection must too, so it is handed every address the host resolved to, each checked, and
 * tries them in turn, as Node's own address fallback does: a host that answers on its second
 * address is read, and an address that was not checked is never tried.
 *
 * A real https server on 127.0.0.1 answers under a public name. The lookup answers two public
 * addresses, IPv6 first. The connection maps the IPv6 one to `::1`, where nothing listens, and the
 * IPv4 one to `127.0.0.1`, where the server does.
 */

import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import https from 'node:https';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { logger, RuntimeFetchProvider } from '../../index.js';
import { createSafeFetch, nodeHttpsTransport, type DnsAddress, type DnsLookup, type SafeFetchTransport, type TransportInit } from '../../utils/safe-fetch.js';
import { closeLoopback, listenOnLoopback } from '../utils/loopback-server.js';
import { selfSignedTls } from '../utils/self-signed-tls.js';

const HOST = 'lists.example';
const V6 = { address: '2606:2800:220:1:248:1893:25c8:1946', family: 6 } as const;
const V4 = { address: '93.184.216.34', family: 4 } as const;
/** Where each public address reaches on this machine. */
const REACHES: Record<string, string> = { [V6.address]: '::1', [V4.address]: '127.0.0.1' };
const LIST = {
  id: 'list', type: ['VerifiableCredential', 'StatusList2021Credential'],
  credentialSubject: { type: 'StatusList2021', encodedList: 'H4sIAAAAAAAA' },
};

const tls = selfSignedTls(HOST);
const trusted = https.globalAgent.options.ca;
let server: https.Server;
let port: number;

beforeAll(async () => {
  server = https.createServer(tls, (_request: IncomingMessage, response: ServerResponse) => {
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(LIST));
  });
  https.globalAgent.options.ca = [tls.cert];
  port = await listenOnLoopback(server as unknown as Server);
});

afterAll(async () => {
  https.globalAgent.options.ca = trusted;
  await closeLoopback(server as unknown as Server);
});

const lookup: DnsLookup = async () => [V6, V4];

/** Every request the transport was handed: the address it pins first, and the ones it may try after. */
function recording() {
  const handed: [string, readonly string[]][] = [];
  const reach = ({ address, family }: DnsAddress): DnsAddress => ({ address: REACHES[address] ?? address, family });
  const transport: SafeFetchTransport = (url, init: TransportInit) => {
    handed.push([init.pinnedAddress, (init.fallbackAddresses ?? []).map(({ address }) => address)]);
    const first = reach({ address: init.pinnedAddress, family: init.family });
    return nodeHttpsTransport(url, {
      ...init,
      pinnedAddress: first.address,
      fallbackAddresses: (init.fallbackAddresses ?? []).map(reach),
    });
  };
  return { transport, handed };
}

describe('a host with two public addresses, the first unreachable', () => {
  it('is read through the provider, on its second address', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const { transport, handed } = recording();
    expect(await new RuntimeFetchProvider({ lookup, transport }).fetchStatusList(`https://${HOST}:${port}/list`)).toEqual(LIST);
    expect(handed).toEqual([[V6.address, [V4.address]]]);
  });

  it('is read through SafeFetch, on its second address', async () => {
    const { transport, handed } = recording();
    expect(await (await createSafeFetch({ lookup, transport })(`https://${HOST}:${port}/list`)).json()).toEqual(LIST);
    expect(handed).toEqual([[V6.address, [V4.address]]]);
  });

  it('is still refused whole when any address it resolves to is not public', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const { transport, handed } = recording();
    const split: DnsLookup = async () => [V4, { address: '10.0.0.7', family: 4 }];
    expect(await new RuntimeFetchProvider({ lookup: split, transport }).fetchStatusList(`https://${HOST}:${port}/list`)).toBeNull();
    expect(handed).toEqual([]);
  });
});
