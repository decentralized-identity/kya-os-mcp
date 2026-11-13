/**
 * The private-network rule: which URLs it refuses, as the URL parser writes their hosts and schemes,
 * and how a transport under it opts out. Redirect handling has its own tests
 * (`checked-redirects.test.ts`, and through `RuntimeFetchProvider`).
 */

import { describe, expect, it, vi } from 'vitest';
import { privateNetworkRefusal, underPrivateNetworkRule } from '../private-network-rule.js';
import { LOCAL_HOST_NAMES, PUBLIC_NAME_FOR_LOOPBACK } from '../../__tests__/utils/local-host-names.js';

/** Whether the rule, without the opt-out, refuses `url`. */
const refuses = (url: string) => privateNetworkRefusal(url) !== undefined;

describe('privateNetworkRefusal', () => {
  it('refuses a non-public IP literal in any form the URL parser accepts', () => {
    const refused = [
      'https://127.0.0.1/', 'https://127.1/', 'https://2130706433/', 'https://0x7f000001/', 'https://127.0.0.1./',
      'https://10.0.0.5/', 'https://172.16.0.1/', 'https://192.168.1.1/', 'https://169.254.169.254/', 'https://0.0.0.0/',
      'https://100.64.0.1/', 'https://[::1]/', 'https://[0:0:0:0:0:0:0:1]/', 'https://[::]/', 'https://[fe80::1]/',
      'https://[fd00::1]/', 'https://[::ffff:127.0.0.1]/', 'https://[::ffff:a9fe:a9fe]/', 'https://[64:ff9b::a9fe:a9fe]/',
      'https://[::ffff:0:7f00:1]/', 'https://[::ffff:0:127.0.0.1]/', 'https://[::ffff:0:a9fe:a9fe]/',
    ];
    expect(refused.filter(url => !refuses(url))).toEqual([]);
  });

  it('refuses an IP literal with any trailing dots, which the URL parser keeps as a name after the first', () => {
    // The parser reads `127.0.0.1.` as an IPv4 address, but keeps `127.0.0.1..` as written.
    const refused = ['https://127.0.0.1../', 'https://10.0.0.1.../', 'https://169.254.169.254..:8443/', 'https://0x7f.1../',
      'https://0177.0.0.1../', 'https://2130706433../', 'https://1.2.3.4.5../'];
    expect(refused.filter(url => !refuses(url))).toEqual([]);
    expect(['https://8.8.8.8../', 'https://example.com../'].filter(refuses)).toEqual([]);
  });

  it('refuses localhost and any name under it, in any case, with or without a trailing dot (RFC 6761 §6.3)', () => {
    const refused = ['https://localhost/', 'https://LOCALHOST:8443/', 'https://localhost./', 'https://localhost../', 'https://api.localhost/',
      'https://a.b.LocalHost./', 'http://local%68ost/', 'https://\uff4c\uff4f\uff43\uff41\uff4c\uff48\uff4f\uff53\uff54/'];
    expect(refused.filter(url => !refuses(url))).toEqual([]);
  });

  it('refuses a single label, and a name under localdomain, localdomain6, local, internal or home.arpa, in any case and with any trailing dots', () => {
    const refused = [
      ...LOCAL_HOST_NAMES.map(name => `https://${name}/`), 'https://METADATA./', 'https://Printer.LOCAL../',
      'https://instance-data.ec2.internal.:8443/', 'https://home.arpa/', 'https://localdomain/', 'https://internal./',
      'https://LOCALHOST6.LOCALDOMAIN6../', 'https://localdomain6/',
    ];
    expect(refused.filter(url => !refuses(url))).toEqual([]);
  });

  it('refuses a URL that does not parse, which a runtime might resolve against a base of its own', () => {
    for (const url of ['//127.0.0.1/did.json', '/did.json', 'not a url']) expect(privateNetworkRefusal(url, true)).toBe('a URL that does not parse');
  });

  it('admits any other name, whatever it resolves to, and a public IP literal', () => {
    const admitted = ['https://example.com/', 'https://localhost.example/', 'https://localhost.example./', 'https://notlocalhost.example/',
      'https://localhostx.example/', 'https://10.0.0.5.example/', 'https://did.test/', 'https://did.invalid./', 'https://local.example/',
      'https://internal.example/', 'https://home.arpa.example/', 'https://printer.local.example/', 'https://nothome.arpa/', 'https://api.glocal/',
      'https://localdomain6.example/', 'https://api.notlocaldomain6/',
      'https://8.8.8.8/', 'https://172.32.0.1/', 'https://[2606:4700:4700::1111]/', 'https://[::ffff:0:808:808]/'];
    expect(admitted.filter(refuses)).toEqual([]);
  });

  it('admits a public name whose address is a loopback address, which the runtime learns only when it connects', () => {
    // The rule resolves no name: an egress control, not this rule, keeps such a name from a private address.
    expect(privateNetworkRefusal(`https://${PUBLIC_NAME_FOR_LOOPBACK}/`)).toBeUndefined();
  });
});

describe('underPrivateNetworkRule', () => {
  const answering = () => vi.fn(async (_url: string, _init?: unknown) => new Response('{}'));

  it('refuses a private host before any request, quoting it, and asks for every redirect by hand', async () => {
    const fetch = answering();
    await expect(underPrivateNetworkRule({ fetch }).fetch('https://10.0.0.5/list')).rejects.toThrow('Request to "10.0.0.5" refused');
    await expect(underPrivateNetworkRule({ fetch }).fetch('https://api.localhost:8443/list')).rejects.toThrow('Request to "api.localhost:8443" refused');
    await expect(underPrivateNetworkRule({ fetch }).fetch('//10.0.0.5/list')).rejects.toThrow('Request to a URL that does not parse refused');
    expect(fetch).not.toHaveBeenCalled();
    await underPrivateNetworkRule({ fetch }).fetch('https://example.com/list', { headers: { Accept: 'application/json' } });
    expect(fetch).toHaveBeenCalledWith('https://example.com/list', { headers: { Accept: 'application/json' }, redirect: 'manual' });
  });

  it('admits a private host, local names included, only for a transport whose allowPrivateNetworkHosts is true', async () => {
    for (const [allowPrivateNetworkHosts, admitted] of [[true, true], [1, false], ['true', false], [false, false]] as const) {
      const fetch = answering();
      const transport = { fetch, allowPrivateNetworkHosts } as unknown as Parameters<typeof underPrivateNetworkRule>[0];
      const hosts = [['https://127.0.0.1/did.json', '127.0.0.1'], ['http://localhost:8080/did.json', 'localhost:8080'],
        ['https://metadata.google.internal/did.json', 'metadata.google.internal']] as const;
      for (const [url, host] of hosts) {
        const reading = underPrivateNetworkRule(transport).fetch(url);
        if (admitted) await expect(reading).resolves.toBeInstanceOf(Response);
        else await expect(reading).rejects.toThrow(`Request to "${host}" refused`);
      }
      expect(fetch).toHaveBeenCalledTimes(admitted ? 3 : 0);
    }
  });

  it('refuses a scheme other than http and https before any request, whether or not the transport opts out', async () => {
    for (const allowPrivateNetworkHosts of [false, true]) {
      const fetch = answering();
      const rule = underPrivateNetworkRule({ fetch, allowPrivateNetworkHosts });
      const schemes = [['data:application/json,{}', 'data:'], ['file:///etc/passwd', 'file:'], ['ftp://example.com/list', 'ftp:']] as const;
      for (const [url, scheme] of schemes) await expect(rule.fetch(url)).rejects.toThrow(`Request to a "${scheme}" URL refused`);
      expect(fetch).not.toHaveBeenCalled();
    }
  });
});
