import fs from 'node:fs';
import vm from 'node:vm';
import { describe, expect, it, vi } from 'vitest';

const scope = 'https://id.gs1.org/01/09506000134352';
const fields = {
  tool: 'place_order',
  scopes: JSON.stringify([scope]),
  agent_did: 'did:key:agent',
  session_id: 'signed-request',
};

const human = {
  accountRef: 'account-a',
  provider: 'google',
  issuer: 'https://accounts.google.com',
  displayName: 'Human A',
  identitySource: 'identity-provider',
};
type ResponseFixture = { ok: boolean; json: () => Promise<unknown> };
type BrowserOptions = {
  webauthnRequired?: boolean;
  human?: typeof human;
  fetch?: (
    url: string,
    options?: { body?: FormData | string },
  ) => Promise<ResponseFixture>;
  getCredential?: () => Promise<unknown>;
};
const response = (body: unknown, ok = true): ResponseFixture => ({
  ok,
  json: async () => body,
});

async function browser(options: boolean | BrowserOptions = false) {
  const config =
    typeof options === 'boolean' ? { webauthnRequired: options } : options;
  const listeners = new Map<string, (event: unknown) => Promise<void>>();
  const screen = {
    loading: false,
    disabled: false,
    hidden: false,
    updateComplete: Promise.resolve(),
    addEventListener: (
      name: string,
      listener: (event: unknown) => Promise<void>,
    ) => listeners.set(name, listener),
  };
  const status = { textContent: '', dataset: {} };
  const resultIcon = { textContent: '' };
  const result = { hidden: true, querySelector: () => resultIcon };
  const resultTitle = { textContent: '', focus: vi.fn() };
  const feedback = {};
  const resultFeedback = { append: vi.fn() };
  const closeWindow = vi.fn();
  const navigate = vi.fn();
  const timers: Array<() => void> = [];
  const close = { hidden: true, addEventListener: (name: string, listener: () => Promise<void>) => listeners.set(`close-${name}`, listener) };
  const check = {
    hidden: true,
    disabled: false,
    addEventListener: (
      name: string,
      listener: (event: unknown) => Promise<void>,
    ) => listeners.set(`check-${name}`, listener),
  };
  const requests: Array<{ url: string; body?: FormData | string }> = [];
  let assertions = 0;
  const bridge = {
    fields,
    webauthnRequired: config.webauthnRequired ?? false,
    needsRegistration: false,
    capabilities: [{ id: 'order', scopes: [scope] }],
    ...(config.human ? { human: config.human } : {}),
  };
  const context = vm.createContext({
    console,
    FormData,
    Set,
    JSON,
    Uint8Array,
    atob,
    btoa,
    window: { close: closeWindow, scrollTo: vi.fn(), location: { replace: navigate } },
    setTimeout: (callback: () => void) => timers.push(callback),
    customElements: { whenDefined: async () => {} },
    document: {
      querySelector: (selector: string) =>
        selector === '#return-to-demo' ? { href: 'http://localhost:4949/' }
        : selector === '#close-consent-window' ? close
        : selector === '#decision-feedback' ? feedback
        : selector === '#result-feedback' ? resultFeedback
        : selector === '#consent-ceremony' ? null
        : selector === '#consent-ui-data'
          ? { textContent: JSON.stringify(bridge) }
          : selector === 'consent-capabilities-screen'
            ? screen
            : selector === '#decision-status'
              ? status
              : selector === '#check-consent-status'
                ? check
                : selector === '#result-title'
                  ? resultTitle
                  : result,
    },
    navigator: {
      credentials: {
        get: async () => {
          assertions++;
          if (config.getCredential) return config.getCredential();
          throw new Error('Passkey cancelled');
        },
      },
    },
    fetch: async (url: string, options?: { body?: FormData | string }) => {
      requests.push({ url, body: options?.body });
      if (config.fetch) return config.fetch(url, options);
      return {
        ok: true,
        json: async () =>
          url.endsWith('/challenge')
            ? {
                nonce: 'one-use',
                intent: config.human ? { human: config.human } : {},
                options: {
                  challenge: 'aGVsbG8',
                  allowCredentials: [{ id: 'a2V5' }],
                },
              }
            : { success: true, delegation_id: 'issued-grant' },
      };
    },
  });
  const source = fs.readFileSync(
    new URL('../src/rp/consent-browser.js', import.meta.url),
    'utf8',
  );
  await vm.runInContext(`(async () => {${source}\n})()`, context);
  return {
    screen,
    status,
    requests,
    result,
    resultTitle,
    resultFeedback, feedback, close, closeWindow, navigate, timers,
    closePopup: () => listeners.get('close-click')?.({}),
    check,
    assertions: () => assertions,
    deny: async () => listeners.get('capabilities-deny')?.({}),
    checkStatus: async () => listeners.get('check-click')?.({}),
    allow: async (scopes: string[]) => {
      const listener = listeners.get('capabilities-allow');
      expect(
        listener,
        'The package capability event must drive approval',
      ).toBeDefined();
      await listener!({
        detail: { selectedCapabilityIds: ['order'], selectedScopes: scopes },
      });
    },
  };
}

describe('capability consent submission', () => {
  it('rejects empty, extra or changed scopes without issuing anything', async () => {
    const page = await browser();
    await page.allow([]);
    await page.allow([scope, 'payment.execute']);
    await page.allow(['https://id.gs1.org/01/12345678901231']);
    expect(page.requests).toHaveLength(0);
  });

  it('posts the reviewed bound scope as FormData and prevents a second decision after success', async () => {
    const page = await browser();
    await page.allow([scope]);
    await page.allow([scope]);
    expect(page.requests).toHaveLength(1);
    expect(page.requests[0]!.url).toBe('/consent/approve');
    expect(
      Object.fromEntries(page.requests[0]!.body as FormData),
    ).toMatchObject({ ...fields, selected_scopes: JSON.stringify([scope]) });
    expect(page.status.textContent).toContain('Grant issued');
  });

  it('moves decision feedback into the result card and closes the popup only on request', async () => {
    const page = await browser();
    await page.deny();
    expect(page.resultFeedback.append).toHaveBeenCalledWith(page.feedback);
    expect(page.resultTitle.focus).toHaveBeenCalledOnce();
    expect(page.close.hidden).toBe(false);
    expect(page.closeWindow).not.toHaveBeenCalled();
    await page.closePopup();
    expect(page.closeWindow).toHaveBeenCalledOnce();
    expect(page.navigate).not.toHaveBeenCalled();
    page.timers[0]!(); // A normal browser tab remained open after window.close().
    expect(page.navigate).toHaveBeenCalledWith('http://localhost:4949/');
  });

  it('keeps the grant unissued on cancelled passkey confirmation and allows an explicit retry', async () => {
    const page = await browser(true);
    await page.allow([scope]);
    expect(page.requests.map((r) => r.url)).toEqual([
      '/consent/webauthn/challenge',
    ]);
    expect(JSON.parse(page.requests[0]!.body as string).selected_scopes).toBe(JSON.stringify([scope]));
    expect(page.status.textContent).toContain('Passkey cancelled');
    expect(page.screen.loading).toBe(false);
    await page.allow([scope]);
    expect(page.requests).toHaveLength(2);
    expect(page.requests.every((r) => r.url.endsWith('/challenge'))).toBe(true);
  });

  it.each(['accountRef', 'provider', 'issuer', 'identitySource'])(
    'rejects changed account %s before asking for any passkey confirmation',
    async (field) => {
      const page = await browser({
        human,
        webauthnRequired: true,
        fetch: async () =>
          response({
            nonce: 'one-use',
            intent: { human: { ...human, [field]: 'changed' } },
            options: { challenge: 'aGVsbG8', allowCredentials: [] },
          }),
      });
      await page.allow([scope]);
      expect(page.assertions()).toBe(0);
      expect(page.requests.map((item) => item.url)).toEqual([
        '/consent/webauthn/challenge',
      ]);
      expect(page.status.textContent).toMatch(/account.*changed|reload/i);
      expect(page.result.hidden).toBe(true);
    },
  );

  it('accepts a provider name update for the same account and displays the confirmed intent name', async () => {
    const binary = new Uint8Array([1]).buffer;
    const page = await browser({
      human,
      webauthnRequired: true,
      getCredential: async () => ({
        id: 'key',
        rawId: binary,
        type: 'public-key',
        getClientExtensionResults: () => ({}),
        response: {
          clientDataJSON: binary,
          authenticatorData: binary,
          signature: binary,
          userHandle: null,
        },
      }),
      fetch: async (url) =>
        response(
          url.endsWith('/challenge')
            ? {
                nonce: 'one-use',
                intent: {
                  human: { ...human, displayName: 'Updated provider name' },
                },
                options: {
                  challenge: 'aGVsbG8',
                  allowCredentials: [{ id: 'a2V5' }],
                },
              }
            : { success: true, delegation_id: 'issued-grant' },
        ),
    });
    await page.allow([scope]);
    expect(page.assertions()).toBe(1);
    expect(page.status.textContent).toContain('Updated provider name');
    expect(page.status.textContent).not.toContain('Human A');
    expect(
      Object.fromEntries(page.requests[1]!.body as FormData),
    ).not.toHaveProperty('human');
  });

  it.each(['AbortError', 'NotAllowedError'])(
    'explains %s before submission without claiming an uncertain outcome',
    async (name) => {
      const page = await browser({
        webauthnRequired: true,
        getCredential: async () => {
          throw Object.assign(new Error('Browser internal detail'), { name });
        },
      });
      await page.allow([scope]);
      expect(page.status.textContent).toBe(
        'Passkey confirmation did not complete. No grant was issued. Try again.',
      );
      expect(page.requests.map((item) => item.url)).toEqual([
        '/consent/webauthn/challenge',
      ]);
      expect(page.screen.loading).toBe(false);
    },
  );

  it.each(['approved', 'consumed'])(
    'recovers %s after a lost response using the recorded human and without another decision',
    async (state) => {
      const page = await browser({
        human,
        fetch: async (url) => {
          if (url === '/consent/approve')
            throw new TypeError('Response connection lost after commit');
          return response({
            state,
            credentialId: 'issued-grant',
            demoConsent: {
              human: {
                ...human,
                accountRef: 'account-b',
                displayName: 'Recorded Human B',
              },
              authentication: { method: 'webauthn' },
            },
          });
        },
      });
      await page.allow([scope]);
      await page.allow([scope]);
      await page.deny();
      expect(page.result.hidden).toBe(false);
      expect(page.resultTitle.textContent).toBe('Grant issued');
      expect(page.status.textContent).toContain('Recorded Human B');
      expect(page.status.textContent).not.toContain('Human A');
      expect(page.requests.map((item) => item.url)).toEqual([
        '/consent/approve',
        '/consent/status?resume_token=signed-request',
      ]);
      expect(page.check.hidden).toBe(true);
    },
  );

  it('recovers recorded denial instead of claiming success for the attempted approval', async () => {
    const page = await browser({
      fetch: async (url) =>
        url === '/consent/approve'
          ? response({ error: 'already_denied' }, false)
          : response({ state: 'denied' }),
    });
    await page.allow([scope]);
    expect(page.resultTitle.textContent).toBe('Grant denied');
    expect(page.status.textContent).toBe(
      'Grant denied. No credential was issued.',
    );
  });

  it.each(['failed', 'expired'])(
    'locks a terminal %s request without reporting a grant',
    async (state) => {
      const page = await browser({
        fetch: async (url) =>
          url === '/consent/approve'
            ? response({ error: state }, false)
            : response({ state }),
      });
      await page.allow([scope]);
      await page.allow([scope]);
      await page.deny();
      expect(page.requests).toHaveLength(2);
      expect(page.status.textContent).toMatch(/fresh authorization/i);
      expect(page.status.textContent).not.toContain('Grant issued');
    },
  );

  it('freezes decisions when status is unavailable and offers an explicit status check, never another POST', async () => {
    let available = false;
    const page = await browser({
      fetch: async (url) => {
        if (!available || url === '/consent/approve')
          throw new TypeError('Network unavailable');
        return response({ state: 'approved', credentialId: 'committed-grant' });
      },
    });
    await page.allow([scope]);
    expect(page.screen.loading).toBe(true);
    expect(page.check.hidden).toBe(false);
    expect(page.status.textContent).not.toContain('No grant was issued');
    await page.allow([scope]);
    await page.deny();
    expect(page.requests).toHaveLength(2);
    available = true;
    await page.checkStatus();
    expect(page.resultTitle.textContent).toBe('Grant issued');
    expect(
      page.requests.filter((item) => item.url === '/consent/approve'),
    ).toHaveLength(1);
    expect(
      page.requests.filter((item) => item.url.startsWith('/consent/status')),
    ).toHaveLength(2);
  });

  it('recovers a committed denial when its response cannot be parsed', async () => {
    const page = await browser({
      fetch: async (url) =>
        url === '/consent/deny'
          ? {
              ok: true,
              json: async () => {
                throw new SyntaxError('Truncated response');
              },
            }
          : response({ state: 'denied' }),
    });
    await page.deny();
    await page.allow([scope]);
    expect(page.resultTitle.textContent).toBe('Grant denied');
    expect(page.requests.map((item) => item.url)).toEqual([
      '/consent/deny',
      '/consent/status?resume_token=signed-request',
    ]);
  });

  it('does not infer issued authority from pending, issuing or malformed status bodies', async () => {
    for (const state of ['pending', 'issuing', 'unknown', 'approved']) {
      const page = await browser({
        fetch: async (url) =>
          url === '/consent/approve'
            ? response({}, false)
            : response({ state }),
      });
      await page.allow([scope]);
      expect(page.result.hidden).toBe(true);
      expect(page.status.textContent).not.toContain('Grant issued');
    }
  });
});
