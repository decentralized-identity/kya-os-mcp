import fs from 'node:fs';
import vm from 'node:vm';
import { parse, type DefaultTreeAdapterTypes } from 'parse5';
import { describe, expect, it, vi } from 'vitest';
import { renderConsent } from '../src/rp/consent-page.js';
import type { HumanAccount } from '../src/rp/human-identity.js';
import type { ConsentFlow } from '../src/rp/consent-store.js';

vi.mock('../src/rp/key/credential-store.js', () => ({
  hasAuthenticator: () => false,
  listAuthenticators: () => [],
}));

// Exercise the actual projector script through its public SSE and HTTP inputs.
// This tiny DOM only implements the primitives this framework-free page uses.
class Element {
  private text = '';
  get textContent(): string { return this.text + this.children.map(child => child.textContent).join(''); }
  set textContent(value: string) { this.text = value; this.children = []; }
  innerHTML = '';
  className = '';
  hidden = false;
  disabled = false;
  href = '';
  title = '';
  value = '';
  onchange: (() => unknown) | null = null;
  onsubmit: ((event: { preventDefault(): void }) => unknown) | null = null;
  focus() {}
  attributes = new Map<string, string>();
  style: Record<string, string> = {};
  children: Element[] = [];
  onclick: ((event?: Partial<MouseEvent>) => unknown) | null = null;
  classList = {
    add: (name: string) => { this.className += ` ${name}`; },
    remove: (name: string) => { this.className = this.className.split(' ').filter((n) => n !== name).join(' '); },
    contains: (name: string) => this.className.split(' ').includes(name),
    toggle: (name: string, force?: boolean) => {
      if (force ?? !this.classList.contains(name)) this.classList.add(name);
      else this.classList.remove(name);
    },
  };
  appendChild(child: Element) { this.children.push(child); }
  replaceChildren(...children: Element[]) { this.text = ''; this.children = children; }
  prepend(child: Element) { this.children.unshift(child); }
  querySelector() { const child = new Element(); this.children.push(child); return child; }
  scrollIntoView() {}
  removeAttribute(name: string) { this.attributes.delete(name); if (name === 'href') this.href = ''; }
  setAttribute(name: string, value: string) { this.attributes.set(name, value); if (name === 'href') this.href = value; }
  getAttribute(name: string) { return this.attributes.get(name) ?? null; }
}

// Extract the trusted local fixture script for VM execution, not HTML sanitization.
function inlinePageScript(html: string): string {
  const scripts: string[] = [];
  function visit(node: DefaultTreeAdapterTypes.Node) {
    if ('tagName' in node && node.tagName === 'script') {
      const type = (node.attrs.find(attr => attr.name === 'type')?.value ?? '').trim().toLowerCase();
      if (!node.attrs.some(attr => attr.name === 'src')
        && ['', 'text/javascript', 'application/javascript'].includes(type)) {
        scripts.push(node.childNodes.map(child => 'value' in child ? child.value : '').join(''));
      }
    }
    if ('childNodes' in node) node.childNodes.forEach(visit);
  }
  visit(parse(html));
  if (scripts.length !== 1) {
    throw new Error(`The local page fixture must contain exactly one inline classic script; found ${scripts.length}`);
  }
  return scripts[0]!;
}

describe('local fixture script selection', () => {
  it('ignores external and data scripts instead of executing them in the page harness', () => {
    const script = inlinePageScript('<script src="/external.js">throw new Error("external")</script>'
      + '<script type="application/json">{"data":"fixture"}</script>'
      + '<script>globalThis.fixtureExecuted = true;</script>');
    const context = vm.createContext({});
    vm.runInContext(script, context);
    expect(context.fixtureExecuted).toBe(true);
  });

  it('fails clearly when a fixture contains no executable inline script', () => {
    expect(() => inlinePageScript('<script type="application/json">{}</script>'))
      .toThrow('The local page fixture must contain exactly one inline classic script; found 0');
  });

  it('fails clearly if a page gains a second inline script the harness would otherwise skip', () => {
    expect(() => inlinePageScript('<script>first()</script><script>second()</script>'))
      .toThrow('The local page fixture must contain exactly one inline classic script; found 2');
  });
});

async function projector(initialChallenge?: Record<string, unknown>, credential: unknown = null,
  html = fs.readFileSync(new URL('../web/index.html', import.meta.url), 'utf8')) {
  const elements = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map((match) => [match[1]!, new Element()]));
  const streams = new Map<string, { onmessage?: (event: { data: string }) => void; onopen?: () => void }>();
  const state = { credential, responses: {} as Record<string, unknown>, statuses: {} as Record<string, number>, requests: [] as string[], posts: [] as Array<{ url: string; body: unknown }> };
  const listeners = new Map<string, (event: unknown) => void>();
  const get = (id: string) => {
    if (!elements.has(id) && /^(ledger-row-|tree-forged)/.test(id)) elements.set(id, new Element());
    const element = elements.get(id);
    if (!element) throw new Error(`Missing projector element #${id}`);
    return element;
  };
  const popup = { opener: {} as object | null, name: '', location: { replace: vi.fn() }, focus: vi.fn(), close: vi.fn() };
  const open = vi.fn().mockReturnValue(popup);
  const context = vm.createContext({
    URL, Date, console, setTimeout, clearTimeout, AbortSignal, AbortController,
    window: { open, location: { origin: 'http://localhost:4949' }, screen: { availWidth: 1440, availHeight: 900, availLeft: 0, availTop: 0 } },
    document: {
      getElementById: get, createElement: () => new Element(),
      body: new Element(), querySelectorAll: () => [], addEventListener: (type: string, callback: (event: unknown) => void) => listeners.set(type, callback),
    },
    fetch: async (url: string, options?: { body?: string }) => {
      state.requests.push(url);
      if (options?.body) state.posts.push({ url, body: JSON.parse(options.body) });
      if (state.responses[url] instanceof Error) throw state.responses[url];
      const status = state.statuses[url] ?? 200;
      return { status, ok: status >= 200 && status < 300, json: async () => Object.hasOwn(state.responses, url)
      ? typeof state.responses[url] === 'function' ? (state.responses[url] as () => unknown)() : state.responses[url] : url.endsWith('/api/state')
      ? { responsibleParty: { hubOrigin: 'http://localhost:4950' }, authorizationChallenge: initialChallenge }
      : url.endsWith('/api/rp/state')
        ? { statusList: { version: 1 }, activeIndex: null, revoked: false }
        : url.includes('/consent/status?') ? { state: 'pending' }
        : { credential: state.credential } };
    },
    EventSource: class { constructor(url: string) { streams.set(url, this); } },
  });
  vm.runInContext(inlinePageScript(html), context);
  await new Promise((resolve) => setTimeout(resolve, 0));
  const emit = (stream: string, data: Record<string, unknown>) => {
    const source = streams.get(stream);
    if (!source?.onmessage) throw new Error(`Missing SSE stream ${stream}`);
    source.onmessage({ data: JSON.stringify(data) });
  };
  return { get, emit, state, open, popup, key: (key: string, target?: unknown) => listeners.get('keydown')?.({ key, target }), reconnect: (url: string) => streams.get(url)?.onopen?.() };
}

const attributePayload = `\" onpointerenter=\"globalThis.projectorInjected=1\" data-injected=\"'&<>`;
const encodedPayload = '&quot; onpointerenter=&quot;globalThis.projectorInjected=1&quot; data-injected=&quot;&#39;&amp;&lt;&gt;';
const digestPayload = 'sha256:<b>bad</b>';

function auditFixture() {
  return {
    ledger: { ledgerId: 'test-ledger', ledgerEpochId: 'test-epoch' },
    entries: [{ seq: attributePayload, outcome: attributePayload, eventType: 'order', reason: attributePayload,
      at: '2026-09-08T12:00:00Z', anchored: true, entryDigest: digestPayload, previousEntryDigest: null }],
    checkpoint: { rootDigest: digestPayload, treeSize: 1, createdAt: Date.now() },
    witness: { observer: { did: 'did:key:witness' }, observedAt: Date.now(), observationDigest: digestPayload },
    profile: { advertised: 'AAP-2' }, tree: [{ hash: digestPayload }, { hash: digestPayload, leafIndex: 0, prefix: '└ ', label: '[0]' }],
    inclusions: [], allIncluded: true, chainIntact: true,
  };
}

describe('payment and checkout decisions', () => {
  it('distinguishes payment authorization from delegation failure and settlement uncertainty from refusal', async () => {
    const p = await projector();
    p.emit('/api/events', { type: 'verdict', verdict: 'denied', code: 'PAYMENT_REQUIRED', body: { error: 'PAYMENT_REQUIRED', x402Version: 2 } });
    expect(p.get('seal').textContent).toBe('PAYMENT NEEDED');
    expect(p.get('decision-summary').textContent).toContain('Authority verified');
    p.emit('/api/events', { type: 'verdict', verdict: 'denied', code: 'SETTLEMENT_PENDING', body: { error: 'SETTLEMENT_PENDING' } });
    expect(p.get('seal').textContent).toBe('CHECK OUTCOME');
    expect(p.get('decision-summary').textContent).toContain('Do not submit another payment');
    expect(p.get('decision-summary').textContent).not.toContain('No order placed');
  });
  it('opens only same-merchant checkout review links and keeps their consent separate from RP grant polling', async () => {
    const p = await projector();
    const url = 'http://localhost:4949/checkout/demo?token=opaque';
    p.emit('/api/events', { type: 'checkout.review', id: 'demo', url, expiresAt: new Date(Date.now() + 300_000).toISOString() });
    expect(p.get('seal').textContent).toBe('REVIEW CHECKOUT');
    expect(p.get('authorization-link').textContent).toBe('Review checkout');
    await p.get('authorization-link').onclick!({ button: 0, preventDefault() {} });
    expect(p.popup.location.replace).toHaveBeenCalledWith(url);
    expect(p.popup.opener).toBeNull();
    p.emit('/api/events', { type: 'checkout.review', id: 'demo', url: 'https://attacker.example/checkout/demo?token=opaque' });
    expect(p.get('authorization-link').href).toBe('');
    expect(p.get('seal').textContent).toBe('DENIED');
  });
});

describe('revocation terminal feedback', () => {
  it('renders the HTTP result even when the completion SSE is lost', async () => {
    const p = await projector();
    p.state.responses['http://localhost:4950/api/rp/state'] = { grantIssued: true, activeIndex: 94, keyRequired: false, revoked: false, statusList: { version: 1 } };
    p.state.responses['http://localhost:4950/api/rp/revoke'] = { index: 94, revoked: true, version: 2, totalMs: 5, audit: 'recorded' };
    p.emit('http://localhost:4950/api/rp/events', { type: 'revoke_start', index: 94 });
    await p.get('btn-revoke').onclick!();
    expect(p.get('seal').textContent).toBe('REVOKED');
    expect(p.get('verdict-code').textContent).toBe('GRANT_REVOKED');
  });

  it('leaves VERIFYING on failure and does not claim the grant was revoked', async () => {
    const p = await projector();
    p.state.responses['http://localhost:4950/api/rp/state'] = { grantIssued: true, activeIndex: 94, keyRequired: false, revoked: false, statusList: { version: 1 } };
    p.state.responses['http://localhost:4950/api/rp/revoke'] = { error: 'revocation_failed', message: 'Storage unavailable' };
    p.emit('http://localhost:4950/api/rp/events', { type: 'revoke_start', index: 94 });
    await p.get('btn-revoke').onclick!();
    expect(p.get('seal').textContent).not.toBe('VERIFYING');
    expect(p.get('verdict-code').textContent).toBe('REVOCATION_NOT_CONFIRMED');
  });

  it('distinguishes successful publication from an unavailable audit export', async () => {
    const p = await projector();
    p.emit('http://localhost:4950/api/rp/events', { type: 'revoke_start', index: 94 });
    p.emit('http://localhost:4950/api/rp/events', { type: 'revoke_done', index: 94, revoked: true, version: 2, audit: 'unavailable' });
    expect(p.get('verdict-context').textContent).toBe('AUDIT EXPORT PENDING');
    expect(p.get('seal').textContent).toBe('REVOKED');
    expect(p.get('verdict-code').textContent).toBe('GRANT_REVOKED');
  });
});

describe('projector untrusted receipt and audit rendering', () => {
  it('keeps quote-bearing receipt fields literal through the actual merchant SSE handler', async () => {
    const p = await projector();
    p.emit('/api/events', {
      type: 'verdict', verdict: 'allowed', elapsedMs: 1,
      body: { ok: true, orderId: attributePayload,
        order: { name: 'Risotto', product: attributePayload, quantity: 2, unitPrice: '19.90', total: '39.80' },
        mandate: { responsibleParty: attributePayload } },
      receipt: { jws: attributePayload, meta: { kid: attributePayload } },
    });
    expect(p.get('receipt').innerHTML).toContain(`<div class="jws" id="jws">${encodedPayload}</div>`);
    expect(p.get('receipt').innerHTML).not.toContain('" onpointerenter="');
  });

  it('contains ledger identifiers, outcomes and reason text inside their intended attributes', async () => {
    const p = await projector();
    p.state.responses['/api/act/audit'] = auditFixture();
    await p.get('btn-audit').onclick!();
    const table = p.get('audit-table').innerHTML;
    expect(table).toContain(`class="o-${encodedPayload}"`);
    expect(table).toContain(`id="ledger-row-${encodedPayload}"`);
    expect(table).toContain(`title="${encodedPayload}"`);
    expect(table).not.toContain('" onpointerenter="');
  });

  it('contains verdict classes, dimension/reason titles and exported commands inside their attributes', async () => {
    const p = await projector();
    p.state.responses['/api/act/audit'] = auditFixture();
    p.state.responses['/api/act/export'] = {
      components: [{ path: attributePayload, size: 12 }], command: { honest: attributePayload }, manifestDigest: digestPayload,
      reports: { honest: { [attributePayload]: { verdict: attributePayload, reasonCodes: [attributePayload] } }, tampered: {} },
    };
    await p.get('btn-export').onclick!();
    expect(p.get('audit-export').innerHTML).toContain(`title="${encodedPayload}"`);
    expect(p.get('audit-export').innerHTML).toContain('manifest &lt;b&gt;bad&lt;/b&gt; signed');
    const verdicts = p.get('audit-verdicts').innerHTML;
    expect(verdicts).toContain(`class="verdict ${encodedPayload}"`);
    expect(verdicts).toContain(`title="${encodedPayload}: ${encodedPayload} ${encodedPayload}"`);
    expect(verdicts).not.toContain('" onpointerenter="');
  });

  it('escapes ledger, tree and witness digest prefixes without changing ordinary digest or text labels', async () => {
    const p = await projector();
    p.state.responses['/api/act/audit'] = auditFixture();
    await p.get('btn-audit').onclick!();
    for (const id of ['audit-table', 'audit-tree-root', 'audit-tree', 'audit-cp']) {
      expect(p.get(id).innerHTML, id).toContain('&lt;b&gt;bad&lt;/b&gt;');
      expect(p.get(id).innerHTML, id).not.toContain('<b>bad</b>');
    }
    p.emit('/api/events', { type: 'audit', entries: 1, rootDigest: digestPayload, treeSize: 1 });
    expect(p.get('audit-root').textContent).toBe('root <b>bad</b>… · 1 leaves');
    for (const digest of ['0123456789abcdef0123456789abcdef', 'Ab_C-deF0123456789_ab-CdeF0123456']) {
      const ordinary = auditFixture();
      ordinary.entries[0]!.entryDigest = 'sha256:' + digest;
      ordinary.tree[0]!.hash = 'sha256:' + digest;
      p.state.responses['/api/act/audit'] = ordinary;
      await p.get('btn-audit').onclick!();
      expect(p.get('audit-table').innerHTML).toContain(`<td class="digest">${digest.slice(0, 10)}</td>`);
      expect(p.get('audit-tree-root').innerHTML).toContain(`<span class="h">${digest.slice(0, 24)}</span>`);
      p.emit('/api/events', { type: 'audit', entries: 1, rootDigest: 'sha256:' + digest, treeSize: 1 });
      expect(p.get('audit-root').textContent).toBe(`root ${digest.slice(0, 16)}… · 1 leaves`);
    }
  });

  it('escapes RP revocation timing before sending it into the log HTML', async () => {
    const p = await projector();
    p.emit('http://localhost:4950/api/rp/events', { type: 'revoke_phase', elapsedMs: '<b>bad</b>', phase: 'test' });
    const markup = p.get('rp-log').children.flatMap(row => row.children.map(child => child.innerHTML)).join('');
    expect(markup).toContain('&lt;b&gt;bad&lt;/b&gt;');
    expect(markup).not.toContain('<b>bad</b>');
  });
});

const challenge = {
  type: 'verdict', verdict: 'needs_authorization', elapsedMs: 10,
  body: {
    error: 'needs_authorization', resumeToken: 'human-grant-session',
    authorizationUrl: 'http://127.0.0.1:4950/consent?session_id=human-grant-session',
    expiresAt: Math.floor(Date.now() / 1000) + 300,
    scopes: ['https://id.gs1.org/01/09506000134352'],
  },
};

function namedGrant(displayName = 'Dylan Hobbs') {
  return {
    issuer: 'did:web:localhost%3A4950',
    credentialSubject: {
      id: 'did:key:shopping-agent',
      delegation: {
        constraints: { audience: 'did:key:merchant' },
        metadata: {
          demoConsent: {
            consentRef: 'sha256:consent-reference',
            human: { provider: 'google', issuer: 'https://accounts.google.com', accountRef: 'google-account-reference', identitySource: 'identity-provider', displayName },
            authentication: { method: 'webauthn', credentialRef: 'sha256:passkey-reference', intentHash: 'sha256:intent-reference', userVerified: true },
            approvedAt: '2026-09-08T12:00:00Z',
          },
        },
      },
    },
  };
}

const scriptTagVariants = [
  { name: 'uppercase script tags', closingTag: '</SCRIPT>' },
  { name: 'browser-accepted closing-tag attributes', closingTag: '</SCRIPT\t\n bar>' },
];

describe('projector grant refresh delivery', () => {
  const rp = 'http://localhost:4950';
  const tick = () => new Promise(resolve => setTimeout(resolve, 0));

  it('shows an issued grant without waiting for a stalled merchant state read', async () => {
    const p = await projector();
    let release!: (value: unknown) => void;
    p.state.responses['/api/state'] = new Promise(resolve => { release = resolve; });
    p.state.credential = namedGrant();
    p.emit(rp + '/api/rp/events', { type: 'consent.approved', index: 94 });
    await tick();
    try {
      expect(p.get('grant-pill').textContent).toBe('active');
      expect(p.get('c-human').textContent).toBe('Dylan Hobbs');
    } finally { release({ responsibleParty: { hubOrigin: rp } }); }
  });

  it('does not let a delayed pre-approval snapshot erase the issued grant', async () => {
    const p = await projector();
    let release!: (value: unknown) => void;
    let requested = false;
    const stale = new Promise(resolve => { release = resolve; });
    p.state.responses[rp + '/api/rp/delegation'] = () => { requested = true; return stale; };
    p.emit('/api/events', { type: 'reset' });
    await tick();
    expect(requested).toBe(true);
    p.state.responses[rp + '/api/rp/delegation'] = { credential: namedGrant() };
    p.emit(rp + '/api/rp/events', { type: 'consent.approved', index: 94 });
    await tick();
    expect(p.get('grant-pill').textContent).toBe('active');
    release({ credential: null });
    await tick();
    expect(p.get('grant-pill').textContent).toBe('active');
    expect(p.get('c-human').textContent).toBe('Dylan Hobbs');
  });

  it.each(['approved', 'denied', 'expired'])('reconciles a pending popup after a missed %s event', async status => {
    const p = await projector(challenge.body);
    p.state.responses[rp + '/consent/status?resume_token=' + challenge.body.resumeToken] = { state: status, index: 94 };
    if (status === 'approved') p.state.credential = namedGrant();
    p.reconnect(rp + '/api/rp/events');
    await tick();
    expect(p.get('authorization-panel').hidden).toBe(true);
    expect(p.get('verdict-code').textContent).toBe(status === 'approved' ? 'HUMAN_APPROVED' : 'CONSENT_' + status.toUpperCase());
    expect(p.get('seal').textContent).not.toBe('AUTHORIZED');
  });

  it('ignores a recovered decision for a challenge replaced while its status was loading', async () => {
    const p = await projector(challenge.body);
    let release!: (value: unknown) => void;
    p.state.responses[rp + '/consent/status?resume_token=' + challenge.body.resumeToken] = new Promise(resolve => { release = resolve; });
    p.reconnect(rp + '/api/rp/events');
    await tick();
    const newer = { ...challenge.body, resumeToken: 'newer-flow', authorizationUrl: rp + '/consent?session_id=newer-flow' };
    p.emit('/api/events', { ...challenge, body: newer });
    release({ state: 'approved', index: 94 });
    await tick();
    expect(p.get('authorization-panel').hidden).toBe(false);
    expect(p.get('authorization-link').href).toBe(newer.authorizationUrl);
    expect(p.get('verdict-code').textContent).toBe('NEEDS_AUTHORIZATION');
  });

  it('recovers a grant issued while the RP event stream was disconnected', async () => {
    const p = await projector();
    p.state.credential = namedGrant();
    p.reconnect(rp + '/api/rp/events');
    await tick();
    expect(p.get('grant-pill').textContent).toBe('active');
    expect(p.get('c-human').textContent).toBe('Dylan Hobbs');
  });
});

describe('projector human-grant journey', () => {
  it('identifies the W3C credential with a separate Delegation heading inside its frame', () => {
    const html = fs.readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
    let frame: DefaultTreeAdapterTypes.Element | undefined;
    function visit(node: DefaultTreeAdapterTypes.Node) {
      if ('tagName' in node && node.tagName === 'fieldset'
        && node.attrs.some(attr => attr.name === 'class' && attr.value.split(/\s+/).includes('credential-frame'))) {
        frame = node;
      }
      if ('childNodes' in node) node.childNodes.forEach(visit);
    }
    function text(node: DefaultTreeAdapterTypes.Node): string {
      return 'value' in node ? node.value : 'childNodes' in node ? node.childNodes.map(text).join(' ') : '';
    }
    visit(parse(html));
    expect(frame, 'credential grouping should have native fieldset semantics').toBeDefined();
    const legend = frame!.childNodes.find(node => 'tagName' in node && node.tagName === 'legend');
    expect(legend, 'the fieldset should have a legend').toBeDefined();
    expect(text(legend!).trim()).toBe('W3C Verifiable Credential');
    const heading = frame!.childNodes.find(node => 'tagName' in node && node.tagName === 'h2');
    expect(heading, 'the credential type should be a heading inside the frame').toBeDefined();
    expect(text(heading!).trim()).toBe('Delegation');
  });

  it('shows every action scope from the signed delegation constraints without inferring the tool name', async () => {
    const grant = namedGrant();
    const scopes = ['commerce.order', 'commerce.order.read'];
    const scoped = { ...grant, credentialSubject: { ...grant.credentialSubject, delegation: {
      ...grant.credentialSubject.delegation,
      constraints: { ...grant.credentialSubject.delegation.constraints, scopes },
      metadata: { ...grant.credentialSubject.delegation.metadata, tool: 'different_tool' },
    } } };
    const p = await projector(undefined, scoped);
    expect(p.get('c-action-scopes').textContent).toBe(scopes.join(' · '));
    expect(p.get('c-action-scopes').textContent).not.toContain('different_tool');
  });

  it.each(['order', 'day'])('keeps the currency amount separate from its signed per-%s limit', async (per) => {
    const grant = namedGrant();
    const scoped = { ...grant, credentialSubject: { ...grant.credentialSubject, delegation: {
      ...grant.credentialSubject.delegation,
      constraints: { ...grant.credentialSubject.delegation.constraints, crisp: { scopes: [{
        resource: 'https://id.gs1.org/01/09506000134352', matcher: 'gs1-product-class',
        constraints: { currency: 'CHF', maxAmount: '50.00', per },
      }] } },
    } } };
    const p = await projector(undefined, scoped);
    expect(p.get('c-cap-label').textContent).toBe(`Per-${per} limit`);
    expect(p.get('c-cap').textContent).toBe('CHF 50.00');
    p.state.credential = null;
    p.emit('/api/events', { type: 'reset' });
    expect(p.get('c-cap-label').textContent).toBe('Per-order limit');
    expect(p.get('c-cap').textContent).toBe('—');
  });

  it.each([
    { label: 'absent', scopes: undefined },
    { label: 'empty', scopes: [] as string[] },
  ])('does not invent an action scope for a grant with $label scopes', async ({ scopes }) => {
    const grant = namedGrant();
    const scoped = { ...grant, credentialSubject: { ...grant.credentialSubject, delegation: {
      ...grant.credentialSubject.delegation,
      constraints: { ...grant.credentialSubject.delegation.constraints, ...(scopes ? { scopes } : {}) },
      metadata: { ...grant.credentialSubject.delegation.metadata, tool: 'place_order' },
    } } };
    const p = await projector(undefined, scoped);
    expect(p.get('c-action-scopes').textContent).toBe('—');
  });

  it('clears approved action scopes when the grant is reset', async () => {
    const grant = namedGrant();
    const scoped = { ...grant, credentialSubject: { ...grant.credentialSubject, delegation: {
      ...grant.credentialSubject.delegation,
      constraints: { ...grant.credentialSubject.delegation.constraints, scopes: ['commerce.order'] },
    } } };
    const p = await projector(undefined, scoped);
    expect(p.get('c-action-scopes').textContent).toBe('commerce.order');
    p.state.credential = null;
    p.emit('/api/events', { type: 'reset' });
    expect(p.get('c-action-scopes').textContent).toBe('—');
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(p.get('c-action-scopes').textContent).toBe('—');
  });

  it('renders scope strings literally rather than interpreting credential data as HTML', async () => {
    const grant = namedGrant();
    const scope = '<img src=x onerror=alert(1)>';
    const scoped = { ...grant, credentialSubject: { ...grant.credentialSubject, delegation: {
      ...grant.credentialSubject.delegation,
      constraints: { ...grant.credentialSubject.delegation.constraints, scopes: [scope] },
    } } };
    const p = await projector(undefined, scoped);
    expect(p.get('c-action-scopes').textContent).toBe(scope);
    expect(p.get('c-action-scopes').innerHTML).toBe('');
  });

  it.each(scriptTagVariants)('executes the actual projector page with $name', async ({ closingTag }) => {
    const html = fs.readFileSync(new URL('../web/index.html', import.meta.url), 'utf8')
      .replaceAll('<script>', '<SCRIPT>').replaceAll('</script>', closingTag);
    const p = await projector(undefined, namedGrant(), html);
    expect(p.get('c-human').textContent).toBe('Dylan Hobbs');
    expect(p.get('verdict-code').textContent).toBe('GRANT_ACTIVE');
    p.emit('/api/events', { type: 'reset' });
    expect(p.get('grant-pill').textContent).toBe('no grant');
  });

  it('renders consent as a separate gate and preserves proven holder identity while consent is pending', async () => {
    const p = await projector();
    p.emit('/api/events', { ...challenge, checks: { signature: 'skip', revocation: 'skip', holder: 'pass', product: 'skip', cap: 'skip', consent: 'pending', receipt: 'skip' } });
    const gates = p.get('gates').children;
    expect(gates).toHaveLength(7);
    expect(gates[0]!.className).toBe('gate skip');
    expect(gates[2]!.className).toBe('gate pass');
    expect(gates[5]!.innerHTML).toContain('Human consent');
    expect(gates[5]!.className).toBe('gate pending');
  });

  it('shows a consent binding refusal without repainting a verified signature as failed', async () => {
    const p = await projector();
    p.emit('/api/events', { type: 'verdict', verdict: 'denied', code: 'CONSENT_BINDING_MISMATCH', reason: 'Resume token binding differs from this credential.', checks: { signature: 'pass', revocation: 'pass', holder: 'pass', product: 'pass', cap: 'pass', consent: 'fail', receipt: 'skip' } });
    const gates = p.get('gates').children;
    expect(gates[0]!.className).toBe('gate pass');
    expect(gates[5]!.className).toBe('gate fail');
    expect(p.get('verdict-code').textContent).toBe('CONSENT_BINDING_MISMATCH');
  });

  it('opens human consent in a centered popup and detaches its opener before navigating', async () => {
    const p = await projector(challenge.body);
    const preventDefault = vi.fn();
    p.popup.location.replace.mockImplementation(() => { expect(p.popup.opener).toBeNull(); });
    expect(p.get('authorization-link').onclick).toBeTypeOf('function');
    await p.get('authorization-link').onclick!({ button: 0, preventDefault });
    expect(p.open).toHaveBeenCalledWith('about:blank', '_blank', expect.stringContaining('popup=yes,width=680,height=820'));
    expect(p.popup.location.replace).toHaveBeenCalledWith(challenge.body.authorizationUrl);
    expect(p.popup.focus).toHaveBeenCalled();
    expect(preventDefault).toHaveBeenCalledOnce();
  });

  it('keeps the ordinary consent link usable if popups are blocked or a modified click requests a tab', async () => {
    const p = await projector(challenge.body);
    const preventDefault = vi.fn();
    expect(p.get('authorization-link').onclick).toBeTypeOf('function');
    await p.get('authorization-link').onclick!({ button: 0, ctrlKey: true, preventDefault });
    expect(p.open).not.toHaveBeenCalled();
    p.open.mockReturnValue(null);
    await p.get('authorization-link').onclick!({ button: 0, preventDefault });
    expect(preventDefault).not.toHaveBeenCalled();
    expect(p.get('authorization-link').href).toBe(challenge.body.authorizationUrl);
  });

  it('restores a cached verified consent challenge from the agent reply when no new merchant SSE event occurs', async () => {
    const p = await projector();
    p.state.responses['/api/act/order'] = { result: { content: [{ type: 'text', text: JSON.stringify(challenge.body) }] } };
    await p.get('btn-order').onclick!();
    expect(p.get('authorization-link').href).toBe(challenge.body.authorizationUrl);
    expect(p.get('authorization-panel').hidden).toBe(false);
  });

  it('shows the Google account, passkey, signed consent and agent relationship from grant metadata', async () => {
    const p = await projector(undefined, namedGrant());
    expect(p.get('human-grant').hidden).toBe(false);
    expect(p.get('c-human').textContent).toBe('Dylan Hobbs');
    expect(p.get('c-human-source').textContent).toContain('Google account');
    expect(p.get('c-human-authentication').textContent).toContain('RP verified the passkey');
    expect(p.get('c-human-consent').textContent).toContain('consent-reference');
    expect(p.get('c-agent').textContent).toBe('did:key:shopping-agent');
    expect(p.get('verdict-code').textContent).toBe('GRANT_ACTIVE');
  });

  it('preserves complete identifiers in credential details for both key and web DIDs', async () => {
    const grant = namedGrant();
    grant.issuer = 'did:web:authorization.workshop.example:responsible-parties:account';
    grant.credentialSubject.id = 'did:key:z6MkpiZsrvpx2mJFA7kd6MDMPQMfxmRkqRGX3v6f5WuqzMTjPT';
    grant.credentialSubject.delegation.constraints.audience = 'did:key:z6MkgrhQVX7j7BNBNBE8rkbqkQi2h9cjJK115XP9n7bkL24N';
    const p = await projector(undefined, grant);
    expect(p.get('c-rp').textContent).toBe(grant.issuer);
    expect(p.get('c-agent').textContent).toBe(grant.credentialSubject.id);
    expect(p.get('c-aud').textContent).toBe(grant.credentialSubject.delegation.constraints.audience);
  });

  it('shows the full resolved signing key separately from its source and clears it when unresolved', async () => {
    const p = await projector();
    const kid = 'did:web:authorization.workshop.example:responsible-parties:account#key-1';
    p.state.responses['/api/state'] = { responsibleParty: { hubOrigin: 'http://localhost:4950', resolved: true, kid } };
    p.emit('/api/events', { type: 'reset' });
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(p.get('rp-resolved').textContent).toBe('DID document resolved from the network');
    expect(p.get('rp-resolved-kid').textContent).toBe(kid);
    expect(p.get('rp-resolved-kid').hidden).toBe(false);
    p.state.responses['/api/state'] = { responsibleParty: { hubOrigin: 'http://localhost:4950', resolved: false } };
    p.emit('/api/events', { type: 'reset' });
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(p.get('rp-resolved-kid').textContent).toBe('');
    expect(p.get('rp-resolved-kid').hidden).toBe(true);
    expect(p.get('rp-resolved').textContent).toContain('not resolved');
  });

  it('renders provider profile text literally and clears the named relationship on reset', async () => {
    const profile = '<img src=x onerror=alert(1)>';
    const p = await projector(undefined, namedGrant(profile));
    expect(p.get('c-human').textContent).toBe(profile);
    expect(p.get('c-human').innerHTML).toBe('');
    p.state.credential = null;
    p.emit('/api/events', { type: 'reset' });
    expect(p.get('human-grant').hidden).toBe(true);
    expect(p.get('c-human').textContent).toBe('');
  });

  it('makes no named-human claim for self-declared metadata', async () => {
    const grant = namedGrant();
    grant.credentialSubject.delegation.metadata.demoConsent.human.identitySource = 'self-declared';
    const p = await projector(undefined, grant);
    expect(p.get('human-grant').hidden).toBe(true);
    expect(p.get('c-human').textContent).toBe('');
  });

  it('keeps legacy grants readable without attributing them to a named Google account', async () => {
    const grant = namedGrant();
    const { metadata: _metadata, ...delegation } = grant.credentialSubject.delegation;
    const legacy = { ...grant, credentialSubject: { ...grant.credentialSubject, delegation } };
    const p = await projector(undefined, legacy);
    expect(p.get('grant-pill').textContent).toBe('active');
    expect(p.get('human-grant').hidden).toBe(true);
    expect(p.get('c-human').textContent).toBe('');
  });
  it('starts with an explicit missing grant and displays the live challenge link', async () => {
    const p = await projector();
    expect(p.get('grant-pill').textContent).toBe('no grant');
    p.emit('/api/events', challenge);
    expect(p.get('seal').textContent).toBe('CONSENT NEEDED');
    expect(p.get('authorization-panel').hidden).toBe(false);
    expect(p.get('authorization-link').href).toBe(challenge.body.authorizationUrl);
    expect(p.get('authorization-detail').textContent).toContain('09506000134352');
  });

  it('never makes an unrelated authorization origin clickable', async () => {
    const p = await projector();
    p.emit('/api/events', { ...challenge, body: { ...challenge.body, authorizationUrl: 'https://attacker.example/consent' } });
    expect(p.get('authorization-link').href).toBe('');
    expect(p.get('verdict-code').textContent).toBe('AUTHORIZATION_URL_REJECTED');
  });

  it('recovers a still-pending challenge when the operator opens the console late', async () => {
    const p = await projector(challenge.body);
    expect(p.get('authorization-panel').hidden).toBe(false);
    expect(p.get('authorization-link').href).toBe(challenge.body.authorizationUrl);
  });

  it('refuses expired consent URLs and ignores approvals of a different request', async () => {
    const p = await projector();
    p.emit('/api/events', { ...challenge, body: { ...challenge.body, expiresAt: 1 } });
    expect(p.get('verdict-code').textContent).toBe('AUTHORIZATION_EXPIRED');
    expect(p.get('authorization-link').href).toBe('');
    p.emit('/api/events', challenge);
    p.emit('http://localhost:4950/api/rp/events', { type: 'consent.approved', resumeToken: 'another-request', index: 95 });
    expect(p.get('seal').textContent).toBe('CONSENT NEEDED');
    expect(p.get('authorization-panel').hidden).toBe(false);
  });

  it('marks approval as ready for retry, and hides the single-use URL', async () => {
    const p = await projector();
    p.emit('/api/events', challenge);
    p.emit('http://localhost:4950/api/rp/events', { type: 'consent.approved', sessionId: 'human-grant-session', index: 94 });
    expect(p.get('seal').textContent).toBe('GRANT APPROVED');
    expect(p.get('authorization-panel').hidden).toBe(true);
    expect(p.get('verdict-code').textContent).toBe('HUMAN_APPROVED');
    expect(p.get('verdict-context').textContent).toContain('RETRY');
  });

  it('shows human denial without inventing a grant and resets to no consent', async () => {
    const p = await projector();
    p.emit('/api/events', challenge);
    p.emit('http://localhost:4950/api/rp/events', { type: 'consent.denied', sessionId: 'human-grant-session' });
    expect(p.get('seal').textContent).toBe('DENIED');
    expect(p.get('verdict-code').textContent).toBe('CONSENT_DENIED');
    expect(p.get('authorization-panel').hidden).toBe(true);
    p.emit('/api/events', { type: 'reset' });
    expect(p.get('grant-pill').textContent).toBe('no grant');
    expect(p.get('verdict-code').textContent).toBe('NO_GRANT');
  });
});

async function registrationPage(signedIn: boolean, displayName = 'Dylan Hobbs', label = 'Platform passkey', identityEnabled = true,
  html = fs.readFileSync(new URL('../web/setup-key.html', import.meta.url), 'utf8')) {
  const elements = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(match => [match[1]!, new Element()]));
  const requests: Array<{ url: string; credentials?: string }> = [];
  const get = (id: string) => {
    if (!elements.has(id) && /^(ledger-row-|tree-forged)/.test(id)) elements.set(id, new Element());
    const element = elements.get(id);
    if (!element) throw new Error(`Missing registration element #${id}`);
    return element;
  };
  const context = vm.createContext({
    URL, console, location: { origin: identityEnabled ? 'http://localhost:4950' : 'http://localhost:4949', href: 'http://localhost:4950/setup-key.html' },
    document: { getElementById: get, createElement: () => new Element() },
    fetch: async (url: string, options?: { credentials?: string }) => {
      requests.push({ url, credentials: options?.credentials });
      const data = url.endsWith('/api/state') ? (identityEnabled ? {} : { responsibleParty: { hubOrigin: 'http://localhost:4950' } })
        : url.endsWith('/api/rp/state') ? { googleIdentityEnabled: identityEnabled }
          : url.endsWith('/auth/account') ? { enabled: true, signedIn, account: signedIn ? { provider: 'google', displayName, identitySource: 'identity-provider', accountRef: 'account-ref' } : null }
            : { authenticators: [{ label, idTail: 'abcd', registeredAt: '2026-09-08T12:00:00Z', transports: ['internal'] }] };
      return { ok: true, json: async () => data };
    },
  });
  vm.runInContext(inlinePageScript(html), context);
  await new Promise(resolve => setTimeout(resolve, 0));
  return { get, requests };
}

describe('account-bound passkey registration page', () => {
  it.each(scriptTagVariants)('executes the actual registration page with $name', async ({ closingTag }) => {
    const html = fs.readFileSync(new URL('../web/setup-key.html', import.meta.url), 'utf8')
      .replaceAll('<script>', '<SCRIPT>').replaceAll('</script>', closingTag);
    const page = await registrationPage(true, 'Workshop Test Human', 'Platform passkey', true, html);
    expect(page.get('account-name').textContent).toBe('Workshop Test Human');
    expect(page.get('go').disabled).toBe(false);
    expect(page.requests.some(request => request.url.endsWith('/auth/account'))).toBe(true);
  });

  it('preserves noncredentialed cross-origin RP requests for legacy registration', async () => {
    const page = await registrationPage(false, '', 'Platform passkey', false);
    expect(page.get('go').disabled).toBe(false);
    expect(page.get('account-panel').hidden).toBe(true);
    expect(page.requests.filter(request => request.url.startsWith('http://localhost:4950')).every(request => request.credentials === 'same-origin')).toBe(true);
  });
  it('requires Google sign-in before offering passkey registration on the RP origin', async () => {
    const page = await registrationPage(false);
    expect(page.get('go').disabled).toBe(true);
    expect(page.get('sign-in').hidden).toBe(false);
    expect(page.get('sign-in').href).toBe('http://localhost:4950/auth/login?return_to=%2Fsetup-key.html');
  });

  it('uses provider profile text and renders authenticator labels without HTML injection', async () => {
    const unsafe = '<img src=x onerror=alert(1)>';
    const page = await registrationPage(true, unsafe, unsafe);
    expect(page.get('account-name').textContent).toBe(unsafe);
    expect(page.get('account-name').innerHTML).toBe('');
    expect(page.get('registered').children[0]?.textContent).toContain(unsafe);
    expect(page.get('registered').children[0]?.innerHTML).toBe('');
    expect(page.get('go').disabled).toBe(false);
    expect(page.requests.filter(request => request.url.endsWith('/auth/account') || request.url.includes('/api/rp/key')).every(request => request.credentials === 'include')).toBe(true);
  });
});

describe('named consent rendering', () => {
  it('escapes the provider name, omits private claims, and requires a passkey for an account without one', () => {
    const account: HumanAccount = {
      id: 'local-account-ref', provider: 'google', issuer: 'https://accounts.google.com',
      subject: 'private-google-subject', email: 'private-google-email@example.test', emailVerified: true,
      displayName: '<img src=x onerror=alert(1)>', authenticatedAt: '2026-09-08T12:00:00Z',
    };
    const flow: ConsentFlow = {
      challenge: {
        error: 'needs_authorization', message: 'Human consent required',
        authorizationUrl: 'http://localhost:4950/consent?resume_token=fixture',
        resumeToken: 'fixture-token-for-human-consent', expiresAt: 2_000_000_000,
        scopes: ['https://id.gs1.org/01/09506000134352'], display: { title: 'Approve grant', hint: ['link'] },
      },
      bindings: { agentDid: 'did:key:shopping-agent', audience: 'did:key:merchant', product: 'risotto', quantity: 2, productClass: 'https://id.gs1.org/01/09506000134352', cap: '50.00', currency: 'CHF', validHours: 48 },
      state: 'pending', createdAt: '2026-09-08T12:00:00Z',
    };
    const html = renderConsent(flow, {
      identity: { did: 'did:web:localhost%3A4950', kid: 'issuer-key', privateKeyBase64: '', publicKeyBase64: '' },
      agentDid: () => flow.bindings.agentDid, merchantDid: () => flow.bindings.audience,
      statusListUrl: 'http://localhost:4950/status-list', broadcast: () => {},
    }, 'http://localhost:4950', account);
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).not.toContain('<img src=x onerror=alert(1)>');
    expect(html).not.toContain(account.subject);
    expect(html).not.toContain(account.email);
    const bridge = JSON.parse(html.match(/<script id="consent-ui-data" type="application\/json">([^<]*)<\/script>/)![1]!);
    expect(bridge.capabilities).toHaveLength(1);
    expect(bridge.capabilities[0].scopes).toEqual([flow.bindings.productClass]);
    expect(bridge.capabilities[0].cedar).toBeUndefined();
    expect(html).toContain('slot="identity"');
    expect(html).toContain('slot="notice"');
    expect(html).toContain('data-valid-hours="48"');
    expect(bridge.webauthnRequired).toBe(true);
    expect(bridge.needsRegistration).toBe(true);
    expect(bridge.human.identitySource).toBe('identity-provider');
    expect(html).toContain('http://localhost:4950/setup-key.html');
    expect(html).toContain('Passkey approval required');
  });
});

describe('monitor request timeout recovery', () => {
  it('shows an unknown outcome and releases controls without automatically retrying an order', async () => {
    const monitor = await projector();
    monitor.state.responses['/api/act/order'] = Object.assign(new Error('Timed out'), { name: 'TimeoutError' });
    await monitor.get('btn-order').onclick!();
    expect(monitor.get('seal').textContent).toBe('CHECK OUTCOME');
    expect(monitor.get('verdict-code').textContent).toBe('REQUEST_OUTCOME_UNKNOWN');
    // A separate explicit operator action still works after the failure.
    monitor.state.responses['/api/act/discover'] = {};
    await monitor.get('btn-discover').onclick!();
    expect(monitor.state.requests.filter(url => url === '/api/act/order')).toHaveLength(1);
    expect(monitor.state.requests.filter(url => url === '/api/act/discover')).toHaveLength(1);
  });
});

describe('stage decision hierarchy', () => {
  it('keeps grant issuance separate from the merchant accepting an order', async () => {
    const p = await projector();
    p.emit('http://localhost:4950/api/rp/events', { type: 'consent.approved', index: 12 });
    expect(p.get('seal').textContent).toBe('GRANT APPROVED');
    expect(p.get('seal').className).not.toContain('ok');
    expect(p.get('decision-label').textContent).toBe('Human authorization');
    expect(p.get('decision-summary').textContent).toContain('still needs verification');
    p.emit('http://localhost:4950/api/rp/events', { type: 'revoke_done', index: 12, version: 2 });
    expect(p.get('seal').textContent).toBe('REVOKED');
    expect(p.get('decision-label').textContent).toBe('Human authorization');
    expect(p.get('decision-summary').textContent).toContain('Waiting for the next agent request');
  });

  it('renders idle readiness as neutral rather than a successful decision', async () => {
    const p = await projector();
    p.emit('/api/events', { type: 'reset' });
    expect(p.get('seal').className).toBe('seal ready');
    expect(p.get('decision-summary').textContent).toBe('Waiting for an agent request.');
  });
});

describe('decision processing feedback', () => {
  it('indicates processing only while a merchant request is unresolved', async () => {
    const p = await projector();
    expect(p.get('decision-stage').getAttribute('aria-busy')).toBe('false');
    p.emit('/api/events', { type: 'request', product: 'risotto', quantity: 2 });
    expect(p.get('seal').textContent).toBe('VERIFYING');
    expect(p.get('decision-stage').getAttribute('aria-busy')).toBe('true');
    expect(p.get('decision-icon').innerHTML).toContain('processing-ring');
    expect(p.get('decision-icon').innerHTML).toContain('processing-dot');
  });

  it.each([
    { event: { type: 'verdict', verdict: 'allowed', elapsedMs: 1,
      body: { ok: true, orderId: 'order-one', order: { name: 'Risotto', product: 'risotto', quantity: 2, unitPrice: '19.90', total: '39.80' } } },
      headline: 'AUTHORIZED', code: '' },
    { event: { type: 'verdict', verdict: 'denied', code: 'PRODUCT_OUT_OF_SCOPE', body: { detail: {} } },
      headline: 'REFUSED', code: 'PRODUCT_OUT_OF_SCOPE' },
    { event: { type: 'verdict', verdict: 'denied', code: 'SPEND_CAP_EXCEEDED', body: { message: 'Over the approved cap.' } },
      headline: 'REFUSED', code: 'SPEND_CAP_EXCEEDED' },
    { event: { type: 'verdict', verdict: 'denied', code: 'delegation_invalid', reason: 'Credential revoked.' },
      headline: 'DENIED', code: 'CREDENTIAL_REVOKED' },
    { event: challenge, headline: 'CONSENT NEEDED', code: 'NEEDS_AUTHORIZATION' },
  ])('reveals $headline / $code synchronously when its result arrives', async ({ event, headline, code }) => {
    const p = await projector();
    p.emit('/api/events', { type: 'request', product: 'risotto', quantity: 2 });
    p.emit('/api/events', event);
    // No timer or animation completion advances between the event and these
    // assertions: motion may decorate the result but must never delay it.
    expect(p.get('seal').textContent).toBe(headline);
    expect(p.get('verdict-code').textContent).toBe(code);
    expect(p.get('decision-stage').getAttribute('aria-busy')).toBe('false');
    expect(p.get('decision-icon').innerHTML).not.toContain('processing-ring');
  });

  it('updates consecutive refusals without holding or replaying an older result', async () => {
    const p = await projector();
    for (const code of ['PRODUCT_OUT_OF_SCOPE', 'SPEND_CAP_EXCEEDED', 'PRODUCT_OUT_OF_SCOPE']) {
      p.emit('/api/events', { type: 'request', product: 'risotto', quantity: 2 });
      expect(p.get('decision-stage').getAttribute('aria-busy')).toBe('true');
      p.emit('/api/events', { type: 'verdict', verdict: 'denied', code, body: { detail: {} } });
      expect(p.get('seal').textContent).toBe('REFUSED');
      expect(p.get('verdict-code').textContent).toBe(code);
      expect(p.get('decision-stage').getAttribute('aria-busy')).toBe('false');
    }
  });

  it('stops processing on an agent error without inventing a merchant verdict', async () => {
    const p = await projector();
    p.emit('/api/events', { type: 'request', product: 'risotto', quantity: 2 });
    p.emit('/api/events', { type: 'agent_error', message: 'Connection lost before receipt arrived.' });
    expect(p.get('decision-stage').getAttribute('aria-busy')).toBe('false');
    expect(p.get('seal').textContent).toBe('CHECK OUTCOME');
    expect(p.get('verdict-code').textContent).toBe('REQUEST_OUTCOME_UNKNOWN');
    expect(p.get('gates').classList.contains('idle')).toBe(true);
    expect(p.get('gates').children.every(gate => gate.className === 'gate')).toBe(true);
  });

  it('preserves a settled merchant decision when a later agent error is reported', async () => {
    const p = await projector();
    p.emit('/api/events', { type: 'request', product: 'olive-oil', quantity: 1 });
    p.emit('/api/events', { type: 'verdict', verdict: 'denied', code: 'PRODUCT_OUT_OF_SCOPE', body: { detail: {} } });
    p.emit('/api/events', { type: 'agent_error', message: 'Could not save the received denial.' });
    expect(p.get('decision-stage').getAttribute('aria-busy')).toBe('false');
    expect(p.get('seal').textContent).toBe('REFUSED');
    expect(p.get('verdict-code').textContent).toBe('PRODUCT_OUT_OF_SCOPE');
  });
});


describe('prominent decision codes', () => {
  it('matches the outcome log code and clears stale secondary notes on the next request', async () => {
    const p = await projector();
    p.emit('/api/events', { type: 'verdict', verdict: 'denied', code: 'PRODUCT_OUT_OF_SCOPE', body: { detail: {} }, checks: {} });
    expect(p.get('verdict-code').textContent).toBe('PRODUCT_OUT_OF_SCOPE');
    expect(p.get('log').children[0]!.children[0]!.innerHTML).toContain('PRODUCT_OUT_OF_SCOPE');
    p.emit('http://localhost:4950/api/rp/events', { type: 'revoke_done', index: 94, audit: 'unavailable' });
    expect(p.get('verdict-code').textContent).toBe('GRANT_REVOKED');
    expect(p.get('verdict-context').textContent).toBe('AUDIT EXPORT PENDING');
    p.emit('/api/events', { type: 'request', product: 'risotto', quantity: 2 });
    expect(p.get('verdict-code').textContent).toBe('');
    expect(p.get('verdict-context').textContent).toBe('');
  });
});
describe('audit loading feedback', () => {
  it('opens immediately while a checkpoint is pending, then renders the fresh report', async () => {
    const p = await projector();
    let finish!: (report: ReturnType<typeof auditFixture>) => void;
    p.state.responses['/api/act/audit'] = new Promise(resolve => { finish = resolve; });
    const loading = p.get('btn-audit').onclick!();
    expect(p.get('audit-overlay').classList.contains('on')).toBe(true);
    expect(p.get('audit-status').hidden).toBe(false);
    expect(p.get('audit-status').textContent).toContain('Creating the signed checkpoint');
    expect(p.get('audit-body').hidden).toBe(true);
    finish(auditFixture());
    await loading;
    expect(p.get('audit-status').hidden).toBe(true);
    expect(p.get('audit-body').hidden).toBe(false);
    expect(p.get('audit-ledger-id').textContent).toContain('test-ledger');
  });

  it('does not reopen an audit the presenter dismissed while it loaded', async () => {
    const p = await projector();
    let finish!: (report: ReturnType<typeof auditFixture>) => void;
    p.state.responses['/api/act/audit'] = new Promise(resolve => { finish = resolve; });
    const loading = p.get('btn-audit').onclick!();
    p.get('audit-close').onclick!();
    finish(auditFixture());
    await loading;
    expect(p.get('audit-overlay').classList.contains('on')).toBe(false);
    p.state.responses['/api/act/audit'] = new Promise(resolve => { finish = resolve; });
    const reopening = p.get('btn-audit').onclick!();
    expect(p.get('audit-ledger-id').textContent).toContain('test-ledger');
    expect(p.get('audit-body').hidden).toBe(false);
    finish(auditFixture());
    await reopening;
  });

  it('keeps errors visible in the open audit and permits a successful retry', async () => {
    const p = await projector();
    p.state.responses['/api/act/audit'] = { error: '<unavailable>' };
    await p.get('btn-audit').onclick!();
    expect(p.get('audit-overlay').classList.contains('on')).toBe(true);
    expect(p.get('audit-status').hidden).toBe(false);
    expect(p.get('audit-status').textContent).toContain('<unavailable>');
    expect(p.get('audit-status').innerHTML).not.toContain('<unavailable>');
    p.state.responses['/api/act/audit'] = auditFixture();
    await p.get('btn-audit').onclick!();
    expect(p.get('audit-status').hidden).toBe(true);
    expect(p.get('audit-table').innerHTML).toContain('table');
  });

  it('keeps the previous snapshot visible but labels it while refreshing', async () => {
    const p = await projector();
    p.state.responses['/api/act/audit'] = auditFixture();
    await p.get('btn-audit').onclick!();
    const previous = p.get('audit-table').innerHTML;
    let finish!: (report: ReturnType<typeof auditFixture>) => void;
    p.state.responses['/api/act/audit'] = new Promise(resolve => { finish = resolve; });
    const loading = p.get('btn-audit').onclick!();
    expect(p.get('audit-body').hidden).toBe(false);
    expect(p.get('audit-table').innerHTML).toBe(previous);
    expect(p.get('audit-status').textContent).toContain('previous snapshot');
    finish(auditFixture());
    await loading;
    expect(p.get('audit-status').hidden).toBe(true);
  });
});

function editableAuditFixture() {
  const base = auditFixture();
  return { ...base, checkpoint: { ...base.checkpoint, treeSize: 3, checkpointDigest: 'sha256:checkpoint' },
    entries: [
      { ...base.entries[0]!, seq: '0', eventType: 'tool.call.started', outcome: 'unknown' },
      { ...base.entries[0]!, seq: '1', eventType: 'tool.call.denied', outcome: 'denied' },
      { ...base.entries[0]!, seq: '2', eventType: 'tool.call.completed', outcome: 'succeeded' },
      { ...base.entries[0]!, seq: '3', eventType: 'tool.call.failed', outcome: 'failed', anchored: false },
    ] };
}
function editedAuditFixture() {
  return { target: { seq: '2', eventType: 'tool.call.completed', before: 'succeeded', after: 'failed' },
    chainBreaksAt: null, anchoredRoot: 'sha256:honest', tamperedRoot: 'sha256:edited',
    forgedReceiptVerifies: true, witnessStillBindsAnchoredRoot: true,
    reports: { honest: { chainIntegrity: { verdict: 'valid', reasonCodes: [] as string[] } },
      tampered: { chainIntegrity: { verdict: 'valid', reasonCodes: [] }, checkpointIntegrity: { verdict: 'invalid', reasonCodes: ['AUDIT_CHECKPOINT_RANGE_MISMATCH', 'AUDIT_MERKLE_PROOF_INVALID'] } } } };
}

describe('interactive audit editing', () => {
  it('opens the cached editor immediately, without forging or refreshing the checkpoint', async () => {
    const p = await projector();
    p.state.responses['/api/act/audit'] = editableAuditFixture();
    await p.get('btn-audit').onclick!();
    const before = p.state.requests.length;
    await p.get('btn-tamper').onclick!();
    expect(p.get('audit-editor').hidden).toBe(false);
    expect(p.get('audit-edit-entry').value).toBe('1');
    expect(p.get('audit-edit-entry').innerHTML).not.toContain('value="3"');
    expect(p.get('audit-edit-before').textContent).toBe('denied');
    expect(p.get('audit-edit-done').disabled).toBe(true);
    expect(p.state.requests.length).toBe(before);
    p.get('audit-edit-cancel').onclick!();
    expect(p.get('audit-editor').hidden).toBe(true);
    expect(p.state.requests.length).toBe(before);
  });

  it('shows loading immediately when T first needs a checkpoint and respects a dismissed overlay', async () => {
    const p = await projector();
    let finish!: (r: ReturnType<typeof editableAuditFixture>) => void;
    p.state.responses['/api/act/audit'] = new Promise(resolve => { finish = resolve; });
    const loading = p.get('btn-tamper').onclick!();
    expect(p.get('audit-overlay').classList.contains('on')).toBe(true);
    expect(p.get('audit-status').hidden).toBe(false);
    p.get('audit-close').onclick!();
    finish(editableAuditFixture());
    await loading;
    expect(p.get('audit-overlay').classList.contains('on')).toBe(false);
    expect(p.state.requests).not.toContain('/api/act/tamper');
  });

  it('submits the selected change against the shown checkpoint and paints pending feedback before completion', async () => {
    const p = await projector();
    p.state.responses['/api/act/audit'] = editableAuditFixture();
    await p.get('btn-audit').onclick!();
    await p.get('audit-edit').onclick!();
    p.get('audit-edit-entry').value = '2'; p.get('audit-edit-entry').onchange!();
    p.get('audit-edit-outcome').value = 'failed'; p.get('audit-edit-outcome').onchange!();
    expect(p.get('audit-edit-done').disabled).toBe(false);
    let finish!: (r: ReturnType<typeof editedAuditFixture>) => void;
    p.state.responses['/api/act/tamper'] = new Promise(resolve => { finish = resolve; });
    const done = p.get('audit-editor').onsubmit!({ preventDefault() {} });
    expect(p.get('audit-edit-feedback').textContent).toContain('Verifying');
    expect(p.get('audit-edit-done').disabled).toBe(true);
    await p.get('audit-editor').onsubmit!({ preventDefault() {} });
    expect(p.state.posts.filter(p => p.url === '/api/act/tamper')).toEqual([{ url: '/api/act/tamper', body: { sequence: '2', outcome: 'failed', checkpointDigest: 'sha256:checkpoint' } }]);
    finish(editedAuditFixture()); await done;
    expect(p.get('audit-editor').hidden).toBe(true);
    expect(p.get('audit-tamper-note').textContent).toContain('succeeded → failed');
    expect(p.get('audit-chain-note').textContent).not.toContain('broken');
    expect(p.get('audit-tamper').innerHTML).not.toContain('PREDECESSOR_MISMATCH');
    expect(p.get('audit-verdicts').innerHTML).toContain('CHECKPOINT_RANGE_MISMATCH');
    expect(p.get('audit-tamper').innerHTML).toContain('CHECKPOINT_RANGE_MISMATCH');
    expect(p.get('audit-tamper').innerHTML).not.toContain('CHECKPOINT_ROOT_MISMATCH');
  });

  it('rejects no-op submissions and keeps server errors visible beside the selected value', async () => {
    const p = await projector(); p.state.responses['/api/act/audit'] = editableAuditFixture();
    await p.get('btn-audit').onclick!(); await p.get('btn-tamper').onclick!();
    await p.get('audit-editor').onsubmit!({ preventDefault() {} });
    expect(p.state.requests).not.toContain('/api/act/tamper');
    p.get('audit-edit-outcome').value = 'succeeded'; p.get('audit-edit-outcome').onchange!();
    p.state.responses['/api/act/tamper'] = { error: '<checkpoint changed>' };
    await p.get('audit-editor').onsubmit!({ preventDefault() {} });
    expect(p.get('audit-editor').hidden).toBe(false);
    expect(p.get('audit-edit-feedback').textContent).toContain('<checkpoint changed>');
    expect(p.get('audit-edit-feedback').innerHTML).not.toContain('<checkpoint changed>');
    expect(p.get('audit-edit-outcome').value).toBe('succeeded');
    expect(p.get('audit-edit-done').disabled).toBe(false);
  });

  it('ignores global shortcuts while an input or select has focus', async () => {
    const p = await projector();
    const before = p.state.requests.length;
    for (const key of ['T', 'E', 'A', 'R', '1', 'K']) p.key(key, { closest: () => ({}) });
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(p.state.requests.length).toBe(before);
  });

  it('never offers unanchored or empty ledger edits', async () => {
    const p = await projector();
    const report = editableAuditFixture(); report.entries = [];
    p.state.responses['/api/act/audit'] = report;
    await p.get('btn-audit').onclick!(); await p.get('btn-tamper').onclick!();
    expect(p.get('audit-editor').hidden).toBe(true);
    expect(p.get('audit-status').textContent).toContain('No checkpointed entries');
    expect(p.state.requests).not.toContain('/api/act/tamper');
  });
});


describe('audit edit lifecycle and truthful event summaries', () => {
  it('shows verifier failures in the original bundle instead of assuming it passed', async () => {
    const p = await projector(); p.state.responses['/api/act/audit'] = editableAuditFixture();
    await p.get('btn-audit').onclick!(); await p.get('audit-edit').onclick!();
    p.get('audit-edit-entry').value = '2'; p.get('audit-edit-entry').onchange!();
    p.get('audit-edit-outcome').value = 'failed'; p.get('audit-edit-outcome').onchange!();
    const edited = editedAuditFixture();
    edited.reports.honest.chainIntegrity = { verdict: 'invalid', reasonCodes: ['AUDIT_PREDECESSOR_MISMATCH'] };
    p.state.responses['/api/act/tamper'] = edited;
    await p.get('audit-editor').onsubmit!({ preventDefault() {} });
    expect(p.get('audit-verdicts').innerHTML).toContain('honest bundle, same verifier · policy · keys: 0 valid · 0 indeterminate · 1 invalid');
    expect(p.get('audit-verdicts').innerHTML).not.toContain('· 0 invalid');
    p.state.responses['/api/act/export'] = { reports: edited.reports, components: [], manifestDigest: 'sha256:manifest', command: { honest: 'verify original' } };
    await p.get('btn-export').onclick!();
    expect(p.get('audit-export').innerHTML).not.toContain('expected exit 0');
    expect(p.get('audit-export').innerHTML.match(/expected exit 1/g)).toHaveLength(2);
  });

  it('queues T during checkpoint refresh instead of silently dropping it', async () => {
    const p = await projector(); p.state.responses['/api/act/audit'] = editableAuditFixture();
    await p.get('btn-audit').onclick!();
    let finish!: (r: ReturnType<typeof editableAuditFixture>) => void;
    p.state.responses['/api/act/audit'] = new Promise(resolve => { finish = resolve; });
    const refreshing = p.get('btn-audit').onclick!();
    p.key('T');
    expect(p.get('audit-status').textContent).toContain('editor');
    finish(editableAuditFixture()); await refreshing;
    expect(p.get('audit-editor').hidden).toBe(false);
    expect(p.state.requests).not.toContain('/api/act/tamper');
  });

  it('does not reopen an overlay closed while an edit verifies', async () => {
    const p = await projector(); p.state.responses['/api/act/audit'] = editableAuditFixture();
    await p.get('btn-audit').onclick!(); await p.get('btn-tamper').onclick!();
    p.get('audit-edit-entry').value = '2'; p.get('audit-edit-entry').onchange!();
    p.get('audit-edit-outcome').value = 'failed'; p.get('audit-edit-outcome').onchange!();
    let finish!: (r: ReturnType<typeof editedAuditFixture>) => void;
    p.state.responses['/api/act/tamper'] = new Promise(resolve => { finish = resolve; });
    const submitting = p.get('audit-editor').onsubmit!({ preventDefault() {} });
    p.get('audit-close').onclick!(); finish(editedAuditFixture()); await submitting;
    expect(p.get('audit-overlay').classList.contains('on')).toBe(false);
    expect(p.get('audit-editor').hidden).toBe(true);
  });

  it('does not invent a following chain link in a final-row tamper event', async () => {
    const p = await projector(); const edited = editedAuditFixture();
    p.emit('/api/events', { type: 'tamper', ...edited, forgedInclusion: false, rootsMatch: false, verdicts: edited.reports.tampered });
    const message = p.get('log').children[0]!.children[0]!.innerHTML;
    expect(message).toContain('no following chain link');
    expect(message).not.toContain('chain break at #');
  });
});

describe('console HTTP failure handling', () => {
  it.each([
    { status: 401, body: { error: 'admin_required' }, detail: 'admin_required' },
    { status: 403, body: { message: 'Origin refused' }, detail: 'Origin refused' },
    { status: 502, body: { error: 'RP reset refused' }, detail: 'RP reset refused' },
  ])('preserves the receipt and reports HTTP $status when reset is refused', async ({ status, body, detail }) => {
    const p = await projector();
    const previous = '<div>Previous signed receipt</div>';
    p.get('receipt').innerHTML = previous;
    p.state.statuses['/api/act/reset'] = status;
    p.state.responses['/api/act/reset'] = body;
    await p.get('btn-reset').onclick!();
    expect(p.get('receipt').innerHTML).toBe(previous);
    expect(p.get('log').children[0]!.children[0]!.innerHTML)
      .toContain(`reset failed: HTTP ${status}: ${detail}`);
    p.state.statuses['/api/act/reset'] = 200;
    p.state.responses['/api/act/reset'] = { success: true };
    await p.get('btn-reset').onclick!();
    expect(p.get('receipt').innerHTML).not.toBe(previous);
  });

  it('reports a proxy HTTP error even when its body is not JSON', async () => {
    const p = await projector();
    p.get('receipt').innerHTML = 'Preserved receipt';
    p.state.statuses['/api/act/reset'] = 503;
    p.state.responses['/api/act/reset'] = () => { throw new SyntaxError('Unexpected token <'); };
    await p.get('btn-reset').onclick!();
    expect(p.get('receipt').innerHTML).toBe('Preserved receipt');
    const message = p.get('log').children[0]!.children[0]!.innerHTML;
    expect(message).toContain('reset failed: HTTP 503');
    expect(message).not.toContain('Unexpected token');
  });

  it('preserves the receipt when a successful HTTP response contains an operation error', async () => {
    const p = await projector();
    p.get('receipt').innerHTML = 'Preserved receipt';
    p.state.responses['/api/act/reset'] = { error: 'reset_unavailable' };
    await p.get('btn-reset').onclick!();
    expect(p.get('receipt').innerHTML).toBe('Preserved receipt');
    expect(p.get('log').children[0]!.children[0]!.innerHTML)
      .toContain('reset failed: reset_unavailable');
  });

  it('accepts only the documented no-delegation 404 as an empty grant', async () => {
    const p = await projector();
    const endpoint = 'http://localhost:4950/api/rp/delegation';
    p.state.statuses[endpoint] = 404;
    p.state.responses[endpoint] = { error: 'no active delegation' };
    p.reconnect('http://localhost:4950/api/rp/events');
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(p.get('rp-pill').textContent).toContain('no active grant');
    const before = p.get('log').children.length;
    p.state.responses[endpoint] = { error: 'route not found' };
    p.reconnect('http://localhost:4950/api/rp/events');
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(p.get('log').children).toHaveLength(before + 1);
    expect(p.get('log').children[0]!.children[0]!.innerHTML)
      .toContain('HTTP 404: route not found');
  });

  it('reconciles a structured revocation refusal without leaving VERIFYING on screen', async () => {
    const p = await projector();
    p.state.responses['http://localhost:4950/api/rp/state'] = { grantIssued: true, activeIndex: 94, keyRequired: false, revoked: false, statusList: { version: 1 } };
    p.state.statuses['http://localhost:4950/api/rp/revoke'] = 403;
    p.state.responses['http://localhost:4950/api/rp/revoke'] = { error: 'admin_required', message: 'Operator authentication required' };
    p.emit('http://localhost:4950/api/rp/events', { type: 'revoke_start', index: 94 });
    await p.get('btn-revoke').onclick!();
    expect(p.get('verdict-code').textContent).toBe('REVOCATION_NOT_CONFIRMED');
    expect(p.get('seal').textContent).not.toBe('VERIFYING');
    expect(p.get('log').children[0]!.children[0]!.innerHTML)
      .toContain('HTTP 403: Operator authentication required');
  });
});

describe('merchant audit run reset', () => {
  const reset = { success: true, auditRunId: 'epoch-fresh', archivedAudit: { ledgerEpochId: 'epoch-old' } };

  it('shows an honest empty audit after reset without claiming broken chains, signatures or exportable evidence', async () => {
    const p = await projector(); p.emit('/api/events', { type: 'reset', ...reset });
    p.state.responses['/api/act/audit'] = {
      ...auditFixture(), entries: [], checkpoint: null, witness: null, tree: [], inclusions: [], chainIntact: false, allIncluded: false,
    };
    await p.get('btn-audit').onclick!();
    expect(p.get('audit-status').hidden).toBe(true);
    expect(p.get('audit-table').innerHTML).toContain('No merchant decisions');
    expect(p.get('audit-chain-note').textContent).toContain('0 entries');
    expect(p.get('audit-chain-note').textContent).not.toContain('BROKEN');
    expect(p.get('audit-cp').innerHTML).toContain('No checkpoint yet');
    expect(p.get('audit-cp').innerHTML).not.toContain('signed');
    expect(p.get('audit-edit').disabled).toBe(true);
    expect(p.get('audit-export').innerHTML).toBe('');
    await p.get('btn-export').onclick!();
    expect(p.state.requests).not.toContain('/api/act/export');
    expect(p.get('audit-status').textContent).toContain('No entries to export');
  });

  it('clears the merchant run only after HTTP success, including missed reset SSE, and retains RP history', async () => {
    const p = await projector();
    p.state.responses['/api/act/audit'] = editableAuditFixture();
    await p.get('btn-audit').onclick!();
    p.get('receipt').innerHTML = 'Old signed receipt';
    p.get('rp-log').innerHTML = 'Retained RP consent history';
    let finish!: (value: unknown) => void;
    p.state.responses['/api/act/reset'] = new Promise(resolve => { finish = resolve; });
    const pending = p.get('btn-reset').onclick!();
    expect(p.get('audit-table').innerHTML).toContain('table');
    expect(p.get('receipt').innerHTML).toBe('Old signed receipt');
    finish(reset); await pending;
    expect(p.get('audit-overlay').classList.contains('on')).toBe(false);
    expect(p.get('audit-table').innerHTML).toBe('');
    expect(p.get('audit-export').innerHTML).toBe('');
    expect(p.get('audit-root').textContent).toBe('');
    expect(p.get('audit-n').innerHTML).toContain('0');
    expect(p.get('receipt').innerHTML).not.toContain('Old signed receipt');
    expect(p.get('rp-log').innerHTML).toBe('Retained RP consent history');
    expect(p.get('verdict-code').textContent).toBe('NO_GRANT');
    p.state.responses['/api/act/audit'] = new Promise(resolve => { finish = resolve; });
    const fresh = p.get('btn-audit').onclick!();
    expect(p.get('audit-body').hidden).toBe(true);
    finish(editableAuditFixture()); await fresh;
  });

  it('retains a loaded audit when the server refuses reset', async () => {
    const p = await projector();
    p.state.responses['/api/act/audit'] = editableAuditFixture();
    await p.get('btn-audit').onclick!();
    const table = p.get('audit-table').innerHTML;
    p.state.statuses['/api/act/reset'] = 409;
    p.state.responses['/api/act/reset'] = { error: 'archive_failed' };
    await p.get('btn-reset').onclick!();
    expect(p.get('audit-table').innerHTML).toBe(table);
    expect(p.get('audit-overlay').classList.contains('on')).toBe(true);
  });

  it.each([{}, { success: false }])('requires explicit successful reset confirmation before clearing the run: %j', async result => {
    const p = await projector(); p.state.responses['/api/act/audit'] = editableAuditFixture();
    await p.get('btn-audit').onclick!();
    const table = p.get('audit-table').innerHTML;
    p.state.responses['/api/act/reset'] = result;
    await p.get('btn-reset').onclick!();
    expect(p.get('audit-table').innerHTML).toBe(table);
    expect(p.get('audit-overlay').classList.contains('on')).toBe(true);
    expect(p.get('log').children[0]!.children[0]!.innerHTML).toContain('did not confirm reset');
  });

  it('ignores an old checkpoint response after another monitor resets, without releasing a new action', async () => {
    const p = await projector();
    let oldFinish!: (value: unknown) => void, newFinish!: (value: unknown) => void;
    p.state.responses['/api/act/audit'] = new Promise(resolve => { oldFinish = resolve; });
    const old = p.get('btn-audit').onclick!();
    await new Promise(resolve => setTimeout(resolve, 0));
    p.emit('/api/events', { type: 'reset', ...reset });
    p.state.responses['/api/act/audit'] = new Promise(resolve => { newFinish = resolve; });
    const current = p.get('btn-audit').onclick!();
    oldFinish(editableAuditFixture()); await old;
    expect(p.get('audit-table').innerHTML).toBe('');
    expect(p.get('audit-body').hidden).toBe(true);
    expect(p.get('audit-overlay').getAttribute('aria-busy')).toBe('true');
    const report = editableAuditFixture(); report.ledger.ledgerEpochId = 'epoch-fresh';
    newFinish(report); await current;
    expect(p.get('audit-ledger-id').textContent).toContain('epoch-fresh');
  });

  it('discards an in-flight edit response from the archived run', async () => {
    const p = await projector(); p.state.responses['/api/act/audit'] = editableAuditFixture();
    await p.get('btn-audit').onclick!(); await p.get('audit-edit').onclick!();
    p.get('audit-edit-entry').value = '2'; p.get('audit-edit-entry').onchange!();
    p.get('audit-edit-outcome').value = 'failed'; p.get('audit-edit-outcome').onchange!();
    let finish!: (value: unknown) => void;
    p.state.responses['/api/act/tamper'] = new Promise(resolve => { finish = resolve; });
    const pending = p.get('audit-editor').onsubmit!({ preventDefault() {} });
    p.emit('/api/events', { type: 'reset', ...reset });
    finish(editedAuditFixture()); await pending;
    expect(p.get('audit-table').innerHTML).toBe('');
    expect(p.get('audit-editor').hidden).toBe(true);
    expect(p.get('audit-verdicts').innerHTML).toBe('');
    expect(p.get('audit-overlay').classList.contains('on')).toBe(false);
  });

  it('never exports a stale checkpoint if reset completes while export is acquiring it', async () => {
    const p = await projector(); let finish!: (value: unknown) => void;
    p.state.responses['/api/act/audit'] = new Promise(resolve => { finish = resolve; });
    const exporting = p.get('btn-export').onclick!();
    p.emit('/api/events', { type: 'reset', ...reset });
    finish(editableAuditFixture()); await exporting;
    expect(p.state.requests).not.toContain('/api/act/export');
    expect(p.get('audit-overlay').classList.contains('on')).toBe(false);
    expect(p.get('audit-table').innerHTML).toBe('');
  });

  it('ignores a delayed duplicate reset notification after a new request has begun', async () => {
    const p = await projector(); p.state.responses['/api/act/reset'] = reset;
    await p.get('btn-reset').onclick!();
    p.emit('/api/events', { type: 'request', product: 'risotto', quantity: 2 });
    expect(p.get('seal').textContent).toBe('VERIFYING');
    const lines = p.get('log').children.length;
    p.emit('/api/events', { type: 'reset', ...reset });
    expect(p.get('seal').textContent).toBe('VERIFYING');
    expect(p.get('log').children).toHaveLength(lines);
  });

  it('does not unlock or repaint a new action when the earlier reset HTTP response arrives after SSE', async () => {
    const p = await projector(); let finish!: (value: unknown) => void;
    p.state.responses['/api/act/reset'] = new Promise(resolve => { finish = resolve; });
    const resetting = p.get('btn-reset').onclick!();
    p.emit('/api/events', { type: 'reset', ...reset });
    let finishAudit!: (value: unknown) => void;
    p.state.responses['/api/act/audit'] = new Promise(resolve => { finishAudit = resolve; });
    const auditing = p.get('btn-audit').onclick!();
    finish(reset); await resetting;
    expect(p.get('audit-overlay').getAttribute('aria-busy')).toBe('true');
    expect(p.get('audit-overlay').classList.contains('on')).toBe(true);
    finishAudit(editableAuditFixture()); await auditing;
  });

  it.each(['resolve', 'reject'])('discards an old order %s after reset without replacing the new decision', async mode => {
    const p = await projector(); let finish!: (value: unknown) => void, fail!: (reason: Error) => void;
    p.state.responses['/api/act/order'] = new Promise((resolve, reject) => { finish = resolve; fail = reject; });
    const order = p.get('btn-order').onclick!();
    await new Promise(resolve => setTimeout(resolve, 0));
    p.emit('/api/events', { type: 'reset', ...reset });
    p.emit('/api/events', { type: 'request', product: 'risotto', quantity: 2 });
    const lines = p.get('log').children.length;
    if (mode === 'reject') fail(new Error('Old request failed'));
    else finish({ result: { content: [{ text: JSON.stringify({ error: 'needs_authorization', resumeToken: 'old-token' }) }] } });
    await order;
    expect(p.get('seal').textContent).toBe('VERIFYING');
    expect(p.get('log').children).toHaveLength(lines);
    expect(p.get('authorization-panel').hidden).toBe(true);
  });

  it('does not initiate revocation using a grant returned by an old pre-reset state read', async () => {
    const p = await projector(); const url = 'http://localhost:4950/api/rp/state';
    let finish!: (value: unknown) => void;
    p.state.responses[url] = new Promise(resolve => { finish = resolve; });
    const revoking = p.get('btn-revoke').onclick!();
    await new Promise(resolve => setTimeout(resolve, 0));
    delete p.state.responses[url];
    p.emit('/api/events', { type: 'reset', ...reset });
    finish({ grantIssued: true, activeIndex: 94, keyRequired: false }); await revoking;
    expect(p.state.posts.some(post => post.url.includes('/api/rp/revoke'))).toBe(false);
    expect(p.get('verdict-code').textContent).toBe('NO_GRANT');
    expect(p.get('btn-revoke').disabled).toBe(true);
  });

  it('does not repopulate the fresh audit count from an older merchant state response', async () => {
    const p = await projector(); let finish!: (value: unknown) => void;
    p.state.responses['/api/state'] = new Promise(resolve => { finish = resolve; });
    p.emit('/api/events', { type: 'audit', entries: 4, rootDigest: 'sha256:old', treeSize: 4 });
    await new Promise(resolve => setTimeout(resolve, 0));
    delete p.state.responses['/api/state'];
    p.emit('/api/events', { type: 'reset', ...reset });
    finish({ audit: { entries: 4, profile: 'AAP-2', delivery: 'sync', ledger: { ledgerId: 'old' } } });
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(p.get('audit-n').innerHTML).toBe('0 <small>ENTRIES</small>');
    expect(p.get('audit-root').textContent).toBe('');
  });
});
