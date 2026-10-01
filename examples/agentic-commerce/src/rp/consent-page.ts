/** Capability consent from @kya-os/consent, backed by the persisted challenge. */
import fs from 'node:fs';
import { generateConsentShell } from '@kya-os/consent/bundle/shell';
import { CONSENT_BUNDLE } from '@kya-os/consent/bundle/inline';
import type { ConsentConfig } from '@kya-os/consent/types';
import { merchantOrigin } from '../lib/wiring.js';
import {
  hasAuthenticator,
  listAuthenticators,
} from './key/credential-store.js';
import { publicHumanAccount, type HumanAccount } from './human-identity.js';
import type { ConsentFlow } from './consent-store.js';
import type { ConsentRoutesConfig } from './consent.js';

const CONSENT_CSS = fs.readFileSync(
  new URL('./consent.css', import.meta.url),
  'utf8',
);
const CONSENT_BROWSER = fs.readFileSync(
  new URL('./consent-browser.js', import.meta.url),
  'utf8',
);
const escapeHtml = (value: unknown) =>
  String(value).replace(
    /[&<>"']/g,
    (char) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[
        char
      ]!,
  );

export function renderConsent(
  flow: ConsentFlow,
  config: ConsentRoutesConfig,
  serverUrl: string,
  account?: HumanAccount,
): string {
  const b = flow.bindings;
  const webauthnRequired = Boolean(
    account || (config.consentWebauthn && hasAuthenticator()),
  );
  const needsRegistration = Boolean(
    account &&
      !listAuthenticators().some((key) => key.accountId === account.id),
  );
  const registrationUrl = new URL(
    '/setup-key.html',
    account ? serverUrl : merchantOrigin(),
  ).href;
  const gtin = new URL(b.productClass).pathname.split('/')[2] ?? b.productClass;
  const consentConfig: ConsentConfig = {
    branding: { primaryColor: '#0f172a', companyName: 'KYA-OS' },
    ui: {
      submitButtonText: 'Approve grant',
      cancelButtonText: 'Deny',
      autoClose: false,
    },
    terms: { required: false },
    expirationDays: b.validHours / 24,
  };
  // Keep the package's native form for the default no-JavaScript ceremony.
  let fallback =
    generateConsentShell({
      config: consentConfig,
      tool: 'place_order',
      scopes: [b.productClass],
      agentDid: b.agentDid,
      sessionId: flow.challenge.resumeToken,
      projectId: 'gs1-w3c-agentic-commerce',
      serverUrl,
      authMode: 'consent-only',
    })
      .match(/<noscript>[\s\S]*?<\/noscript>/)?.[0]
      ?.replace(
        /<h1>Permission Request<\/h1>\s*<p>[\s\S]*?<\/p>/,
        '<p>Approve the grant described above, or deny the request.</p>',
      )
      .replace(
        '<button type="submit">Allow Basic Access</button>',
        `<label class="scope-choice"><input type="checkbox" name="selected_scopes" value="${escapeHtml(JSON.stringify([b.productClass]))}" checked required><span>Allow orders for <code>${escapeHtml(b.productClass)}</code> within the limits above.</span></label><button type="submit">Approve grant</button><button type="submit" formaction="/consent/deny" formnovalidate class="deny">Deny</button>`,
      ) ?? '';
  if (webauthnRequired)
    fallback = fallback.replace(
      '<button type="submit">Approve grant</button>',
      '<p>Enable JavaScript to confirm this grant with your passkey.</p><button type="submit" disabled>Passkey approval required</button>',
    );
  const registration = needsRegistration || (config.consentWebauthn && !webauthnRequired)
    ? `<span><a id="register-passkey" href="${escapeHtml(registrationUrl)}" target="_blank" rel="noopener">Register passkey</a>, then return and reload.</span>`
    : '';
  const identity = account
    ? `<section slot="identity" class="identity-card" aria-label="Your account"><span class="identity-icon" aria-hidden="true">${escapeHtml((account.displayName || 'G').slice(0, 1))}</span><div><span class="small-label">YOU ARE AUTHORIZING</span><strong id="human-account-name">${escapeHtml(account.displayName || 'Google account')}</strong><span>Google account signed in · ${needsRegistration ? 'Register your passkey next' : 'Passkey confirmation next'}</span>${registration}</div><span class="identity-check" aria-label="Signed in">✓</span></section>`
    : `<section slot="identity" class="identity-card"><span class="identity-icon" aria-hidden="true">Y</span><div><span class="small-label">YOU ARE AUTHORIZING</span><strong>Your permission. Your boundaries.</strong><span>${webauthnRequired ? 'Confirm with your registered authenticator' : 'Approve the limits below to issue a grant'}</span>${registration}</div></section>`;
  const details = `<section slot="details" class="grant-details" aria-label="Grant boundaries">
    <div class="limits"><div><span class="small-label">MaxAmount · per order</span><strong class="amount">${escapeHtml(b.currency)} ${escapeHtml(b.cap)}</strong></div><div><span class="small-label">GRANT EXPIRES</span><strong id="grant-expiry" data-valid-hours="${escapeHtml(b.validHours)}">${escapeHtml(b.validHours)} hours <small>from approval</small></strong></div></div>
    <div class="merchant"><span class="small-label">ONLY AT DAL GIARDINO</span><code>${escapeHtml(b.audience)}</code></div>
    <details class="technical-details"><summary>View grant details</summary><dl><div><dt>Action</dt><dd><code>place_order</code></dd></div><div><dt>Agent DID</dt><dd><code>${escapeHtml(b.agentDid)}</code></dd></div><div><dt>Responsible Party · issuer</dt><dd><code>${escapeHtml(config.identity.did)}</code></dd></div><div><dt>Scope matcher</dt><dd>GS1 product-class prefix, including its lots and serial numbers.</dd></div></dl></details>
  </section>`;
  const feedback = `<div id="decision-feedback"><div id="decision-status" role="status" aria-live="polite"></div><button id="check-consent-status" type="button" hidden>Check decision status</button></div>`;
  // Override the package's default notice, showing only actionable feedback.
  const notice = `<div slot="notice" class="consent-feedback">${feedback}</div>`;
  const footer = `<footer slot="footer" class="card-footer"><span>✓ KYA-OS · Human authorization</span><span>Permission to order · No payment is made</span></footer>`;
  const data = JSON.stringify({
    fields: {
      tool: 'place_order',
      scopes: JSON.stringify([b.productClass]),
      agent_did: b.agentDid,
      session_id: flow.challenge.resumeToken,
    },
    capabilities: [
      {
        id: 'commerce.order',
        label: 'Place orders',
        description: `Uses place_order for GTIN ${gtin} and its lots or serial numbers.`,
        icon: 'package',
        riskLevel: 'medium',
        defaultOn: true,
        scopes: [b.productClass],
      },
    ],
    agentMetadata: {
      name: 'Acme Shopping Agent',
      did: b.agentDid,
      verified: false,
    },
    webauthnRequired,
    needsRegistration,
    ...(account ? { human: publicHumanAccount(account) } : {}),
  }).replace(/</g, '\\u003c');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Approve grant · KYA-OS</title><style>${CONSENT_CSS}</style></head><body>
    <main>
    <consent-capabilities-screen orgName="Dal Giardino" headlineVerb="order" description="Review what this agent can do on your behalf. You stay in control of the scope, limits and duration." submit-label="${webauthnRequired ? 'Approve grant with passkey' : 'Approve grant'}" cancel-label="Deny" theme="light">
      ${identity}${details}${notice}${footer}
    </consent-capabilities-screen>
    <section id="consent-result" hidden aria-labelledby="result-title"><span class="result-icon" aria-hidden="true">✓</span><h1 id="result-title" tabindex="-1">Grant issued</h1><div id="result-feedback"></div><button id="close-consent-window" type="button" hidden>Back to demo</button><a id="return-to-demo" href="${escapeHtml(merchantOrigin())}">Return to demo console →</a></section>
    <noscript><section class="native-summary"><h1>Acme Shopping Agent requests permission to order at Dal Giardino</h1>${identity.replace('slot="identity"', '')}<h2>Place orders for GTIN ${escapeHtml(gtin)}</h2><code>${escapeHtml(b.productClass)}</code>${details.replace('slot="details"', '')}</section></noscript>
    ${fallback}</main>
    <script type="module">${CONSENT_BUNDLE}</script><script id="consent-ui-data" type="application/json">${data}</script><script type="module">${CONSENT_BROWSER}</script></body></html>`;
}
