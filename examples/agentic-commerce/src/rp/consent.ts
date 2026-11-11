/** The RP renders the consent package; all grant data comes from the
 * merchant's persisted, signed challenge, never from editable browser fields. */
import { Hono, type Context } from 'hono';
import type { KeyedIdentity } from '../lib/wiring.js';
import { env, makeVcSigningFunction } from '../lib/wiring.js';
import { publicOrigin } from '../lib/public-origin.js';
import { ensureStatusList, readBit, STATUS_LIST_SIZE } from './statuslist.js';
import { issueAndActivate, nextDelegationIndex } from './issue.js';
import { hasAuthenticator } from './key/credential-store.js';
import { renderConsent } from './consent-page.js';
import { ConsentWebauthn } from './consent-webauthn.js';
import type { HumanIdentityAuth } from './human-identity.js';
import { buildDemoConsent } from './demo-consent.js';
import { tokenReference, type ConsentEvidence } from '../lib/consent-evidence.js';
import {
  ConsentFlowError,
  ConsentFlowStore,
  type ConsentFields,
  type ConsentFlow,
} from './consent-store.js';

export interface ConsentRoutesConfig {
  identity: KeyedIdentity;
  statusListUrl: string;
  /** Browser-facing RP origin, independent of an internal reverse-proxy URL. */
  authorizationOrigin?: string;
  rpID?: string;
  agentDid: () => string;
  merchantDid: () => string;
  store?: ConsentFlowStore;
  broadcast: (event: Record<string, unknown>) => void;
  consentWebauthn?: boolean;
  identityAuth?: HumanIdentityAuth;
  recordDecision?: () => Promise<unknown>;
}

async function parseFields(c: Context): Promise<ConsentFields> {
  const raw = await c.req.text();
  if (Buffer.byteLength(raw) > 16_384)
    throw new ConsentFlowError('consent_invalid', 'Consent form is too large.');
  if (c.req.header('Content-Type')?.includes('application/json'))
    return JSON.parse(raw) as ConsentFields;
  const form = await new Request(c.req.url, {
    method: 'POST',
    headers: { 'Content-Type': c.req.header('Content-Type') ?? '' },
    body: raw,
  }).formData();
  const fields: ConsentFields = {};
  for (const [key, value] of form) {
    if (key in fields)
      throw new ConsentFlowError(
        'consent_invalid',
        'Duplicate form fields are not accepted.',
      );
    fields[key] = value;
  }
  return fields;
}
export function createConsentRoutes(config: ConsentRoutesConfig): Hono {
  const app = new Hono();
  const origin = publicOrigin(config.authorizationOrigin ?? new URL(config.statusListUrl).origin);
  const store = config.store ?? new ConsentFlowStore({ authorizationOrigin: origin });
  const ceremony = new ConsentWebauthn({
    rpID: config.rpID ?? env('WEBAUTHN_RP_ID', 'localhost'),
  });
  const keyRequired = () =>
    Boolean(config.identityAuth?.enabled || (config.consentWebauthn && hasAuthenticator()));
  app.use('/consent*', async (c, next) => {
    c.header('Cache-Control', 'no-store');
    c.header('Referrer-Policy', 'same-origin');
    c.header('X-Frame-Options', 'DENY');
    c.header('X-Content-Type-Options', 'nosniff');
    if (
      c.req.method === 'POST' &&
      c.req.header('Origin') &&
      c.req.header('Origin') !== origin
    )
      return c.json(
        {
          error: 'consent_origin_mismatch',
          message: 'Consent must be submitted from this RP page.',
        },
        403,
      );
    await next();
  });
  app.onError((error, c) => {
    if (error instanceof ConsentFlowError)
      return c.json(
        { error: error.code, message: error.message },
        error.code.includes('mismatch') || error.code === 'consent_invalid' || error.code === 'consent_selection_invalid'
          ? 400
          : error.code === 'consent_expired'
            ? 410
            : 409,
      );
    if (error instanceof SyntaxError || error instanceof TypeError)
      return c.json(
        { error: 'consent_invalid', message: 'Malformed consent form.' },
        400,
      );
    return c.json(
      {
        error: 'consent_failed',
        message:
          'The RP could not issue this grant. Request a fresh authorization.',
      },
      500,
    );
  });
  function trusted(flow: ConsentFlow) {
    if (
      flow.bindings.agentDid !== config.agentDid() ||
      flow.bindings.audience !== config.merchantDid()
    )
      throw new ConsentFlowError(
        'consent_binding_mismatch',
        'This consent request belongs to another agent or merchant.',
      );
  }
  app.get('/consent', (c) => {
    const flow = store.requirePending(c.req.query('resume_token') ?? '');
    trusted(flow);
    const query = new URL(c.req.url).searchParams;
    const signed = new URL(flow.challenge.authorizationUrl).searchParams;
    if (
      query.size !== signed.size ||
      [...signed].some(
        ([key, value]) =>
          query.getAll(key).length !== 1 || query.get(key) !== value,
      )
    )
      throw new ConsentFlowError(
        'consent_binding_mismatch',
        'The authorization URL differs from the signed challenge.',
      );
    const account = config.identityAuth?.account(c) ?? undefined;
    if (config.identityAuth?.enabled && !account) {
      const url = new URL(c.req.url);
      return c.redirect(`/auth/login?return_to=${encodeURIComponent(url.pathname + url.search)}`, 302);
    }
    config.broadcast({
      type: 'consent.requested',
      authorizationUrl: flow.challenge.authorizationUrl,
      agentDid: flow.bindings.agentDid,
    });
    return c.html(renderConsent(flow, config, origin, account));
  });
  app.get('/consent/status', (c) => {
    c.header('Cache-Control', 'no-store');
    const flow = store.get(c.req.query('resume_token') ?? '');
    if (!flow) return c.json({ error: 'consent_missing' }, 404);
    return c.json({
      state:
        flow.challenge.expiresAt <= Math.floor(Date.now() / 1000) &&
        (flow.state === 'pending' || flow.state === 'issuing')
          ? 'expired'
          : flow.state,
      expiresAt: flow.challenge.expiresAt,
      credentialId: flow.credentialId,
      index: flow.index,
      demoConsent: flow.auditPayload?.['demoConsent'] ?? null,
      approvedScopes: flow.approvedScopes ?? null,
    });
  });
  app.post('/consent/webauthn/challenge', async (c) => {
    const account = config.identityAuth?.account(c) ?? undefined;
    if (config.identityAuth?.enabled && !account) return c.json({ error: 'signin_required', message: 'Sign in before approving this grant.' }, 401);
    if (!keyRequired())
      return c.json(
        {
          error: 'consent_webauthn_unavailable',
          message:
            'Click-wrap is available because issuance WebAuthn is disabled or no authenticator is registered.',
        },
        409,
      );
    const fields = await parseFields(c);
    const flow = store.requirePending(String(fields['session_id'] ?? ''));
    trusted(flow);
    store.validateFields(flow, fields);
    const approvedScopes = store.selectedScopes(flow, fields);
    return c.json(await ceremony.challenge({ ...flow, approvedScopes }, origin, account));
  });
  app.post('/consent/approve', async (c) => {
    const account = config.identityAuth?.account(c) ?? undefined;
    if (config.identityAuth?.enabled && !account) return c.json({ error: 'signin_required', message: 'Sign in before approving this grant.' }, 401);
    const fields = await parseFields(c);
    const token = String(fields['session_id'] ?? '');
    const flow = await store.approve(token, fields, async (flow) => {
      trusted(flow);
      const authentication = keyRequired()
        ? await ceremony.verify(flow, fields, origin, account)
        : undefined;
      const demoConsent = account && authentication
        ? buildDemoConsent(account, authentication, token)
        : undefined;
      const consent: ConsentEvidence = {
        profile: 'urn:kya-os:example:agentic-commerce:consent:v1', consentRef: tokenReference(token),
        approvedAt: new Date().toISOString(), agentDid: flow.bindings.agentDid, audience: flow.bindings.audience,
        scopes: flow.approvedScopes, cap: { maxAmount: flow.bindings.cap, currency: flow.bindings.currency, per: 'order' },
        validHours: flow.bindings.validHours,
        authentication: demoConsent ? 'google+webauthn' : authentication ? 'webauthn' : 'rp-local-approval',
      };
      const list = await ensureStatusList({
        identity: config.identity,
        signingFunction: makeVcSigningFunction(
          config.identity.privateKeyBase64,
        ),
        url: config.statusListUrl,
      });
      let index = nextDelegationIndex();
      while (index < STATUS_LIST_SIZE && (await readBit(list, index))) index++;
      if (index >= STATUS_LIST_SIZE)
        throw new ConsentFlowError(
          'consent_invalid',
          'No unused status-list index remains.',
        );
      const issued = await issueAndActivate({
        index,
        agentDid: flow.bindings.agentDid,
        audience: flow.bindings.audience,
        productClass: flow.approvedScopes[0],
        cap: flow.bindings.cap,
        currency: flow.bindings.currency,
        validHours: flow.bindings.validHours,
        identity: config.identity,
        statusListUrl: config.statusListUrl,
        ...(demoConsent ? { demoConsent } : {}),
        consent,
      });
      return { ...issued, ...(authentication ? { authentication } : {}) };
    });
    await config.recordDecision?.();
    config.broadcast({
      type: 'consent.approved',
      resumeToken: token,
      credentialId: flow.credentialId,
      index: flow.index,
      scope: flow.approvedScopes?.[0],
      approvedScopes: flow.approvedScopes,
      cap: flow.bindings.cap,
      currency: flow.bindings.currency,
    });
    if (c.req.header('Accept')?.includes('text/html'))
      return c.html(
        '<!doctype html><html lang="en"><title>Grant issued</title><body style="font:28px Arial;background:#f6f2e9;padding:60px"><h1>Grant issued</h1><p>Return to Claude and place an order within the approved scope and limits.</p></body></html>',
      );
    return c.json({
      success: true,
      delegation_id: flow.credentialId,
      index: flow.index,
    });
  });
  app.post('/consent/deny', async (c) => {
    const fields = await parseFields(c);
    const token = String(fields['session_id'] ?? '');
    const pending = store.requirePending(token);
    trusted(pending);
    const flow = store.deny(token, fields, config.identity.did);
    await config.recordDecision?.();
    config.broadcast({
      type: 'consent.denied',
      resumeToken: token,
      agentDid: flow.bindings.agentDid,
    });
    if (c.req.header('Accept')?.includes('text/html'))
      return c.html(
        '<!doctype html><html lang="en"><title>Grant denied</title><body style="font:28px Arial;background:#f6f2e9;padding:60px"><h1>Grant denied</h1><p>No credential was issued.</p></body></html>',
      );
    return c.json({
      success: true,
      state: 'denied',
      message: 'The Responsible Party denied this grant.',
    });
  });
  return app;
}
