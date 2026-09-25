/**
 * Key-gated revocation over WebAuthn (FIDO2). Two phases:
 *
 *   POST /api/rp/revoke/challenge → build the revocation intent, return
 *                                   navigator.credentials.get() options whose
 *                                   challenge is sha256(intent).
 *   POST /api/rp/revoke/execute   → verify the assertion against ANY registered
 *                                   authenticator AND the intent hash, then (only
 *                                   on success) publish the revocation.
 *
 * Registration (/api/rp/key/register/*) is gated by KEY_SETUP=1 and accepts
 * both roaming keys (a security key, a conference badge) and platform
 * authenticators (Touch ID) — whichever is in the operator's hand on stage.
 *
 * Fail-safe: no valid touch → no assertion → 403 → nothing published.
 */
import { randomBytes } from 'node:crypto';
import { Hono } from 'hono';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { buildRevocationIntent } from './revocation-intent.js';
import {
  findAuthenticator,
  listAuthenticators,
  removeAuthenticator,
  saveAuthenticator,
  updateCounter,
  writeRevocationRecord,
} from './credential-store.js';
import type { HumanAccount, HumanIdentityAuth } from '../human-identity.js';
import type { RevokeOutcome } from '../revoke.js';

export interface KeyRoutesConfig {
  rpID: string;
  origin: string;
  /** Identity-enabled setup lives on the RP origin; revocation keeps its console origin. */
  registrationOrigin?: string;
  /** Other first-party origins that may enrol an authenticator. The console is
   *  served by the merchant on a laptop and by a separate host once deployed, so
   *  enrolment must accept both rather than one or the other. */
  additionalRegistrationOrigins?: readonly string[];
  rpName: string;
  setupEnabled: boolean;
  identityAuth?: HumanIdentityAuth;
  statusListUrl: () => string;
  currentIndex: () => number | null;
  performRevoke: (index: number) => Promise<RevokeOutcome>;
}

const CHALLENGE_TTL_MS = 120_000;

export function createKeyRoutes(config: KeyRoutesConfig) {
  const app = new Hono<{ Variables: { account: HumanAccount | null } }>();
  const enrolmentOrigins = (): string[] => [
    ...new Set([
      config.registrationOrigin ?? config.origin,
      ...(config.additionalRegistrationOrigins ?? []),
    ]),
  ];
  app.use('/api/rp/key/*', async (c, next) => {
    const origin = c.req.header('Origin');
    if (c.req.method === 'POST' && origin && !enrolmentOrigins().includes(origin))
      return c.json({ error: 'key_setup_origin_mismatch' }, 403);
    const account = config.identityAuth?.enabled
      ? config.identityAuth.account(c)
      : null;
    if (config.identityAuth?.enabled && !account)
      return c.json(
        {
          error: 'identity_required',
          message:
            'Sign in with Google before registering or managing an authenticator.',
        },
        401,
      );
    c.set('account', account);
    await next();
  });
  const pendingRegistrations = new Map<
    string,
    { challenge: string; label: string; accountId?: string; expiresAt: number }
  >();
  const pendingAuth = new Map<
    string,
    { challengeB64u: string; intent: unknown; index: number; expiresAt: number }
  >();

  // ---- registration (KEY_SETUP=1) -----------------------------------------

  app.get('/api/rp/key/list', (c) => {
    const account = c.get('account');
    const registered = listAuthenticators().filter(
      (a) => !config.identityAuth?.enabled || a.accountId === account?.id,
    );
    return c.json({
      authenticators: registered.map((a) => ({
        idTail: a.id.slice(-6),
        label: a.label,
        transports: a.transports ?? [],
        registeredAt: a.registeredAt,
        ...(a.accountId ? { accountRef: a.accountId } : {}),
      })),
    });
  });

  app.post('/api/rp/key/register/options', async (c) => {
    if (!config.setupEnabled)
      return c.json(
        { error: 'key setup disabled — start the hub with KEY_SETUP=1' },
        403,
      );
    const body = await c.req
      .json()
      .catch(() => ({}) as Record<string, unknown>);
    const label = String(
      (body as Record<string, unknown>)['label'] ?? 'authenticator',
    ).slice(0, 40);
    const account = c.get('account');
    // Anonymous enrollments are separate users, even on the same authenticator.
    // Assertions look up the stored key by credential ID; only an authenticated
    // account has a stable user handle across registrations.
    const userID = account
      ? new TextEncoder().encode(account.id)
      : Uint8Array.from(randomBytes(32));
    if (!userID.length || userID.length > 64)
      return c.json({ error: 'invalid_account_reference' }, 500);
    const accountName =
      account?.displayName ??
      (account?.emailVerified ? account.email : undefined) ??
      'Google account';
    for (const [challenge, pending] of pendingRegistrations)
      if (pending.expiresAt <= Date.now())
        pendingRegistrations.delete(challenge);
    const options = await generateRegistrationOptions({
      rpName: config.rpName,
      rpID: config.rpID,
      userID,
      userName: account ? accountName : 'responsible-party',
      ...(account ? { userDisplayName: accountName } : {}),
      attestationType: 'none',
      // No attachment preference: a roaming key (badge, YubiKey) or the laptop's
      // platform authenticator (Touch ID) are both fine. Presence, not UV.
      authenticatorSelection: {
        userVerification: 'discouraged',
        residentKey: 'discouraged',
      },
      excludeCredentials: listAuthenticators()
        .filter((a) => !account || a.accountId === account.id)
        .map((a) => ({
          id: a.id,
          ...(a.transports ? { transports: a.transports as never } : {}),
        })),
    });
    pendingRegistrations.set(options.challenge, {
      challenge: options.challenge,
      label,
      ...(account ? { accountId: account.id } : {}),
      expiresAt: Date.now() + CHALLENGE_TTL_MS,
    });
    return c.json(options);
  });

  app.post('/api/rp/key/register/verify', async (c) => {
    if (!config.setupEnabled)
      return c.json({ error: 'key setup disabled' }, 403);
    const response = await c.req.json().catch(() => null);
    let challenge: string;
    try {
      // The browser challenge is only a lookup key. The verifier must match the
      // original server challenge and origin before any key is persisted.
      const clientData = JSON.parse(
        Buffer.from(
          response?.response?.clientDataJSON ?? '',
          'base64url',
        ).toString('utf8'),
      ) as { challenge?: unknown };
      if (typeof clientData.challenge !== 'string')
        throw new Error('missing challenge');
      challenge = clientData.challenge;
    } catch {
      return c.json({ error: 'invalid registration response' }, 400);
    }
    const pending = pendingRegistrations.get(challenge);
    pendingRegistrations.delete(challenge); // consume before asynchronous verification
    if (!pending || pending.expiresAt <= Date.now())
      return c.json({ error: 'registration expired or unknown' }, 400);
    const account = c.get('account');
    if (pending.accountId !== account?.id)
      return c.json(
        {
          error: 'registration_account_changed',
          message: 'Sign in with the same account that started registration.',
        },
        403,
      );
    try {
      const verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: pending.challenge,
        expectedOrigin: enrolmentOrigins(),
        expectedRPID: config.rpID,
        requireUserVerification: false,
      });
      if (!verification.verified || !verification.registrationInfo)
        return c.json({ verified: false }, 400);
      const { credential, aaguid } = verification.registrationInfo;
      if (findAuthenticator(credential.id))
        return c.json({ error: 'authenticator_already_registered' }, 409);
      saveAuthenticator({
        id: credential.id,
        publicKey: Buffer.from(credential.publicKey).toString('base64url'),
        counter: credential.counter,
        ...(credential.transports ? { transports: credential.transports } : {}),
        ...(aaguid ? { aaguid } : {}),
        ...(pending.accountId ? { accountId: pending.accountId } : {}),
        label: pending.label,
        registeredAt: new Date().toISOString(),
      });
      return c.json({
        verified: true,
        idTail: credential.id.slice(-6),
        aaguid: aaguid ?? null,
        ...(pending.accountId ? { accountRef: pending.accountId } : {}),
      });
    } catch (err) {
      return c.json(
        {
          verified: false,
          error: err instanceof Error ? err.message : String(err),
        },
        400,
      );
    }
  });

  app.post('/api/rp/key/remove', async (c) => {
    if (!config.setupEnabled)
      return c.json({ error: 'key setup disabled' }, 403);
    const body = await c.req
      .json()
      .catch(() => ({}) as Record<string, unknown>);
    const idTail = String((body as Record<string, unknown>)['idTail'] ?? '');
    if (!idTail)
      return c.json({ error: 'an explicit authenticator id is required' }, 400);
    const account = c.get('account');
    const matches = listAuthenticators().filter(
      (a) =>
        a.id.endsWith(idTail) &&
        (!config.identityAuth?.enabled || a.accountId === account?.id),
    );
    if (matches.length > 1)
      return c.json({ error: 'authenticator id is ambiguous' }, 409);
    const match = matches[0];
    if (!match) return c.json({ error: 'unknown authenticator' }, 404);
    removeAuthenticator(match.id);
    return c.json({ removed: idTail });
  });

  // ---- revocation, phase 1: challenge -------------------------------------

  app.post('/api/rp/revoke/challenge', async (c) => {
    const index = config.currentIndex();
    if (index === null)
      return c.json({ error: 'no_active_grant', message: 'There is no active grant to revoke. Approve a grant first.' }, 409);
    const registered = listAuthenticators();
    if (registered.length === 0)
      return c.json(
        {
          error:
            'no authenticator registered — open /setup-key.html with KEY_SETUP=1',
        },
        400,
      );
    const nonce = randomBytes(16).toString('base64url');
    const built = buildRevocationIntent({
      statusListUrl: config.statusListUrl(),
      index,
      nonce,
      ts: Date.now(),
    });
    const options = await generateAuthenticationOptions({
      rpID: config.rpID,
      allowCredentials: registered.map((a) => ({
        id: a.id,
        ...(a.transports ? { transports: a.transports as never } : {}),
      })),
      challenge: built.digest, // the challenge IS sha256(intent)
      userVerification: 'discouraged',
      timeout: 60_000,
    });
    pendingAuth.set(nonce, {
      challengeB64u: built.challengeB64u,
      intent: built.intent,
      index,
      expiresAt: Date.now() + CHALLENGE_TTL_MS,
    });
    return c.json({
      nonce,
      options,
      intentPreview: {
        index,
        challengeHead: built.challengeB64u.slice(0, 8),
        statusListUrl: config.statusListUrl(),
      },
    });
  });

  // ---- revocation, phase 2: execute (assertion required) ------------------

  app.post('/api/rp/revoke/execute', async (c) => {
    const body = await c.req
      .json()
      .catch(() => ({}) as Record<string, unknown>);
    const nonce = String(body['nonce'] ?? '');
    const pending = pendingAuth.get(nonce);
    if (!pending || Date.now() > pending.expiresAt) {
      pendingAuth.delete(nonce);
      return c.json(
        { error: 'challenge expired or unknown — nothing revoked' },
        400,
      );
    }
    const response = body['response'] as { id?: string } | undefined;
    const cred = response?.id ? findAuthenticator(response.id) : undefined;
    if (!cred)
      return c.json(
        {
          error:
            'assertion is not from a registered authenticator — nothing revoked',
        },
        403,
      );

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: body['response'] as never,
        expectedChallenge: pending.challengeB64u,
        expectedOrigin: config.origin,
        expectedRPID: config.rpID,
        credential: {
          id: cred.id,
          publicKey: new Uint8Array(Buffer.from(cred.publicKey, 'base64url')),
          counter: cred.counter,
          ...(cred.transports ? { transports: cred.transports as never } : {}),
        },
        requireUserVerification: false,
      });
    } catch (err) {
      return c.json(
        {
          error: `assertion rejected: ${err instanceof Error ? err.message : String(err)}`,
        },
        403,
      );
    }
    if (!verification.verified)
      return c.json(
        { error: 'assertion did not verify — nothing revoked' },
        403,
      );

    // Success: consume the nonce (single use), advance the counter, write the
    // hardware-attested record, THEN publish the revocation.
    pendingAuth.delete(nonce);
    updateCounter(cred.id, verification.authenticationInfo.newCounter);
    const recordFile = writeRevocationRecord({
      intent: pending.intent,
      verifiedAt: new Date().toISOString(),
      authenticator: {
        label: cred.label,
        idTail: cred.id.slice(-6),
        aaguid: cred.aaguid ?? null,
      },
      newCounter: verification.authenticationInfo.newCounter,
      userVerified: verification.authenticationInfo.userVerified,
    });
    const result = await config.performRevoke(pending.index);
    return c.json({
      ...result,
      hardwareAttested: true,
      authenticator: cred.label,
      idTail: cred.id.slice(-6),
      recordFile,
    });
  });

  return app;
}
