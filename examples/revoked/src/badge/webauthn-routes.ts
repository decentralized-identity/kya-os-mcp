/**
 * Badge-gated revocation over WebAuthn (FIDO2). Two phases:
 *
 *   POST /api/revoke/challenge  → build the revocation intent, return
 *                                 navigator.credentials.get() options whose
 *                                 challenge is sha256(intent).
 *   POST /api/revoke/execute    → verify the assertion against the registered
 *                                 badge AND the intent hash, then (only on
 *                                 success) publish the on-chain revocation.
 *
 * Registration (/api/badge/register/*) is one-time, gated by BADGE_SETUP=1.
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
  hasBadgeCredential,
  loadBadgeCredential,
  saveBadgeCredential,
  updateCounter,
  writeRevocationRecord,
} from './credential-store.js';

export interface RevokeResult {
  resourceId: string | undefined;
  txHash: string | undefined;
  visibleMs: number;
  totalMs: number;
}

export interface BadgeRoutesConfig {
  rpID: string;
  origin: string;
  rpName: string;
  setupEnabled: boolean;
  statusListUrl: () => string;
  currentIndex: () => number;
  performRevoke: (index: number) => Promise<RevokeResult>;
}

const OPERATOR_USER = new TextEncoder().encode('revoked-operator');
const CHALLENGE_TTL_MS = 120_000;

export function createBadgeRoutes(config: BadgeRoutesConfig): Hono {
  const app = new Hono();

  // one pending challenge at a time is enough for a single operator
  let pendingRegChallenge: string | null = null;
  const pendingAuth = new Map<string, { challengeB64u: string; intent: unknown; index: number; expiresAt: number }>();

  // ---- registration (one-time, BADGE_SETUP=1) -----------------------------

  app.post('/api/badge/register/options', async (c) => {
    if (!config.setupEnabled) return c.json({ error: 'badge setup disabled' }, 403);
    const options = await generateRegistrationOptions({
      rpName: config.rpName,
      rpID: config.rpID,
      userID: OPERATOR_USER,
      userName: 'operator',
      attestationType: 'none',
      authenticatorSelection: {
        authenticatorAttachment: 'cross-platform', // the external badge, not laptop Touch ID
        userVerification: 'discouraged',           // demonstrate PRESENCE (touch), don't gamble on PIN/UV
        residentKey: 'discouraged',
      },
    });
    pendingRegChallenge = options.challenge;
    return c.json(options);
  });

  app.post('/api/badge/register/verify', async (c) => {
    if (!config.setupEnabled) return c.json({ error: 'badge setup disabled' }, 403);
    if (!pendingRegChallenge) return c.json({ error: 'no registration in progress' }, 400);
    const response = await c.req.json();
    try {
      const verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: pendingRegChallenge,
        expectedOrigin: config.origin,
        expectedRPID: config.rpID,
        // Presence (touch), not UV (PIN/biometric) — matches the 'discouraged'
        // userVerification we registered with. Without this, the verify demands
        // UV and rejects a touch-only badge attestation (the DC34 badge does
        // presence, not UV).
        requireUserVerification: false,
      });
      if (!verification.verified || !verification.registrationInfo) {
        return c.json({ verified: false }, 400);
      }
      const { credential, aaguid } = verification.registrationInfo;
      saveBadgeCredential({
        id: credential.id,
        publicKey: Buffer.from(credential.publicKey).toString('base64url'),
        counter: credential.counter,
        ...(credential.transports ? { transports: credential.transports } : {}),
        ...(aaguid ? { aaguid } : {}),
        registeredAt: new Date().toISOString(),
      });
      pendingRegChallenge = null;
      return c.json({ verified: true, credIdTail: credential.id.slice(-6), aaguid: aaguid ?? null });
    } catch (err) {
      return c.json({ verified: false, error: err instanceof Error ? err.message : String(err) }, 400);
    }
  });

  // ---- revocation, phase 1: challenge -------------------------------------

  app.post('/api/revoke/challenge', async (c) => {
    const cred = loadBadgeCredential();
    if (!cred) return c.json({ error: 'no badge registered — run setup first' }, 400);

    const index = config.currentIndex();
    const nonce = randomBytes(16).toString('base64url');
    const built = buildRevocationIntent({
      statusListUrl: config.statusListUrl(),
      index,
      nonce,
      ts: Date.now(),
    });

    const options = await generateAuthenticationOptions({
      rpID: config.rpID,
      allowCredentials: [{
        id: cred.id,
        ...(cred.transports ? { transports: cred.transports as never } : {}),
      }],
      challenge: built.digest,        // challenge IS sha256(intent)
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
      intentPreview: { index, challengeHead: built.challengeB64u.slice(0, 8) },
    });
  });

  // ---- revocation, phase 2: execute (assertion required) ------------------

  app.post('/api/revoke/execute', async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const nonce = String(body['nonce'] ?? '');
    const pending = pendingAuth.get(nonce);
    if (!pending || Date.now() > pending.expiresAt) {
      pendingAuth.delete(nonce);
      return c.json({ error: 'challenge expired or unknown — nothing revoked' }, 400);
    }
    const cred = loadBadgeCredential();
    if (!cred) return c.json({ error: 'no badge registered' }, 400);

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: body['response'],
        expectedChallenge: pending.challengeB64u,
        expectedOrigin: config.origin,
        expectedRPID: config.rpID,
        credential: {
          id: cred.id,
          publicKey: new Uint8Array(Buffer.from(cred.publicKey, 'base64url')),
          counter: cred.counter,
          ...(cred.transports ? { transports: cred.transports as never } : {}),
        },
        requireUserVerification: false, // presence (touch), not UV — see registration
      });
    } catch (err) {
      return c.json({ error: `badge assertion rejected: ${err instanceof Error ? err.message : String(err)}` }, 403);
    }

    if (!verification.verified) {
      return c.json({ error: 'badge assertion did not verify — nothing revoked' }, 403);
    }

    // Success: consume the nonce (single use), advance the counter, write the
    // hardware-attested record, THEN publish the on-chain revocation.
    pendingAuth.delete(nonce);
    updateCounter(verification.authenticationInfo.newCounter);

    const recordFile = writeRevocationRecord({
      intent: pending.intent,
      verifiedAt: new Date().toISOString(),
      credentialIdTail: cred.id.slice(-6),
      aaguid: cred.aaguid ?? null,
      newCounter: verification.authenticationInfo.newCounter,
      userVerified: verification.authenticationInfo.userVerified,
    });

    const result = await config.performRevoke(pending.index);
    return c.json({
      ...result,
      index: pending.index,
      hardwareAttested: true,
      credentialIdTail: cred.id.slice(-6),
      aaguid: cred.aaguid ?? null,
      recordFile,
    });
  });

  return app;
}
