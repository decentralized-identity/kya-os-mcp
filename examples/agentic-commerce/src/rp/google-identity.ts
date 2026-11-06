import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { Hono, type Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { bodyLimit } from 'hono/body-limit';
import { OAuth2Client, type TokenPayload } from 'google-auth-library';
import { writeJsonAtomic } from '../lib/atomic-json.js';
import { DATA_DIR } from '../lib/wiring.js';
import { publicHumanAccount, type HumanAccount, type HumanIdentityAuth } from './human-identity.js';

const GOOGLE_ISSUER = 'https://accounts.google.com';
const LOGIN_COOKIE = 'kya_google_login';
const SESSION_COOKIE = 'kya_human_session';
const LOGIN_TTL_MS = 5 * 60_000;
const SESSION_TTL_MS = 60 * 60_000;
const MAX_SESSIONS = 1000;
type PendingLogin = { nonce: string; returnTo: string; expiresAt: number; consumed?: boolean };
type AccountSession = { account: HumanAccount; expiresAt: number };
type AccountReference = { key: string; id: string };

export interface GoogleIdentityConfig {
  clientId?: string;
  origin: string;
  dataDir?: string;
  now?: () => number;
  /** Tests replace certificate transport on a real OAuth2Client, not JWT validation. */
  verifier?: Pick<OAuth2Client, 'verifyIdToken'>;
}

/** This private store holds only an opaque identity mapping. Provider tokens,
 * names, emails and raw subjects are never persisted. */
class AccountReferences {
  constructor(private readonly file: string) { this.read(); }

  private read(): AccountReference[] {
    if (!fs.existsSync(this.file)) return [];
    try {
      const data = JSON.parse(fs.readFileSync(this.file, 'utf8')) as { version?: unknown; accounts?: unknown };
      if (data.version !== 1 || !Array.isArray(data.accounts)) throw new Error();
      const keys = new Set<string>(); const ids = new Set<string>();
      for (const row of data.accounts) {
        if (!row || typeof row.key !== 'string' || !/^[a-f0-9]{64}$/.test(row.key) ||
          typeof row.id !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(row.id) ||
          keys.has(row.key) || ids.has(row.id)) throw new Error();
        keys.add(row.key); ids.add(row.id);
      }
      return data.accounts as AccountReference[];
    } catch {
      throw new Error('Google account store is invalid; restore the private account mapping before signing in.');
    }
  }

  idFor(subject: string): string {
    const key = createHash('sha256').update(JSON.stringify([GOOGLE_ISSUER, subject])).digest('hex');
    // Re-read before a synchronous update so a second instance cannot overwrite an earlier mapping.
    const accounts = this.read();
    const existing = accounts.find(account => account.key === key);
    if (existing) return existing.id;
    const id = randomUUID();
    writeJsonAtomic(this.file, { version: 1, accounts: [...accounts, { key, id }] });
    return id;
  }
}

function returnTarget(raw: string): string | null {
  if (raw.length > 4096 || /[\s\\#\u0000-\u001f\u007f]/u.test(raw)) return null;
  if (raw === '/setup-key.html' || raw === '/consent' || raw.startsWith('/consent?')) return raw;
  return null;
}

function displayClaim(value: unknown, limit: number): string | undefined {
  if (typeof value !== 'string') return undefined;
  const clean = value.replace(/[\u0000-\u001f\u007f]/gu, '').trim();
  return clean && clean.length <= limit ? clean : undefined;
}

function constantTimeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a); const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

/** Google proves control of its account. Its display name is a provider claim,
 * not a verified legal identity. Passkey registration binds the opaque local ID. */
export class GoogleIdentity implements HumanIdentityAuth {
  readonly enabled: boolean;
  readonly routes = new Hono();
  private readonly origin: string;
  private readonly host: string;
  private readonly secure: boolean;
  private readonly now: () => number;
  private readonly clientId: string;
  private readonly verifier: Pick<OAuth2Client, 'verifyIdToken'>;
  private readonly references?: AccountReferences;
  private readonly pending = new Map<string, PendingLogin>();
  private readonly sessions = new Map<string, AccountSession>();

  constructor(config: GoogleIdentityConfig) {
    const origin = new URL(config.origin);
    if (origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/' ||
      (origin.protocol !== 'https:' && !(origin.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname)))) {
      throw new Error('Google sign-in requires an HTTPS origin or an exact HTTP loopback origin.');
    }
    this.origin = origin.origin;
    this.host = origin.host;
    this.secure = origin.protocol === 'https:';
    this.now = config.now ?? Date.now;
    this.clientId = config.clientId?.trim() ?? '';
    this.enabled = this.clientId.length > 0;
    this.verifier = config.verifier ?? new OAuth2Client(this.clientId);
    if (this.enabled) this.references = new AccountReferences(path.join(config.dataDir ?? DATA_DIR, 'human-accounts.json'));
    this.mountRoutes();
  }

  account(context: Context): HumanAccount | null {
    if (!this.enabled || !this.isExpectedRequest(context)) return null;
    const token = getCookie(context, SESSION_COOKIE);
    if (!token) return null;
    const session = this.sessions.get(token);
    if (!session || session.expiresAt <= this.now()) {
      this.sessions.delete(token);
      return null;
    }
    return { ...session.account };
  }

  private isExpectedRequest(context: Context): boolean {
    const url = new URL(context.req.url);
    // A TLS proxy can forward HTTP while preserving the public host. Keep the
    // configured hostname and port binding; never trust forwarded headers.
    return url.host === this.host && (url.origin === this.origin
      || (this.secure && url.protocol === 'http:'));
  }

  private cookieOptions(maxAge: number) {
    return { path: '/', httpOnly: true, sameSite: 'Lax' as const, secure: this.secure, maxAge };
  }

  private clearCookie(context: Context, name: string) {
    deleteCookie(context, name, { path: '/', httpOnly: true, sameSite: 'Lax', secure: this.secure });
  }

  private prune() {
    const now = this.now();
    for (const [key, value] of this.pending) if (value.expiresAt <= now) this.pending.delete(key);
    for (const [key, value] of this.sessions) if (value.expiresAt <= now) this.sessions.delete(key);
  }

  private mountRoutes() {
    this.routes.use('/auth/*', async (c, next) => {
      c.header('Cache-Control', 'no-store');
      c.header('Referrer-Policy', 'no-referrer');
      c.header('X-Content-Type-Options', 'nosniff');
      c.header('X-Frame-Options', 'DENY');
      if (!this.isExpectedRequest(c)) return c.json({ error: 'wrong_origin' }, 403);
      if (c.req.method === 'POST' && c.req.header('Origin') !== this.origin) return c.json({ error: 'wrong_origin' }, 403);
      this.prune();
      await next();
    });

    this.routes.get('/auth/account', c => {
      const account = this.account(c);
      return c.json({ enabled: this.enabled, signedIn: !!account, account: account ? publicHumanAccount(account) : null });
    });

    this.routes.get('/auth/login', c => {
      if (!this.enabled) return c.html(this.loginPage(false), 503);
      const values = new URL(c.req.url).searchParams.getAll('return_to');
      const oldToken = getCookie(c, LOGIN_COOKIE);
      const oldTarget = oldToken ? this.pending.get(oldToken)?.returnTo : undefined;
      const returnTo = values.length <= 1 ? returnTarget(values[0] ?? oldTarget ?? '/setup-key.html') : null;
      if (!returnTo) return c.json({ error: 'invalid_return_target' }, 400);
      if (oldToken) this.pending.delete(oldToken);
      if (this.pending.size >= MAX_SESSIONS) return c.json({ error: 'sign_in_busy' }, 503);
      const token = randomBytes(32).toString('base64url');
      this.pending.set(token, { nonce: randomBytes(32).toString('base64url'), returnTo, expiresAt: this.now() + LOGIN_TTL_MS });
      setCookie(c, LOGIN_COOKIE, token, this.cookieOptions(LOGIN_TTL_MS / 1000));
      c.header('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
      // GIS requires the referring origin, including its documented HTTP localhost policy.
      c.header('Referrer-Policy', this.secure ? 'strict-origin-when-cross-origin' : 'no-referrer-when-downgrade');
      return c.html(this.loginPage(true));
    });

    this.routes.get('/auth/google/options', c => {
      if (!this.enabled) return c.json({ error: 'google_not_configured' }, 503);
      const pending = this.pending.get(getCookie(c, LOGIN_COOKIE) ?? '');
      if (!pending || pending.consumed) return c.json({ error: 'sign_in_expired' }, 401);
      return c.json({ clientId: this.clientId, nonce: pending.nonce });
    });

    this.routes.post('/auth/google/verify', bodyLimit({ maxSize: 16_384, onError: c => c.json({ error: 'invalid_credential' }, 413) }), async c => {
      if (!this.enabled) return c.json({ error: 'google_not_configured' }, 503);
      if (c.req.header('Content-Type')?.split(';')[0]?.trim() !== 'application/json') return c.json({ error: 'invalid_credential' }, 400);
      const token = getCookie(c, LOGIN_COOKIE) ?? '';
      const pending = this.pending.get(token);
      if (!pending || pending.consumed) return c.json({ error: 'sign_in_expired' }, 401);
      // Consume before awaiting cryptography/network so concurrent submissions cannot replay the nonce.
      // Keep only the consumed context until expiry so a reload can preserve its safe return target.
      pending.consumed = true;
      let payload: TokenPayload;
      try {
        const input = await c.req.json() as { credential?: unknown };
        if (typeof input.credential !== 'string' || input.credential.length > 16_000) throw new Error();
        const segments = input.credential.split('.');
        if (segments.length !== 3 || !segments[0]) throw new Error();
        const header = JSON.parse(Buffer.from(segments[0], 'base64url').toString('utf8')) as { alg?: unknown; kid?: unknown };
        if (header.alg !== 'RS256' || typeof header.kid !== 'string' || !header.kid || header.kid.length > 256) throw new Error();
        const verified = await this.verifier.verifyIdToken({ idToken: input.credential, audience: this.clientId });
        const claims = verified.getPayload();
        if (!claims || this.pending.get(token) !== pending || pending.expiresAt <= this.now() || !this.validClaims(claims, pending.nonce)) throw new Error();
        payload = claims;
      } catch {
        // Library errors can contain the raw token and claims; never return or log them.
        return c.json({ error: 'invalid_google_credential', message: 'Google sign-in could not be verified. Reload this page and try again.' }, 401);
      }
      if (this.sessions.size >= MAX_SESSIONS) return c.json({ error: 'sign_in_busy' }, 503);
      let account: HumanAccount;
      try {
        account = {
          id: this.references!.idFor(payload.sub), provider: 'google', issuer: GOOGLE_ISSUER, subject: payload.sub,
          displayName: displayClaim(payload.name, 200), email: displayClaim(payload.email, 320),
          emailVerified: payload.email_verified === true, authenticatedAt: new Date(this.now()).toISOString(),
        };
      } catch {
        return c.json({ error: 'account_store_unavailable', message: 'The private account mapping could not be saved. Sign-in was not completed.' }, 503);
      }
      const oldSession = getCookie(c, SESSION_COOKIE);
      if (oldSession) this.sessions.delete(oldSession);
      this.pending.delete(token);
      this.clearCookie(c, LOGIN_COOKIE);
      const session = randomBytes(32).toString('base64url');
      const expiresAt = Math.min(this.now() + SESSION_TTL_MS, payload.exp * 1000);
      this.sessions.set(session, { account, expiresAt });
      setCookie(c, SESSION_COOKIE, session, this.cookieOptions(Math.max(1, Math.floor((expiresAt - this.now()) / 1000))));
      return c.json({ success: true, account: publicHumanAccount(account), returnTo: pending.returnTo });
    });

    this.routes.post('/auth/logout', c => {
      this.sessions.delete(getCookie(c, SESSION_COOKIE) ?? '');
      this.pending.delete(getCookie(c, LOGIN_COOKIE) ?? '');
      this.clearCookie(c, SESSION_COOKIE); this.clearCookie(c, LOGIN_COOKIE);
      return c.json({ success: true });
    });
  }

  private validClaims(claims: TokenPayload, nonce: string): boolean {
    const now = this.now() / 1000;
    return [GOOGLE_ISSUER, 'accounts.google.com'].includes(claims.iss) &&
      claims.aud === this.clientId && (claims.azp === undefined || claims.azp === this.clientId) &&
      typeof claims.sub === 'string' && claims.sub.length > 0 && claims.sub.length <= 255 && !/[\s\u0000-\u001f\u007f]/u.test(claims.sub) &&
      Number.isSafeInteger(claims.exp) && claims.exp > now && Number.isSafeInteger(claims.iat) && claims.iat <= now + 60 &&
      typeof claims.nonce === 'string' && constantTimeEqual(claims.nonce, nonce);
  }

  private loginPage(enabled: boolean): string {
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in to the Responsible Party</title><style>
      :root{color-scheme:light;font-family:Inter,system-ui,sans-serif;color:#191816;background:#f6f2e9}body{margin:0;min-height:100vh;display:grid;place-items:center}main{box-sizing:border-box;width:min(660px,94vw);padding:48px;border:1px solid #d7d0c4;background:#fffcf6;border-radius:20px}small{letter-spacing:.12em;text-transform:uppercase}h1{font-size:clamp(32px,5vw,44px);line-height:1.1;margin:22px 0}p{font-size:19px;line-height:1.6;color:#56524a}#google-button{min-height:44px;margin:30px 0}#status{font-size:16px}a{color:inherit}footer{border-top:1px solid #d7d0c4;padding-top:20px;margin-top:32px;font-size:14px;line-height:1.6;color:#696359}
      </style></head><body><main><small>Responsible Party / Human identity</small><h1>${enabled ? 'Sign in before you connect your key.' : 'Google sign-in is not configured'}</h1><p>${enabled ? 'Your Google account identifies who is enrolling a passkey or approving this grant.' : 'Set GOOGLE_CLIENT_ID for this local demo to enable account sign-in.'}</p>${enabled ? '<div id="google-button"></div><p id="status" role="status" aria-live="polite">Loading Google sign-in…</p>' : ''}<footer>Google confirms control of your account. Your account name is supplied by Google; it is not a verified legal identity.<br>The RP does not request access to your mail, contacts or files.</footer></main>${enabled ? `<script>
      // The server already remembers return_to; keep its consent token out of Google's referrer.
      window.history.replaceState(null, '', '/auth/login');
      const status = document.getElementById('status');
      async function initializeGoogle() {
        try {
          const response = await fetch('/auth/google/options', { credentials: 'same-origin' });
          if (!response.ok) throw new Error('Your sign-in session expired. Reload this page to try again.');
          const options = await response.json();
          google.accounts.id.initialize({ client_id: options.clientId, nonce: options.nonce, auto_select: false, callback: async result => {
            status.textContent = 'Verifying your Google account…';
            try {
              const verified = await fetch('/auth/google/verify', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ credential: result.credential }) });
              const account = await verified.json();
              if (!verified.ok) throw new Error(account.message || 'Sign-in was not completed. Reload this page to try again.');
              status.textContent = 'Account verified. Returning to the RP…';
              window.location.assign(account.returnTo);
            } catch (error) { status.textContent = error.message || 'Sign-in was not completed. Reload this page to try again.'; }
          } });
          google.accounts.id.renderButton(document.getElementById('google-button'), { type: 'standard', theme: 'outline', size: 'large', text: 'signin_with', shape: 'pill' });
          status.textContent = 'Continue with the Google account you want to connect to this RP.';
        } catch (error) { status.textContent = error.message || 'Google sign-in is unavailable. Reload this page to try again.'; }
      }
      const script = document.createElement('script'); script.src = 'https://accounts.google.com/gsi/client'; script.async = true; script.defer = true;
      script.onload = initializeGoogle; script.onerror = () => { status.textContent = 'Google sign-in could not load. Check your connection, then reload this page.'; }; document.head.appendChild(script);
      </script>` : ''}</body></html>`;
  }
}
