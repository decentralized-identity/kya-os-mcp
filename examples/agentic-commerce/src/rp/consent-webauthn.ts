/** Optional issuance ceremony reusing the RP's registered FIDO2 credentials and
 * SimpleWebAuthn verifier. The challenge signs the complete issuance intent. */
import { createHash, randomBytes } from 'node:crypto';
import {
  publicHumanAccount,
  type HumanAccount,
  type PublicHumanAccount,
} from './human-identity.js';
import { canonicalizeJSON } from '@kya-os/mcp';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import {
  findAuthenticator,
  listAuthenticators,
  updateCounter,
} from './key/credential-store.js';
import {
  ConsentFlowError,
  type ConsentFields,
  type ConsentFlow,
} from './consent-store.js';

export class ConsentWebauthn {
  private readonly pending = new Map<
    string,
    {
      challenge: string;
      token: string;
      origin: string;
      expiresAt: number;
      grantDigest: string;
      accountId?: string;
      human?: PublicHumanAccount;
    }
  >();
  constructor(private readonly config: { rpID: string; now?: () => number }) {}
  private now() {
    return (this.config.now ?? Date.now)();
  }
  private grant(flow: ConsentFlow) {
    return {
      agentDid: flow.bindings.agentDid,
      audience: flow.bindings.audience,
      scopes: flow.approvedScopes ?? flow.challenge.scopes,
      cap: flow.bindings.cap,
      currency: flow.bindings.currency,
      validHours: flow.bindings.validHours,
    };
  }
  private grantDigest(flow: ConsentFlow): string {
    return createHash('sha256').update(canonicalizeJSON(this.grant(flow))).digest('hex');
  }
  async challenge(flow: ConsentFlow, origin: string, account?: HumanAccount) {
    const hostname = new URL(origin).hostname;
    // A configured parent RP ID may serve both the merchant and its auth host.
    // Assertion verification still pins the exact browser origin below.
    if (hostname !== this.config.rpID && !hostname.endsWith('.' + this.config.rpID))
      throw new ConsentFlowError(
        'consent_origin_mismatch',
        'Open the signed consent URL on the configured RP host to use this authenticator.',
      );
    for (const [key, value] of this.pending)
      if (value.expiresAt <= this.now()) this.pending.delete(key);
    const registered = listAuthenticators().filter(
      (key) => !account || key.accountId === account.id,
    );
    if (account && !registered.length)
      throw new ConsentFlowError(
        'consent_register_needed',
        'Register an authenticator for this signed-in Google account before approving the grant.',
      );
    const human = account ? publicHumanAccount(account) : undefined;
    const nonce = randomBytes(24).toString('base64url');
    const intent = {
      action: 'issue',
      ...this.grant(flow),
      resumeToken: flow.challenge.resumeToken,
      nonce,
      ts: this.now(),
      ...(human ? { human } : {}),
    };
    const digest = createHash('sha256')
      .update(canonicalizeJSON(intent))
      .digest();
    const options = await generateAuthenticationOptions({
      rpID: this.config.rpID,
      challenge: Uint8Array.from(digest),
      userVerification: 'discouraged',
      timeout: 60_000,
      allowCredentials: registered.map((a) => ({
        id: a.id,
        ...(a.transports ? { transports: a.transports as never } : {}),
      })),
    });
    this.pending.set(nonce, {
      challenge: options.challenge,
      token: flow.challenge.resumeToken,
      grantDigest: this.grantDigest(flow),
      origin,
      ...(account ? { accountId: account.id, human } : {}),
      expiresAt: Math.min(
        this.now() + 120_000,
        flow.challenge.expiresAt * 1000,
      ),
    });
    return { nonce, options, intent };
  }
  async verify(
    flow: ConsentFlow,
    fields: ConsentFields,
    origin: string,
    account?: HumanAccount,
  ): Promise<Record<string, unknown>> {
    const nonce = String(fields['webauthn_nonce'] ?? '');
    const pending = this.pending.get(nonce);
    this.pending.delete(nonce); // A failed or replayed assertion cannot reuse this ceremony.
    if (
      !pending ||
      pending.expiresAt <= this.now() ||
      pending.token !== flow.challenge.resumeToken ||
      pending.origin !== origin ||
      pending.accountId !== account?.id
    )
      throw new ConsentFlowError(
        'consent_assertion_expired',
        'Authenticator issuance intent is missing, expired, or belongs to another consent request.',
      );
    if (pending.grantDigest !== this.grantDigest(flow))
      throw new ConsentFlowError(
        'consent_assertion_mismatch',
        'The selected scopes or grant limits changed after passkey confirmation began.',
      );
    try {
      const response = JSON.parse(String(fields['webauthn_response'])) as {
        id?: string;
      };
      const registered = response.id
        ? findAuthenticator(response.id)
        : undefined;
      if (!registered) throw new Error('The authenticator is not registered.');
      if (account && registered.accountId !== account.id)
        throw new Error(
          'The authenticator belongs to a different account or has no account binding.',
        );
      const result = await verifyAuthenticationResponse({
        response: response as never,
        expectedChallenge: pending.challenge,
        expectedOrigin: pending.origin,
        expectedRPID: this.config.rpID,
        credential: {
          id: registered.id,
          publicKey: new Uint8Array(
            Buffer.from(registered.publicKey, 'base64url'),
          ),
          counter: registered.counter,
          ...(registered.transports
            ? { transports: registered.transports as never }
            : {}),
        },
        requireUserVerification: false,
      });
      if (!result.verified)
        throw new Error('The authenticator assertion did not verify.');
      updateCounter(registered.id, result.authenticationInfo.newCounter);
      return {
        method: 'webauthn',
        credentialId: registered.id,
        aaguid: registered.aaguid ?? null,
        label: registered.label,
        intentHash: pending.challenge,
        userVerified: result.authenticationInfo.userVerified,
        ...(pending.human ? { human: pending.human } : {}),
      };
    } catch (error) {
      throw new ConsentFlowError(
        'consent_assertion_rejected',
        `Authenticator assertion rejected: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
}
