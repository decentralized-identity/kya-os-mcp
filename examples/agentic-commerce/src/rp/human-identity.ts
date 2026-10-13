import type { Context } from 'hono';

/** Account claims from a server-verified identity provider response.
 * The stable account reference is local to this RP; a name is display data.
 */
export interface HumanAccount {
  id: string;
  provider: 'google';
  issuer: string;
  subject: string;
  displayName?: string;
  email?: string;
  emailVerified: boolean;
  authenticatedAt: string;
}

/** Narrow seam shared by registration and consent. Never use browser claims. */
export interface HumanIdentityAuth {
  readonly enabled: boolean;
  account(context: Context): HumanAccount | null;
}

export interface PublicHumanAccount {
  accountRef: string;
  provider: 'google';
  issuer: string;
  displayName?: string;
  identitySource: 'identity-provider';
}

export function publicHumanAccount(account: HumanAccount): PublicHumanAccount {
  return {
    accountRef: account.id,
    provider: account.provider,
    issuer: account.issuer,
    ...(account.displayName ? { displayName: account.displayName } : {}),
    identitySource: 'identity-provider',
  };
}
