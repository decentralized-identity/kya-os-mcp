import { createHash } from 'node:crypto';
import type { HumanAccount, PublicHumanAccount } from './human-identity.js';

export interface DemoConsentLink {
  consentRef: string;
  human: PublicHumanAccount;
  authentication: { method: 'webauthn'; credentialRef: string; intentHash: string; userVerified: boolean };
  approvedAt: string;
}
const reference = (value: string) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

/** Bind only a verified account and assertion to the signed grant metadata.
 * Provider tokens, email, raw subject and credential IDs stay at the RP.
 */
export function buildDemoConsent(account: HumanAccount, authentication: Record<string, unknown>, token: string): DemoConsentLink {
  const human = authentication['human'] as PublicHumanAccount | undefined;
  if (authentication['method'] !== 'webauthn' || human?.accountRef !== account.id || human.provider !== account.provider || human.issuer !== account.issuer
      || typeof authentication['credentialId'] !== 'string' || typeof authentication['intentHash'] !== 'string')
    throw new Error('Human account and verified passkey approval do not match.');
  return {
    consentRef: reference(token),
    human: { ...human },
    authentication: { method: 'webauthn', credentialRef: reference(authentication['credentialId']), intentHash: authentication['intentHash'], userVerified: authentication['userVerified'] === true },
    approvedAt: new Date().toISOString(),
  };
}
