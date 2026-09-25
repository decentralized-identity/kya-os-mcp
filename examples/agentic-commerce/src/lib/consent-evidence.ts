import { createHash } from 'node:crypto';
import { canonicalizeJSON, type DelegationCredential } from '@kya-os/mcp';

export const consentDigest = (value: unknown): `sha256:${string}` =>
  `sha256:${createHash('sha256').update(canonicalizeJSON(value)).digest('hex')}`;
export const tokenReference = (token: string): `sha256:${string}` =>
  `sha256:${createHash('sha256').update(token).digest('hex')}`;

/** Example profile inside the VC's existing signed metadata extension point. */
export interface ConsentEvidence {
  profile: 'urn:kya-os:example:agentic-commerce:consent:v1';
  consentRef: string;
  approvedAt: string;
  agentDid: string;
  audience: string;
  scopes: string[];
  cap: { maxAmount: string; currency: string; per: 'order' };
  validHours: number;
  authentication: 'rp-local-approval' | 'webauthn' | 'google+webauthn';
}

/** Call only after the VC's signature, issuer, audience and holder were verified. */
export function verifyConsentEvidence(vc: DelegationCredential, issuer: string): ConsentEvidence {
  const actualIssuer = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id;
  const d = vc.credentialSubject.delegation;
  const evidence = d.metadata?.['consent'] as ConsentEvidence | undefined;
  if (!evidence) throw new Error('CONSENT_REQUIRED: Missing signed human consent attestation.');
  const scopes = d.constraints.crisp?.scopes;
  if (actualIssuer !== issuer || evidence.profile !== 'urn:kya-os:example:agentic-commerce:consent:v1'
    || !/^sha256:[a-f0-9]{64}$/.test(evidence.consentRef ?? '')
    || evidence.agentDid !== vc.credentialSubject.id || evidence.audience !== d.constraints.audience
    || d.constraints.scopes?.length !== 1 || d.constraints.scopes[0] !== 'commerce.order'
    || !Array.isArray(evidence.scopes) || evidence.scopes.length !== 1 || scopes?.length !== 1
    || scopes[0]?.resource !== evidence.scopes[0] || scopes[0]?.matcher !== 'prefix'
    || evidence.cap?.per !== 'order' || scopes[0]?.constraints?.['per'] !== 'order'
    || evidence.cap.maxAmount !== scopes[0]?.constraints?.['maxAmount'] || evidence.cap.currency !== scopes[0]?.constraints?.['currency']
    || !Number.isFinite(Date.parse(evidence.approvedAt)) || Date.parse(evidence.approvedAt) > Date.now() + 120_000
    || !Number.isFinite(evidence.validHours) || evidence.validHours <= 0
    || !['rp-local-approval', 'webauthn', 'google+webauthn'].includes(evidence.authentication)
    || !d.constraints.notAfter || d.constraints.notAfter > Math.floor(Date.parse(evidence.approvedAt) / 1000) + evidence.validHours * 3600 + 1) {
    throw new Error('CONSENT_BINDING_MISMATCH: The signed consent attestation does not cover this grant.');
  }
  return evidence;
}
