import { afterAll, beforeAll, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { NodeCryptoProvider, generateDidKeyFromBase64, type DelegationCredential } from '@kya-os/mcp';
import { verifyConsentEvidence, tokenReference, type ConsentEvidence } from '../src/lib/consent-evidence.js';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'consent-evidence-'));
let credential: DelegationCredential, issuer: string;
let issue: typeof import('../src/rp/issue.js');
beforeAll(async () => {
  process.env['DEMO_VAR_DIR'] = dir;
  const key = await new NodeCryptoProvider().generateKeyPair();
  issuer = generateDidKeyFromBase64(key.publicKey);
  issue = await import('../src/rp/issue.js');
  const consent: ConsentEvidence = { profile: 'urn:kya-os:example:agentic-commerce:consent:v1', consentRef: tokenReference('test-flow'), approvedAt: new Date().toISOString(),
    agentDid: issuer, audience: 'did:key:merchant', scopes: ['https://id.gs1.org/01/09506000134352'], cap: { maxAmount: '50.00', currency: 'CHF', per: 'order' }, validHours: 48, authentication: 'rp-local-approval' };
  credential = await issue.issueDelegation({ index: 94, agentDid: issuer, audience: consent.audience,
    productClass: consent.scopes[0], cap: consent.cap.maxAmount, currency: consent.cap.currency, validHours: 48, consent,
    identity: { did: issuer, kid: `${issuer}#${issuer.slice(8)}`, privateKeyBase64: key.privateKey, publicKeyBase64: key.publicKey } });
});
afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));
it('recognizes the exact RP-attested scope and cap', () => {
  expect(verifyConsentEvidence(credential, issuer).consentRef).toBe(tokenReference('test-flow'));
});
it.each(['subject', 'audience', 'scope', 'cap', 'currency', 'expiry', 'extra-tool', 'future-approval', 'method', 'missing'] as const)('refuses a consent attestation inconsistent with the %s', attack => {
  const vc = structuredClone(credential);
  const delegation = vc.credentialSubject.delegation;
  const consent = delegation.metadata!['consent'] as ConsentEvidence;
  if (attack === 'subject') vc.credentialSubject.id = 'did:key:other';
  if (attack === 'audience') delegation.constraints.audience = 'did:key:other';
  if (attack === 'scope') consent.scopes = ['https://id.gs1.org/01/09506000134369'];
  if (attack === 'cap') consent.cap.maxAmount = '500.00';
  if (attack === 'currency') consent.cap.currency = 'USD';
  if (attack === 'expiry') delegation.constraints.notAfter! += 3600;
  if (attack === 'extra-tool') delegation.constraints.scopes!.push('payments.execute');
  if (attack === 'future-approval') consent.approvedAt = new Date(Date.now() + 3600_000).toISOString();
  if (attack === 'method') (consent as { authentication: string }).authentication = 'unverified';
  if (attack === 'missing') delete delegation.metadata!['consent'];
  // The semantic validator runs after cryptographic verification in the server.
  expect(() => verifyConsentEvidence(vc, issuer)).toThrow(/^CONSENT_(REQUIRED|BINDING_MISMATCH)/);
});
it('reserves legacy issuance indices without importing a legacy grant', () => {
  fs.writeFileSync(path.join(dir, 'delegation-120.json'), 'legacy archive, not an imported credential');
  expect(issue.nextDelegationIndex()).toBe(121);
  expect(issue.activeCredentialOrNull()).toBeNull();
});
