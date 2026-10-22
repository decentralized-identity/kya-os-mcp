/** The RP records the consent and issuance events that it observed itself. */
import { consentDigest } from '../lib/consent-evidence.js';
import type { AuditTrailEventInput } from '@kya-os/mcp/audit';
import type { PartyAudit } from '../lib/party-audit.js';
import type { ConsentFlowStore } from './consent-store.js';

/** Serialize ingestion so overlapping HTTP requests cannot duplicate RP events. */
export function createConsentAuditBridge(audit: PartyAudit, store: ConsentFlowStore, responsibleParty: string) {
  let tail: Promise<void> = Promise.resolve();
  const recorded = new Set<string>();
  async function record(input: AuditTrailEventInput) {
    const result = await audit.record(input);
    if (result.status !== 'recorded') throw new Error('AUDIT_UNAVAILABLE: consent could not be recorded');
  }
  const flush = (): Promise<void> => {
    const next = tail.then(async () => {
      for (const event of store.pendingEvents()) {
        if (!recorded.has(event.id)) {
          const payload = event.payload as Record<string, unknown>;
          const delegation = event.type.startsWith('delegation.');
          // Older persisted queues used this label for a WebAuthn assertion.
          const legacyAuthenticatorProof = event.type === 'credential.verified';
          const phase = event.type.slice(event.type.indexOf('.') + 1);
          const credentialId = String(payload['credentialId'] ?? 'unknown');
          // Legacy status-index revocations may have no archived grant metadata.
          // Omit unknown optional fields; never fabricate consent or a scope.
          const scope = String(payload['productClass'] ?? payload['scope'] ?? '').trim();
          const cap = String(payload['cap'] ?? '');
          const currency = String(payload['currency'] ?? 'CHF');
          const demoConsent = payload['demoConsent'] as { consentRef?: string } | undefined;
          // Authentication is evidence inside consent.approved, not a delegation credential verification.
          const consentRef = String(payload['consentRef'] ?? demoConsent?.consentRef ?? consentDigest(payload['resumeTokenHash'] ?? event.id));
          const actionName = delegation && !scope
            ? `${phase === 'revoked' ? 'revoke' : 'issue'} status-list index=${String(payload['index'] ?? '')}`
            : delegation ? `place_order; index=${String(payload['index'] ?? '')}; MaxAmount=${currency} ${cap}` : 'place_order';
          const occurredAt = Date.parse(String(payload['at'] ?? ''));
          await record({
            eventId: event.id,
            ...(Number.isFinite(occurredAt) ? { occurredAt } : {}),
            eventType: legacyAuthenticatorProof ? 'proof.verified' : event.type,
            actor: { kind: 'public_did', did: event.actor },
            responsibleParty: { kind: 'public_did', did: responsibleParty },
            correlationId: consentRef,
            action: { category: delegation ? 'delegation' : 'consent', name: actionName },
            resource: { kind: 'keyed_commitment', value: consentDigest(payload), keyId: 'consent-grant-bindings' },
            outcome: phase === 'denied' ? 'denied' : 'succeeded',
            ...(phase === 'denied' ? { reason: { code: 'CONSENT_DENIED' } } : {}),
            ...(delegation ? { authorization: { source: 'delegation' as const, decision: phase === 'revoked' ? 'denied' as const : 'allowed' as const, ...(scope ? { scopeId: scope } : {}), delegationRef: credentialId } } : {}),
            evidence: [],
            details: legacyAuthenticatorProof
              ? { family: 'proof', phase: 'verified', verificationCode: 'WEBAUTHN_ASSERTION_VERIFIED' }
              : delegation
              ? { family: 'delegation', phase: phase as 'issued' | 'revoked', delegationRef: credentialId }
              : { family: 'consent', phase: phase as 'requested' | 'approved' | 'denied', consentRef },
          });
          recorded.add(event.id);
        }
        // Retain the RP-owned source event for replay after a process restart.
      }
    });
    tail = next.catch(() => {});
    return next;
  };
  return { flush, record };
}
