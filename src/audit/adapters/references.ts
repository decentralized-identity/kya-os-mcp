import { WebCryptoProvider } from '../../providers/web-crypto.js';
import { hasUnprintableCharacter } from '../../utils/plain-text.js';
import { CryptoProviderAuditHasher, type AuditHasher } from '../crypto.js';

const encoder = new TextEncoder();

let referenceHasher: AuditHasher | undefined;

/**
 * Caller-presented identifiers (credential IDs, grant and consent references,
 * correlation IDs) are untrusted input. A non-empty value within the schema
 * bound that holds no character that does not print as itself (a control or
 * format character, a line or paragraph separator, or a surrogate without
 * its pair) is kept verbatim. Anything else is replaced by the SHA-256 of its
 * well-formed UTF-8 encoding: that form always canonicalizes, fits the bound
 * and prints as itself in a log line, and unlike truncation it cannot be made
 * to collide with a different reference that shares a long prefix.
 *
 * A delegation credential's reference is not made here. SPEC §7.8 defines
 * it, the middleware derives it (`delegationReference`) for the audit trail
 * as a verifier derives it for a proof, and what it derives is a value this
 * function keeps as it is, so the two carry one string.
 */
export async function boundedAuditReference(value: string, maxLength = 256): Promise<string> {
  if (value.length > 0 && value.length <= maxLength && !hasUnprintableCharacter(value)) return value;
  referenceHasher ??= new CryptoProviderAuditHasher(new WebCryptoProvider());
  return referenceHasher.sha256(encoder.encode(value));
}
