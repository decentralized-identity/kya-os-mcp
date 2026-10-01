import { WebCryptoProvider } from '../../providers/web-crypto.js';
import { CryptoProviderAuditHasher, type AuditHasher } from '../crypto.js';

const encoder = new TextEncoder();
// Matches a high surrogate without its low half, or a low surrogate without its
// high half. No `u` flag, so the pattern sees UTF-16 code units.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

let referenceHasher: AuditHasher | undefined;

/**
 * Caller-presented identifiers (credential IDs, grant and consent references,
 * correlation IDs) are untrusted input. A non-empty, well-formed value within
 * the schema bound is kept verbatim. Anything else is replaced by the SHA-256
 * of its well-formed UTF-8 encoding: that form always canonicalizes and fits
 * the bound, and unlike truncation it cannot be made to collide with a
 * different reference that shares a long prefix.
 */
export async function boundedAuditReference(value: string, maxLength = 256): Promise<string> {
  if (value.length > 0 && value.length <= maxLength && !LONE_SURROGATE.test(value)) return value;
  referenceHasher ??= new CryptoProviderAuditHasher(new WebCryptoProvider());
  return referenceHasher.sha256(encoder.encode(value));
}
