/**
 * The issuer a delegation credential names. VC Data Model 2.0 §4.7: "The value of the issuer
 * property MUST be either a URL or an object containing an id property whose value is a URL", a
 * URL as the WHATWG URL Standard defines one. A verifier reads that URL as the issuer's DID,
 * resolves the DID's document and takes the issuer's key from it. So the basic stage refuses a
 * credential whose issuer is neither a URL nor an object whose `id` is one, before any DID is
 * resolved, and every later stage, the key lookup included, holds the issuer's DID as a string.
 */

import type { DelegationCredential } from '../types/protocol.js';
import { describeValue } from '../utils/describe-value.js';
import { isRecord, issuerOf } from '../utils/guards.js';

/**
 * The credential's own declared issuer as a DID string: `issuer` itself, or the `id` of an `issuer`
 * object ({@link issuerOf}); `undefined` when neither is a string. A VC-JWT verifier requires it to
 * equal the JWT `iss`, so a credential cannot claim an issuer other than the one whose key signed
 * the envelope.
 */
export function credentialIssuerDid(credential: DelegationCredential): string | undefined {
  return issuerOf(credential.issuer);
}

/**
 * Why the basic stage refuses `credential` for the way it names its issuer, or `undefined` when
 * {@link credentialIssuerDid} reads from it a URL ({@link isIssuerUrl}), as every DID is. The reason
 * quotes a string that is not one, and names the JSON type of anything else that stands where the
 * URL should be, never converting it.
 */
export function credentialIssuerRefusal(credential: DelegationCredential): string | undefined {
  const did = credentialIssuerDid(credential);
  if (did !== undefined && isIssuerUrl(did)) return undefined;
  const issuer: unknown = credential.issuer;
  return isRecord(issuer)
    ? `Credential issuer id ${describeValue(issuer.id)} is not a URL`
    : `Credential issuer ${describeValue(issuer)} is not a URL`;
}

/**
 * A control character, a format character, a line or paragraph separator, or a lone surrogate:
 * General_Category Cc, Cf or Cs, U+2028 or U+2029. A zero width space or a bidirectional control in
 * a DID makes it read as another, and a control or a separator breaks the line it is shown on.
 */
const UNSEEN_OR_BREAKING = /[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/u;

/**
 * Whether `value` names an issuer as a URL as it stands, the rule for a credential's issuer and a
 * VC-JWT's `iss`: a string the WHATWG URL parser parses against no base without first cleaning it,
 * with nothing in it that reads as another character or as none. The parser removes leading and
 * trailing C0 controls and spaces, and every ASCII tab, CR and LF, before it parses, so a string
 * with white space at either end, as `trim` removes it, is not one. The parser accepts the other
 * characters {@link UNSEEN_OR_BREAKING} matches, percent-encoding some, so a string holding one
 * anywhere is not one either. Constructing a `URL` asks what `URL.canParse` asks, on Node.js 20, the oldest release
 * the package runs on, and in the browsers released before `URL.canParse` (2023) alike.
 */
export function isIssuerUrl(value: string): boolean {
  if (value.trim() !== value || UNSEEN_OR_BREAKING.test(value)) return false;
  try {
    new URL(value);
  } catch {
    return false;
  }
  return true;
}
