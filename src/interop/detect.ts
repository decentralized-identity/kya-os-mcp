/**
 * Structural format sniffing for inbound A2A / KYA-OS envelopes.
 *
 * Pure and total: {@link detectEnvelopeFormat} never throws and never executes a
 * regex against the input — it only inspects structural keys. The gateway uses it
 * to route an unknown envelope onto the right normalizer before any trust logic.
 */
import type { EnvelopeFormat } from './a2a-types.js';

const W3C_VC_CONTEXT = 'https://www.w3.org/2018/credentials/v1';

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Native KYA-OS delegation VC: W3C VC context first + `DelegationCredential` type. */
function looksLikeKyaOsVc(input: Record<string, unknown>): boolean {
  const context = input['@context'];
  const type = input['type'];
  return (
    Array.isArray(context) &&
    context[0] === W3C_VC_CONTEXT &&
    Array.isArray(type) &&
    type.includes('DelegationCredential')
  );
}

/** Adobe A2A: flat header envelope — an `authorization` block plus a party. */
function looksLikeAdobeA2A(input: Record<string, unknown>): boolean {
  return isObject(input['authorization']) && (isObject(input['from']) || isObject(input['to']));
}

/** Google A2A: `agentCard`, a `message.parts` shape, or a google-shaped `delegation`. */
function looksLikeGoogleA2A(input: Record<string, unknown>): boolean {
  if (isObject(input['agentCard'])) return true;
  const message = input['message'];
  if (isObject(message) && Array.isArray(message['parts'])) return true;
  const delegation = input['delegation'];
  if (isObject(delegation) && ('issuer' in delegation || 'subject' in delegation || 'scopes' in delegation)) {
    return true;
  }
  return false;
}

/**
 * Classify an unknown envelope by structure.
 *
 * Precedence is deterministic and intentional, so an envelope carrying
 * overlapping keys resolves predictably:
 *
 *   1. `kya-os-vc`  — checked first; a native VC short-circuits to the existing path.
 *   2. `adobe-a2a`  — flat `authorization` + party envelope.
 *   3. `google-a2a` — `AgentCard` / `Message` / delegation envelope.
 *   4. `unknown`    — anything else (including non-objects and arrays).
 */
export function detectEnvelopeFormat(input: unknown): EnvelopeFormat {
  if (!isObject(input)) return 'unknown';
  if (looksLikeKyaOsVc(input)) return 'kya-os-vc';
  if (looksLikeAdobeA2A(input)) return 'adobe-a2a';
  if (looksLikeGoogleA2A(input)) return 'google-a2a';
  return 'unknown';
}
