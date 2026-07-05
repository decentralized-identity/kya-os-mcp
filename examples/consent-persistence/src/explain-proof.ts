/**
 * Teaching helper: a tight, aligned breakdown of the holder-of-key `DetachedProof` — what the agent
 * signed and why each field matters. It makes "holder-of-key" concrete (and makes it obvious why a
 * non-signing client cannot fake it). Colour is applied only on a real TTY (and honours NO_COLOR),
 * so piped / CI output stays clean.
 */

import type { DetachedProof } from '@kya-os/mcp';

const COLOR = process.stdout.isTTY === true && !process.env['NO_COLOR'];
const paint = (code: string, s: string): string => (COLOR ? `\x1b[${code}m${s}\x1b[0m` : s);
const dim = (s: string): string => paint('2', s);
const cyan = (s: string): string => paint('36', s);
const green = (s: string): string => paint('32', s);

/** Middle-elide a long value so the columns line up without wrapping the terminal. */
const short = (s: string, head = 12, tail = 6): string =>
  s.length > head + tail + 1 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s;

/** Read the JWS protected-header `alg` (EdDSA / ES256) for display. */
function jwsAlg(jws: string): string {
  try {
    const h = JSON.parse(Buffer.from(jws.split('.')[0] ?? '', 'base64url').toString('utf8')) as { alg?: string };
    return h.alg ?? 'EdDSA';
  } catch {
    return 'EdDSA';
  }
}

const LABEL = 9;
const VALUE = 24;

/**
 * Aligned lines describing `proof`. `callDesc` is a short human label for the request
 * (e.g. `checkout {item:"laptop"}`). Returns lines for the caller to print (via its own `say`).
 */
export function describeProof(proof: DetachedProof, callDesc: string): string[] {
  const m = proof.meta;
  const row = (label: string, value: string, tag: string): string =>
    `  ${dim(label.padEnd(LABEL))}${cyan(value.padEnd(VALUE))}${dim(tag)}`;
  return [
    dim('proof the agent signed — a UI client cannot forge this:'),
    row('call', callDesc, ''),
    row('hash', short(m.requestHash, 16, 6), 'the exact args'),
    row('nonce', short(m.nonce, 16, 4), 'single-use'),
    row('audience', short(m.audience), 'this server only'),
    row('key', short(m.did), 'human-approved'),
    row('sig', short(proof.jws, 14, 8), `detached ${jwsAlg(proof.jws)} JWS`),
    green('  → server recomputes the hash and verifies the signature → grant applies'),
  ];
}
