/**
 * The gate acts on a VC-JWT's claims and records the call by the id its payload shows, and both
 * are one reading of that payload: as SPEC.md §7.8 reads it, base64url of well-formed UTF-8. A
 * payload that reading refuses shows no id, so a call it authorized would be recorded under no
 * reference. The gate therefore refuses such a VC-JWT, however its issuer signed it, and every
 * VC-JWT it runs a tool for is recorded by the id it acted on.
 */

import { describe, expect, it } from 'vitest';
import { ACME, acmeDocument } from '../../__tests__/utils/did-documents.js';
import { delegationRecord, envelope, keyOf } from '../../__tests__/utils/delegation-credentials.js';
import { createUnsignedVCJWT } from '../../delegation/utils.js';
import { delegationCredentialId } from '../../delegation/delegation-ref.js';
import { wrapDelegationAsVC } from '../../types/protocol.js';
import { delegationGate } from './helpers/delegation-gate.js';

/** The payload of a VC-JWT for a delegation Acme issues, as JSON text with `note` beside its claims. */
function payloadText(note: string): string {
  const { payload } = createUnsignedVCJWT(wrapDelegationAsVC(delegationRecord(ACME)) as unknown as Record<string, unknown>);
  return JSON.stringify({ ...payload, note });
}

describe('a VC-JWT whose payload is not well-formed UTF-8', () => {
  it('is refused, though its issuer signed those bytes, and its well-formed twin runs the tool under its id', async () => {
    const [login, assert] = await Promise.all([keyOf(ACME, 'login-1'), keyOf(ACME, 'assert-1')]);
    const events: { eventType: string; ref: unknown }[] = [];
    const gate = await delegationGate({
      trustedRootIssuers: [ACME],
      resolution: { didResolver: { resolve: async () => acmeDocument(login, assert) } },
      record: async (event) => {
        events.push({ eventType: event.eventType, ref: (event.authorization as { delegationRef?: string } | undefined)?.delegationRef });
        return { status: 'pending', event: event as never };
      },
    });

    const clean = await envelope(assert, Buffer.from(payloadText('x')).toString('base64url'), assert.kid);
    expect(await gate.call(clean)).toBe('ran');
    const id = delegationCredentialId(clean);
    expect(id).toEqual(expect.any(String));
    expect(events.filter(event => event.eventType === 'delegation.verified').map(event => event.ref)).toEqual([id]);

    // The same claims with one byte of `note` that is no UTF-8: a decoder that repairs it reads
    // the claims above, and one that does not reads no payload.
    const bytes = Buffer.from(payloadText('x'));
    bytes[bytes.lastIndexOf('x'.charCodeAt(0))] = 0xff;
    const broken = await envelope(assert, bytes.toString('base64url'), assert.kid);
    expect(delegationCredentialId(broken)).toBeUndefined();
    expect(await gate.reasoned(broken)).toEqual({ outcome: 'delegation_invalid', reason: 'Invalid VC-JWT format' });
    expect(gate.runs()).toBe(1);
  });
});
