/**
 * Test helper: what a server says of a delegated call, read the way the
 * party it says it to would. A client reads the answer and its proof, and an
 * auditor the trail.
 */
import { createHash } from 'node:crypto';
import { decodeJwt } from 'jose';
import { canonicalize } from 'json-canonicalize';
import type { Recorded } from './delegation-gate-server.js';
import { proofOf } from './received-proof.js';

/** What an event's authorization evidence says of the delegation presented. */
export const delegationEvidence = ({ authorization }: Pick<Recorded, 'authorization'>) => ({
  ...(authorization?.delegationRef === undefined ? {} : { delegationRef: authorization.delegationRef }),
  ...(authorization?.delegationCredentialDigest === undefined
    ? {}
    : { delegationCredentialDigest: authorization.delegationCredentialDigest }),
  ...(authorization?.delegationChainDigests === undefined
    ? {}
    : { delegationChainDigests: authorization.delegationChainDigests }),
});

/** What an event records, with the code it gives: its reason, or its verification code. */
export const eventWithCode = (event: Recorded): string => {
  const code = event.reason ?? (event.details.verificationCode as string | undefined);
  return code === undefined ? event.eventType : `${event.eventType} ${code}`;
};

/** A trail's events in order, each with the code it gives. */
export const trailOf = (recorded: readonly Recorded[]): string[] => recorded.map(eventWithCode);

/**
 * The `tool.call.*` events of a trail in order, each with the reason it gives
 * and the credential it names, so a call's opening and closing events can be
 * told apart from another wrapper's.
 */
export const lifecycleOf = (recorded: readonly Recorded[]): Array<[string, string | undefined]> =>
  recorded
    .filter((event) => event.eventType.startsWith('tool.call.'))
    .map((event) => [
      event.reason === undefined ? event.eventType : `${event.eventType} ${event.reason}`,
      event.authorization?.delegationRef,
    ]);

/**
 * SPEC §7.3's request hash of a call, taken here from the request as written,
 * with another canonicalizer than the server's: SHA-256 of `{ method, params }`.
 */
export const literalRequestHash = (method: string, params: Record<string, unknown>): string =>
  `sha256:${createHash('sha256').update(canonicalize({ method, params })).digest('hex')}`;

/** The claims a proof's JWS actually signs, read from the JWS itself. */
export const signedClaims = (result: object): Record<string, unknown> => decodeJwt(proofOf(result)!.jws);

/**
 * What a proof says of a delegation (SPEC.md §7.8): its `delegationRef` and
 * `delegationChainDigest`, from its `meta` and from what its JWS signs,
 * whichever carries them. This release's server signs neither.
 */
export const delegationClaims = (result: object): Record<string, unknown> => {
  const claimed = (from: Record<string, unknown>) =>
    Object.fromEntries(
      ['delegationRef', 'delegationChainDigest'].filter((claim) => claim in from).map((claim) => [claim, from[claim]]),
    );
  return { ...claimed(signedClaims(result)), ...claimed(proofOf(result)!.meta as unknown as Record<string, unknown>) };
};

/** The reference each event of `eventType` records for the delegation presented, in order. */
export const recordedReferences = (recorded: readonly Recorded[], eventType: string): Array<string | undefined> =>
  recorded.filter((event) => event.eventType === eventType).map((event) => event.authorization?.delegationRef);

export const refusal = (result: { content: Array<{ text: string }> }): { error: string; reason: string } =>
  JSON.parse(result.content[0]!.text);

/** What an answer says of a proof it does not carry. */
export const proofErrorOf = (result: object): unknown =>
  ((result as { _meta?: Record<string, unknown> })._meta ?? {}).proofError;

/** `proofError` on an answer sent without the proof it was meant to carry. */
export const UNPROVEN = 'Proof generation failed \u2014 response is unproven';
