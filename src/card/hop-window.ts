/**
 * The wall-clock gate of an Entity Card delegation chain: each hop is read only inside the window it
 * states, its `validFrom`, every end it states ({@link hopEnds}) and any `ValidUntil` caveat.
 * Attenuation only proves a child expires no later than its parent, which a fully expired but well
 * attenuated chain still does, so this gate is what refuses it.
 *
 * A hop states its end as `validUntil` (VC 2.0), but an issuer may state it another way the library
 * reads elsewhere: as `expirationDate`, the Verifiable Credentials Data Model 1.1 member a status
 * list's end is read from, or as its proof's `expires`, the instant W3C Data Integrity says the proof
 * expires. The proof covers each, so each is the issuer's word, and authority never outlives an end
 * its issuer signed: the gate holds a hop to every one it states, the earliest deciding.
 *
 * Each time a hop states is a date as `../utils/rfc3339.ts` reads one, an RFC 3339 date-time with
 * its zone, so a hop names one window wherever it is read, and one that states another form, a time
 * with no zone included, is malformed. A `ValidUntil` caveat's own form, a date it states or one
 * it leaves out, is held with every caveat's (`./caveats.ts`); this gate reads the date of each
 * caveat whose form holds. Each bound is held with the clock tolerance `maxClockSkewMs`
 * (`../utils/validity-window.ts`), the rule a status list's window is read by, so a hop stamped a
 * moment ago by an issuer whose clock runs ahead is read. A reason quotes at most 64 characters of a
 * time a hop states (`../utils/describe-value.ts`).
 */

import type { RefusalCode } from '../refusal-codes.js';
import { describeValue } from '../utils/describe-value.js';
import { isRecord } from '../utils/guards.js';
import { DATE_TIME_FORM, parseDateTime } from '../utils/rfc3339.js';
import { clockSkewOption, clockSkewRefusal, windowBreach, type WindowBreach } from '../utils/validity-window.js';
import type { DelegationChain } from './delegation.js';

/** A rule a hop's window breaks: why, and the code of that rule. */
export interface HopWindowRule {
  code: Extract<RefusalCode, 'delegation_expired' | 'delegation_not_yet_valid' | 'delegation_malformed' | 'configuration_error'>;
  reason: string;
}

/** One end a hop states: the member that states it, as a reason names it, and what it states. */
export interface HopEnd {
  member: 'validUntil' | 'expirationDate' | 'proof.expires';
  stated: unknown;
}

/**
 * Every end `vc` states beside its caveats, in this order: its `validUntil`, its `expirationDate` and
 * its proof's `expires`, each that it states. Empty when it states none.
 */
export function hopEnds(vc: DelegationChain[number]): HopEnd[] {
  const proof: unknown = vc.proof;
  const ends: [HopEnd['member'], unknown][] = [
    ['validUntil', vc.validUntil],
    ['expirationDate', vc.expirationDate],
    ['proof.expires', isRecord(proof) ? proof.expires : undefined],
  ];
  return ends.filter(([, stated]) => stated !== undefined).map(([member, stated]) => ({ member, stated }));
}

/**
 * The rules any hop of `chain` breaks at `nowMs`, each bound held with `maxClockSkewMs`: an end it
 * states ({@link hopEnds}) or a `ValidUntil` caveat that has passed (`delegation_expired`), a
 * `validFrom` not yet reached (`delegation_not_yet_valid`), or a `validFrom` or an end that is not an
 * RFC 3339 date-time with its zone (`delegation_malformed`), which fails closed. A
 * `maxClockSkewMs` that is not a number of milliseconds from 0 to 600,000 breaks a rule of its own
 * (`configuration_error`), so no hop is read with it. Empty when every hop is inside its window.
 */
export function hopWindowRules(chain: DelegationChain, nowMs: number, maxClockSkewMs: unknown): HopWindowRule[] {
  const skewRefusal = clockSkewRefusal(maxClockSkewMs);
  if (skewRefusal !== undefined) return [{ code: 'configuration_error', reason: skewRefusal }];
  const skewMs = clockSkewOption(maxClockSkewMs);
  const broken: HopWindowRule[] = [];
  chain.forEach((vc, i) => {
    /** The instant `stated` names, or `undefined`, with a malformed rule broken that names it `what`, when it is no date. */
    const dateOf = (what: string, stated: unknown): number | undefined => {
      const ms = parseDateTime(stated);
      if (ms === undefined) broken.push({ code: 'delegation_malformed', reason: `hop ${i}: ${what} ${describeValue(stated)} is not ${DATE_TIME_FORM}` });
      return ms;
    };
    const breachOf = (fromMs: number | undefined, untilMs: number | undefined): WindowBreach | undefined =>
      windowBreach(fromMs, untilMs, nowMs, skewMs);
    for (const { member, stated } of hopEnds(vc)) {
      if (breachOf(undefined, dateOf(member, stated)) === 'expired') {
        broken.push({ code: 'delegation_expired', reason: `hop ${i}: expired (${member} ${describeValue(stated)} is in the past)` });
      }
    }
    if (vc.validFrom !== undefined && breachOf(dateOf('validFrom', vc.validFrom), undefined) === 'not_yet_valid') {
      broken.push({ code: 'delegation_not_yet_valid', reason: `hop ${i}: not yet valid (validFrom ${describeValue(vc.validFrom)} is in the future)` });
    }
    for (const caveat of vc.credentialSubject.caveats ?? []) {
      // A ValidUntil caveat that states no date, or one that is not a date, is refused for its form (`./caveats.ts`).
      const untilMs = caveat.type === 'ValidUntil' ? parseDateTime(caveat.date) : undefined;
      if (untilMs !== undefined && breachOf(undefined, untilMs) === 'expired') {
        broken.push({ code: 'delegation_expired', reason: `hop ${i}: expired caveat (ValidUntil ${describeValue(caveat.date)} is in the past)` });
      }
    }
  });
  return broken;
}
