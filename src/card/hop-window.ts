/**
 * The wall-clock gate of an Entity Card delegation chain: each hop is read only inside the window it
 * states, its `validFrom` and `validUntil` and any `ValidUntil` caveat. Attenuation only proves a
 * child expires no later than its parent, which a fully expired but well attenuated chain still
 * does, so this gate is what refuses it.
 *
 * Each time a hop states is a date as `../utils/rfc3339.ts` reads one, an RFC 3339 date-time with
 * its zone, so a hop names one window wherever it is read, and one that states another form, a time
 * with no zone included, is malformed, as is a `ValidUntil` caveat that states no date. Each bound
 * is held with the clock tolerance `maxClockSkewMs` (`../utils/validity-window.ts`), the rule a
 * status list's window is read by, so a hop stamped a moment ago by an issuer whose clock runs
 * ahead is read.
 */

import type { RefusalCode } from '../refusal-codes.js';
import { describeValue } from '../utils/describe-value.js';
import { DATE_TIME_FORM, parseDateTime } from '../utils/rfc3339.js';
import { clockSkewOption, clockSkewRefusal, windowBreach, type WindowBreach } from '../utils/validity-window.js';
import type { DelegationChain } from './delegation.js';

/** A rule a hop's window breaks: why, and the code of that rule. */
export interface HopWindowRule {
  code: Extract<RefusalCode, 'delegation_expired' | 'delegation_not_yet_valid' | 'delegation_malformed' | 'configuration_error'>;
  reason: string;
}

/**
 * The rules any hop of `chain` breaks at `nowMs`, each bound held with `maxClockSkewMs`: an expired
 * `validUntil` or `ValidUntil` caveat (`delegation_expired`), a `validFrom` not yet reached
 * (`delegation_not_yet_valid`), or a time that is not an RFC 3339 date-time with its zone, or a
 * `ValidUntil` caveat that states none (`delegation_malformed`), which fails closed. A
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
    if (vc.validUntil !== undefined && breachOf(undefined, dateOf('validUntil', vc.validUntil)) === 'expired') {
      broken.push({ code: 'delegation_expired', reason: `hop ${i}: expired (validUntil ${vc.validUntil} is in the past)` });
    }
    if (vc.validFrom !== undefined && breachOf(dateOf('validFrom', vc.validFrom), undefined) === 'not_yet_valid') {
      broken.push({ code: 'delegation_not_yet_valid', reason: `hop ${i}: not yet valid (validFrom ${vc.validFrom} is in the future)` });
    }
    for (const caveat of vc.credentialSubject.caveats ?? []) {
      if (caveat.type !== 'ValidUntil') continue;
      if (caveat.date === undefined) {
        broken.push({ code: 'delegation_malformed', reason: `hop ${i}: ValidUntil caveat states no date` });
      } else if (breachOf(undefined, dateOf('ValidUntil caveat', caveat.date)) === 'expired') {
        broken.push({ code: 'delegation_expired', reason: `hop ${i}: expired caveat (ValidUntil ${caveat.date} is in the past)` });
      }
    }
  });
  return broken;
}
