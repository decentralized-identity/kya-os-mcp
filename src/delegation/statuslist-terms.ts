/**
 * StatusList Terms
 *
 * What a `StatusList2021Manager` states on the lists it signs, read from its options once, where it
 * is built: the format of the lists it creates, the validity period of each version, and the `ttl`.
 *
 * A list that states no end is read until its issuer replaces it, so a copy signed before a
 * revocation, which a cache, a mirror or a party that wants to stay unrevoked keeps, reads as
 * current for as long as its key verifies (SPEC.md §6.6). A list that states its end is unresolvable
 * past it, so such a copy stops being read within the validity period of the version it is. W3C
 * Bitstring Status List v1.0 names both terms: its §7.2, "Validity Periods", leaves the period to
 * the issuer, "there is no minimum or maximum validity period that is suggested for all status
 * lists", and its §2.2 gives a list a `ttl`, a refresh hint that "does not override or replace the
 * validity period".
 */

import type { StatusListCredential } from '../types/protocol.js';
import { describeOptionValue } from '../utils/describe-value.js';
import {
  MIN_BITSTRING_ENTRIES,
  STATUS_LIST_FORMATS,
  statusListFormatOf,
  validUntilMemberOf,
  type StatusListFormat,
} from '../utils/statuslist-format.js';

/**
 * The longest validity period a manager gives its lists, and the longest `ttl`: a century of 365.25
 * days. A list that is valid longer bounds nothing a reader keeps, and one valid far longer would end
 * where no RFC 3339 date-time, four digits of year, can say (SPEC.md §6.6), or where no `Date` is, so
 * every list would fail to sign.
 */
export const MAX_VALIDITY_PERIOD_MS = 36_525 * 24 * 60 * 60 * 1000;

/** The options of a `StatusList2021Manager` that say what its lists state. */
export interface StatusListTermsOptions {
  /**
   * The format the manager creates its lists in and allocates their entries in. `'StatusList2021'`,
   * the default through 1.x: a `StatusList2021Credential` of the Verifiable Credentials Data Model
   * 1.1, with `StatusList2021Entry` entries. `'BitstringStatusList'`: W3C Bitstring Status List v1.0,
   * a `BitstringStatusListCredential` of the Data Model 2.0 with `BitstringStatusListEntry` entries,
   * which 2.0.0 makes the default (DEPRECATIONS.md); it takes a `defaultListSize` of 131,072 or
   * more, the fewest entries such a list may hold. A stored list keeps the format it was created in:
   * the manager sets and clears its bits and renews it in that list's own terms, and allocates an
   * entry only on a list of its own format, so a manager that changes format takes a
   * `statusListBaseUrl` of its own, and a store typed for the lists it then holds
   * (`StatusListStorageProvider`). Any other value throws a `TypeError` naming the option.
   */
  format?: StatusListFormat;
  /**
   * The validity period of each version of a list the manager signs, in milliseconds: every
   * version, as it is created, changed or renewed, states its end this long after it is signed, as
   * the `validUntil` of a `BitstringStatusListCredential` or the `expirationDate` of a
   * `StatusList2021Credential`, so a copy kept from before a revocation stops being read within that
   * time (SPEC.md §6.6). Renew each list with `renewStatusList` before its end, as every half
   * period: a list past its end is unresolvable, and every credential on it is refused. A whole
   * number from 1 to a century, {@link MAX_VALIDITY_PERIOD_MS}; any other value throws a `TypeError`
   * naming the option. Unset, lists state no end.
   */
  validityPeriodMs?: number;
  /**
   * The `credentialSubject.ttl` of each `BitstringStatusListCredential` the manager signs, as
   * Bitstring Status List v1.0 §2.2 defines it: how long, in milliseconds, a reader keeps the list
   * before it fetches it again. It is a hint and never the list's end, which `validityPeriodMs`
   * sets, so serve the list with a `Cache-Control` `max-age` that agrees with it. A whole number
   * from 1 to a century, and no longer than `validityPeriodMs` when that is set. A `StatusList2021`
   * has no such member, so with that format, the default, it throws a `TypeError`, as any other
   * value does. Unset, lists state no `ttl`.
   */
  ttl?: number;
}

/** What a manager states on the lists it signs. */
export interface StatusListTerms {
  /** The format of the lists it creates and of the entries it allocates. */
  readonly format: StatusListFormat;
  /** How long after it signs a version that version ends, or `undefined` when its lists state no end. */
  readonly validityPeriodMs: number | undefined;
  /** The `ttl` its `BitstringStatusList` lists state, or `undefined` when they state none. */
  readonly ttl: number | undefined;
}

/**
 * The terms `options` give a manager whose new lists hold `listSize` entries. Throws a `TypeError`
 * naming the option for a `format` that is not one of the two, for a `validityPeriodMs` or a `ttl`
 * that is not a whole number of milliseconds from 1 to {@link MAX_VALIDITY_PERIOD_MS}, and for an
 * option the format does not have or the terms cannot keep to: a `ttl` on a `StatusList2021`, a
 * `ttl` longer than the validity period, and a `BitstringStatusList` of fewer than
 * {@link MIN_BITSTRING_ENTRIES} entries. So a mistyped option fails where the manager is built, not
 * at every list it signs.
 */
export function statusListTermsOf(options: StatusListTermsOptions = {}, listSize: number): StatusListTerms {
  const format = formatOption(options.format);
  const validityPeriodMs = durationOption('validityPeriodMs', options.validityPeriodMs);
  const ttl = durationOption('ttl', options.ttl);
  if (ttl !== undefined && format !== 'BitstringStatusList') {
    throw new TypeError(
      `[kya-os] ttl is a member of a BitstringStatusList, and a ${format} has none: set format to "BitstringStatusList", or leave ttl out`,
    );
  }
  if (ttl !== undefined && validityPeriodMs !== undefined && ttl > validityPeriodMs) {
    throw new TypeError(
      `[kya-os] ttl (${ttl}) must not be longer than validityPeriodMs (${validityPeriodMs}): a list is not read past its validUntil, whatever its ttl`,
    );
  }
  if (format === 'BitstringStatusList' && !(listSize >= MIN_BITSTRING_ENTRIES)) {
    throw new TypeError(
      `[kya-os] defaultListSize must be at least ${MIN_BITSTRING_ENTRIES} where format is "BitstringStatusList", the fewest entries one may hold ` +
        `(got ${describeOptionValue(listSize)})`,
    );
  }
  return { format, validityPeriodMs, ttl };
}

/** The `format` option, `StatusList2021` when it is not set. */
function formatOption(value: unknown): StatusListFormat {
  if (value === undefined) return 'StatusList2021';
  const format = STATUS_LIST_FORMATS.find((known) => known === value);
  if (format === undefined) {
    throw new TypeError(
      `[kya-os] format must be ${STATUS_LIST_FORMATS.map((known) => `"${known}"`).join(' or ')} (got ${describeOptionValue(value)})`,
    );
  }
  return format;
}

/** The option `name` as a number of milliseconds, or `undefined` when it is not set. */
function durationOption(name: 'validityPeriodMs' | 'ttl', value: unknown): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) <= 0 || (value as number) > MAX_VALIDITY_PERIOD_MS) {
    throw new TypeError(
      `[kya-os] ${name} must be a whole number of milliseconds from 1 to ${MAX_VALIDITY_PERIOD_MS}, a century ` +
        `(got ${describeOptionValue(value)})`,
    );
  }
  return value as number;
}

/**
 * The format a stored list is held to be in: the one it is typed as, and `StatusList2021`, the
 * format every list of a store written before 1.26.0 is in, for a list typed as neither.
 */
export function storedFormatOf(list: StatusListCredential): StatusListFormat {
  return statusListFormatOf(list) ?? 'StatusList2021';
}

/**
 * `list` as its next version states it under `terms`, every other member kept: with its end
 * `terms.validityPeriodMs` after `nowMs`, in the member its own format has, `validUntil` or
 * `expirationDate`, and with `terms.ttl` when it is a `BitstringStatusList`. The start of its window
 * stays the date the list was first issued, so a verifier whose clock runs behind never reads a
 * version as not yet valid. A term the manager does not set leaves what the list states as it is.
 */
export function restated<T extends StatusListCredential>(list: T, terms: StatusListTerms, nowMs: number): T {
  const format = storedFormatOf(list);
  const bounded: T =
    terms.validityPeriodMs === undefined
      ? { ...list }
      : { ...list, [validUntilMemberOf(format)]: new Date(nowMs + terms.validityPeriodMs).toISOString() };
  if (terms.ttl === undefined || format !== 'BitstringStatusList') return bounded;
  return { ...bounded, credentialSubject: { ...bounded.credentialSubject, ttl: terms.ttl } };
}
