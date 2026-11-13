/**
 * The verifier configuration a status-list vector may state (SPEC.md §6.6), checked as
 * `conformance/status_list.py` checks it, so the suite's two readers refuse the same malformed
 * vector, whoever wrote it.
 */

import { describeValue } from '../src/utils/describe-value.js';
import { isRecord } from '../src/utils/guards.js';
import { assertStatusListIssuers } from '../src/utils/statuslist-acceptance.js';

/**
 * Throw a `TypeError` unless a status-list input's `trustedRootIssuer`, when present, is a non-empty
 * string, and its `statusListIssuers`, when present, is a plain object of string arrays, as the
 * library's readers require ({@link assertStatusListIssuers}).
 */
export function assertStatusListConfiguration(input: unknown): void {
  const fields: Record<string, unknown> = isRecord(input) ? input : {};
  const root = fields['trustedRootIssuer'];
  if (root !== undefined && (typeof root !== 'string' || root.length === 0)) {
    throw new TypeError(`trustedRootIssuer ${describeValue(root)} is not a non-empty string`);
  }
  assertStatusListIssuers(fields['statusListIssuers']);
}
