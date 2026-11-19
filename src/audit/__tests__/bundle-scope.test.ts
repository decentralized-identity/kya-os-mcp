/**
 * A replay bundle's scope: the ledger ranges its signed manifest selects, and the components it
 * says it left out. The verifier reports what a bundle omits, and never reports a bundle complete
 * without saying so.
 */

import { describe, expect, it } from 'vitest';
import type { AuditBundleDisposition } from '../types.js';
import { AUDIT_REASON_CODES } from '../verifier.js';
import { history } from './audit-fixtures.js';
import { exportBundle, included, selectionOf, verifyBundle } from './bundle-fixtures.js';

describe('the components a bundle leaves out', () => {
  const omitting = async (disposition: Exclude<AuditBundleDisposition, 'included'>) => {
    const entries = await history();
    return (await verifyBundle(await exportBundle([selectionOf(entries)], [
      included('entries', entries),
      { path: 'evidence/approval.bin', mediaType: 'application/octet-stream', disposition, reasonCode: 'WITHHELD' },
    ]))).scopeEvidenceCompleteness;
  };

  it('reports each disposition as its own reason, and the scope as indeterminate', async () => {
    expect(await omitting('redacted')).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.EXPLICITLY_REDACTED],
    });
    expect(await omitting('disposed')).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.EXPLICITLY_DISPOSED],
    });
    expect(await omitting('unavailable')).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.EXPLICITLY_UNAVAILABLE],
    });
    expect(await omitting('policy_excluded')).toEqual({
      verdict: 'indeterminate', reasonCodes: [AUDIT_REASON_CODES.EXPLICITLY_POLICY_EXCLUDED],
    });
  });

  it('reports a bundle that leaves nothing out as complete', async () => {
    const entries = await history();
    expect((await verifyBundle(await exportBundle([selectionOf(entries)], [
      included('entries', entries),
    ]))).scopeEvidenceCompleteness).toEqual({ verdict: 'valid', reasonCodes: [] });
  });
});
