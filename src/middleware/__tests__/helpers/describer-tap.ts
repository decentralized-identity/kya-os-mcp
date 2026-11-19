/**
 * Test helper: the delegation describer as it is, with a tap on what it hands
 * the gate. A test mocks `with-kya-os.delegation-records.js` with
 * {@link tappedRecords}, importing this module inside its `vi.mock` factory:
 * this module only names the records module's types, so it never loads the
 * module it stands in for.
 */
import type * as RecordsModule from '../../with-kya-os.delegation-records.js';
import type { DelegationRecords } from '../../with-kya-os.delegation-records.js';

/**
 * The records module `actual`, but with each set of records its describer
 * makes passed through `tap` on the way to the gate: to keep them where the
 * test can reach them, or to hand the gate others.
 */
export function tappedRecords(
  actual: typeof RecordsModule,
  tap: (records: DelegationRecords) => DelegationRecords,
): typeof RecordsModule {
  const createDelegationDescriber: typeof actual.createDelegationDescriber = (deps) => {
    const describer = actual.createDelegationDescriber(deps);
    return { ...describer, describe: async (presentation) => tap(await describer.describe(presentation)) };
  };
  return { ...actual, createDelegationDescriber };
}
