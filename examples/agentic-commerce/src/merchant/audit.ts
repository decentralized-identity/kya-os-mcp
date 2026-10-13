/** Merchant ledger composition; RP and merchant reuse the same published audit primitives. */
import { randomUUID } from 'node:crypto';
import { AUDIT_DIR, createPartyAudit, type PartyAudit, type PartyAuditOptions } from '../lib/party-audit.js';
import type { KeyedIdentity } from '../lib/wiring.js';
import { archiveAuditRun, type ArchivedAuditRun } from './audit-archive.js';
export * from '../lib/party-audit.js';
export type { ArchivedAuditRun } from './audit-archive.js';
export type MerchantAuditOptions = PartyAuditOptions;

export interface PreparedAuditRun {
  archive: ArchivedAuditRun | null;
  ledger: PartyAudit['ledger'];
  /** No I/O: call only after the RP reset succeeds, under the drained run gate. */
  commit(): void;
}
export interface MerchantAudit extends PartyAudit {
  /** Caller must exclude all order transports and audit actions until commit. */
  prepareNewRun(): Promise<PreparedAuditRun>;
}

export async function createMerchantAudit(identity: KeyedIdentity, options: MerchantAuditOptions = {}): Promise<MerchantAudit> {
  const createRun = (epochId = `epoch-${randomUUID()}`) => createPartyAudit(identity, { ...options, role: 'merchant', epochId });
  let active = await createRun(options.epochId);
  let revision = 0, pendingRecords = 0;
  // SDK middleware captures this function once. Keep it stable while all
  // records and the console move together to the committed replacement run.
  const record: PartyAudit['record'] = async (input, recordOptions) => {
    const target = active;
    revision += 1; pendingRecords += 1;
    try { return await target.record(input, recordOptions); }
    finally { pendingRecords -= 1; }
  };
  const middlewareAudit: PartyAudit['middlewareAudit'] = { ...active.middlewareAudit, record };
  return {
    middlewareAudit, record,
    get capabilities() { return active.capabilities; },
    get ledger() { return active.ledger; },
    get recorder() { return active.recorder; },
    entries: () => active.entries(), anchor: () => active.anchor(), report: () => active.report(),
    tamper: edit => active.tamper(edit), exportBundle: () => active.exportBundle(), bundle: () => active.bundle(),
    snapshotForArchive: () => active.snapshotForArchive(),
    async prepareNewRun() {
      const previous = active, previousRevision = revision;
      const unchanged = () => active === previous && revision === previousRevision && pendingRecords === 0;
      if (!unchanged()) throw new Error('AUDIT_RUN_BUSY: wait for the current operation, then retry Start over.');
      const candidate = await createRun();
      const snapshot = await previous.snapshotForArchive();
      if (!unchanged()) throw new Error('AUDIT_RUN_CHANGED: retry Start over after the current operation finishes.');
      const archive = snapshot ? archiveAuditRun(snapshot, options.auditDir ?? AUDIT_DIR) : null;
      let committed = false;
      return {
        archive, ledger: { ...candidate.ledger },
        commit() {
          if (committed || !unchanged()) throw new Error('AUDIT_RUN_CHANGED: retry Start over after the current operation finishes.');
          active = candidate; revision = 0; committed = true;
        },
      };
    },
  };
}
