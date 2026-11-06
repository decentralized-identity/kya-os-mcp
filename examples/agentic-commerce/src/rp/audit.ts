import { randomUUID } from 'node:crypto';
import path from 'node:path';
import type { KeyedIdentity } from '../lib/wiring.js';
import { VAR_DIR } from '../lib/wiring.js';
import { createPartyAudit } from '../lib/party-audit.js';
import { createConsentAuditBridge } from './consent-audit.js';
import type { ConsentFlowStore } from './consent-store.js';

export function createRpAudit(identity: KeyedIdentity, store: ConsentFlowStore) {
  const epoch = `epoch-${randomUUID()}`;
  const ready = createPartyAudit(identity, {
    role: 'responsible-party', epochId: epoch,
    auditDir: path.join(VAR_DIR, 'rp', 'audit', epoch),
  }).then(audit => ({ audit, bridge: createConsentAuditBridge(audit, store, identity.did) }));
  return {
    async flush() {
      const { audit, bridge } = await ready;
      await bridge.flush();
      return audit;
    },
    async export() { return (await this.flush()).exportBundle(); },
  };
}
