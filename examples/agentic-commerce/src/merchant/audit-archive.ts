import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import type { AuditArchiveSnapshot } from '../lib/party-audit.js';

/** Safe to expose in the console: no filesystem paths or private key material. */
export interface ArchivedAuditRun {
  id: string;
  ledger: AuditArchiveSnapshot['ledger'];
  ledgerEpochId: string;
  entries: number;
  checkpointDigest: string;
  manifestDigest: string;
  witnessed: boolean;
  witnessError: string | null;
  archivedAt: string;
}

/** Publish the complete archive atomically; never overwrite an earlier run. */
export function archiveAuditRun(snapshot: AuditArchiveSnapshot, auditDir: string): ArchivedAuditRun {
  const archive: ArchivedAuditRun = {
    id: `run-${randomUUID()}`, ledger: snapshot.ledger, ledgerEpochId: snapshot.ledger.ledgerEpochId, entries: snapshot.entries,
    checkpointDigest: snapshot.checkpointDigest, manifestDigest: snapshot.manifestDigest,
    witnessed: snapshot.witnessed, witnessError: snapshot.witnessError, archivedAt: new Date().toISOString(),
  };
  const root = path.join(auditDir, 'archives');
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const temporary = fs.mkdtempSync(path.join(root, '.preparing-'));
  try {
    for (const [name, content] of Object.entries({
      'bundle.json': snapshot.bundle, 'policy.json': snapshot.policy,
      'keys.json': snapshot.keys, 'verification.json': snapshot.verification, 'run.json': archive,
    })) {
      const descriptor = fs.openSync(path.join(temporary, name), 'wx', 0o600);
      try { fs.writeFileSync(descriptor, JSON.stringify(content, null, 2)); fs.fsyncSync(descriptor); }
      finally { fs.closeSync(descriptor); }
    }
    syncDirectory(temporary);
    fs.renameSync(temporary, path.join(root, archive.id));
    syncDirectory(root);
    return archive;
  } finally { fs.rmSync(temporary, { recursive: true, force: true }); }
}

function syncDirectory(directory: string): void {
  const descriptor = fs.openSync(directory, 'r');
  try { fs.fsyncSync(descriptor); }
  finally { fs.closeSync(descriptor); }
}
