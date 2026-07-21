import type { EvidenceRef } from '../types.js';

export interface EncryptedEvidenceInput {
  ref: EvidenceRef;
  ciphertext: Uint8Array;
}

export interface AuditEvidenceProvider {
  putIfAbsent(input: EncryptedEvidenceInput): Promise<EvidenceRef>;
  has(ref: EvidenceRef): Promise<boolean>;
  get(ref: EvidenceRef, context: EvidenceAccessContext): Promise<Uint8Array | null>;
  applyRetention(command: EvidenceRetentionCommand): Promise<EvidenceRetentionResult>;
}

export interface EvidenceAccessContext {
  actor: string;
  purpose: string;
}

export type EvidenceRetentionCommand =
  | { kind: 'dispose'; ref: EvidenceRef; authorizedBy: string; reason: string }
  | { kind: 'legal_hold'; ref: EvidenceRef; holdId: string; authorizedBy: string }
  | { kind: 'release_hold'; ref: EvidenceRef; holdId: string; authorizedBy: string };

export interface EvidenceRetentionResult {
  ref: EvidenceRef;
  state: 'retained' | 'held' | 'disposed' | 'missing';
}
