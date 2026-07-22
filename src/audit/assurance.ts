export type AuditAssuranceProfile = 'AAP-0' | 'AAP-1' | 'AAP-2' | 'AAP-3' | 'AAP-4';
export type AuditDeliveryMode = 'best-effort' | 'buffered' | 'required';
export type AuditSupportingAnchor = 'worm' | 'rfc3161' | 'scitt';

export interface AuditCapabilities {
  profile: AuditAssuranceProfile;
  recorderTopology: 'none' | 'self-hosted' | 'managed' | 'verified-mirror';
  delivery: AuditDeliveryMode;
  journalDurability: 'none' | 'ephemeral' | 'durable';
  atomicAppend: boolean;
  sourceHighWater: boolean;
  merkleCheckpoints: boolean;
  independentObservation: boolean;
  supportingAnchors: AuditSupportingAnchor[];
  evidenceRetention: 'none' | 'inline' | 'separate';
}

export const AUDIT_ASSURANCE_PROFILES: Readonly<Record<AuditAssuranceProfile, {
  name: string;
  claim: string;
}>> = Object.freeze({
  'AAP-0': { name: 'None', claim: 'No audit assurance' },
  'AAP-1': { name: 'Recorded', claim: 'Structured capture of delivered instrumented events' },
  'AAP-2': { name: 'Chained', claim: 'Ordered tamper-evident accepted history for a declared scope' },
  'AAP-3': { name: 'Transparent', claim: 'Efficient inclusion, consistency, and declared source-gap evidence' },
  'AAP-4': { name: 'Observed', claim: 'Conflicting observed views are detectable relative to independently known checkpoints' },
});

/** Fail startup when advertised assurance exceeds configured mechanics. */
export function assertAuditCapabilities(capabilities: AuditCapabilities): void {
  const level = Number(capabilities.profile.slice(-1));
  if (level === 0) return;
  if (capabilities.recorderTopology === 'none' || capabilities.journalDurability === 'none') {
    throw new Error(`${capabilities.profile} requires an audit recorder or verified mirror`);
  }
  if (level >= 2) {
    if (capabilities.journalDurability !== 'durable') {
      throw new Error(`${capabilities.profile} requires a durable journal`);
    }
    if (!capabilities.atomicAppend) {
      throw new Error(`${capabilities.profile} requires atomic append`);
    }
    if (capabilities.delivery === 'best-effort') {
      throw new Error(`${capabilities.profile} cannot use best-effort delivery`);
    }
  }
  if (level >= 3 && (!capabilities.merkleCheckpoints || !capabilities.sourceHighWater)) {
    throw new Error(`${capabilities.profile} requires Merkle checkpoints and source high-water evidence`);
  }
  if (level >= 4) {
    if (!capabilities.independentObservation) {
      throw new Error('AAP-4 requires independent observation with authenticated comparison/gossip');
    }
    if (capabilities.supportingAnchors.length === 0) {
      throw new Error('AAP-4 requires at least one supporting checkpoint receipt');
    }
  }
}
