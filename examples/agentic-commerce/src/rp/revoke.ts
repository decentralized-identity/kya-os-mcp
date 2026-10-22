#!/usr/bin/env npx tsx
/**
 * THE KILL SWITCH, hub edition: load the latest list → set the bit → re-sign
 * with the RP's did:web key → publish as the next version. The merchant's next
 * fetch (it fetches on every call) reads the new signature and the set bit.
 *
 * Usage: npm run revoke [-- --index 94] [--restore]
 */
import { STATUS_LIST_URL, loadRpIdentity, makeVcSigningFunction, readJson, type KeyedIdentity } from '../lib/wiring.js';
import { activeIndex, delegationFile } from './issue.js';
import { ConsentFlowStore } from './consent-store.js';
import type { DelegationCredential } from '@kya-os/mcp';
import { ensureStatusList, loadStatusList, readBit, resignWithBit, saveStatusListVersion, type StatusListMeta } from './statuslist.js';

export interface RevokePhase {
  phase: 'load' | 'sign' | 'publish' | 'verify';
  detail: string;
  elapsedMs: number;
}

export interface RevokeOutcome {
  index: number;
  revoked: boolean;
  version: number;
  publishedAt: string;
  totalMs: number;
  audit?: 'recorded' | 'unavailable';
}

export async function revokeIndex(
  index: number,
  options?: { restore?: boolean; identity?: KeyedIdentity; statusListUrl?: string; onPhase?: (p: RevokePhase) => void },
): Promise<RevokeOutcome> {
  const revoked = !options?.restore;
  const identity = options?.identity ?? loadRpIdentity();
  const url = options?.statusListUrl ?? STATUS_LIST_URL;
  const signingFunction = makeVcSigningFunction(identity.privateKeyBase64);
  const started = Date.now();
  const emit = (phase: RevokePhase['phase'], detail: string) =>
    options?.onPhase?.({ phase, detail, elapsedMs: Date.now() - started });

  emit('load', 'loading the latest signed status list from the hub');
  const current = loadStatusList() ?? (await ensureStatusList({ identity, signingFunction, url }));

  emit('sign', `setting bit ${index} → ${revoked ? '1 (REVOKED)' : '0 (restored)'} and re-signing with ${identity.kid}`);
  const updated = await resignWithBit({ credential: current, index, revoked, identity, signingFunction });

  emit('publish', 'publishing the new version at the status-list URL');
  const meta: StatusListMeta = saveStatusListVersion(updated, { action: revoked ? 'revoke' : 'restore', index, at: new Date().toISOString() });

  emit('verify', 'reading the published bit back');
  const bit = await readBit(loadStatusList()!, index);
  if (bit !== revoked) throw new Error(`Published list disagrees: bit ${index} is not ${revoked ? 'set' : 'clear'}`);

  if (revoked) {
    const vc = readJson<DelegationCredential>(delegationFile(index));
    const scope = vc?.credentialSubject.delegation.constraints.crisp?.scopes?.[0];
    new ConsentFlowStore().appendEvent({ type: 'delegation.revoked', actor: identity.did, payload: {
      credentialId: vc?.id ?? `status-list-index-${index}`, index, scope: scope?.resource ?? '',
      cap: scope?.constraints?.['maxAmount'] ?? '', currency: scope?.constraints?.['currency'] ?? '',
      consentRef: (vc?.credentialSubject.delegation.metadata?.['consent'] as { consentRef?: string } | undefined)?.consentRef,
      statusListUrl: url, version: meta.version, at: meta.updatedAt,
    } });
  }
  return { index, revoked, version: meta.version, publishedAt: meta.updatedAt, totalMs: Date.now() - started };
}

const isMain = process.argv[1]?.endsWith('revoke.ts');
if (isMain) {
  const indexArg = process.argv.indexOf('--index');
  const index = Number(indexArg > -1 ? process.argv[indexArg + 1]! : activeIndex());
  const restore = process.argv.includes('--restore');
  revokeIndex(index, { restore, onPhase: (p) => console.log(`[+${String(p.elapsedMs).padStart(5)} ms] ${p.phase}: ${p.detail}`) })
    .then((r) => {
      console.log(JSON.stringify(r, null, 2));
      console.log(restore
        ? '\nBit cleared. (Demo reset — in production, un-revocation is a new consent ceremony.)'
        : '\nEvery verifier that fetches this list now reads the revocation.');
    })
    .catch((err) => { console.error(err); process.exit(1); });
}
