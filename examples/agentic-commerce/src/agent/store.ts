import path from 'node:path';
import fs from 'node:fs';
import type { DelegationCredential } from '@kya-os/mcp';
import { VAR_DIR, readJson } from '../lib/wiring.js';
import { writeJsonAtomic } from '../lib/atomic-json.js';
import type { MerchantToolResult } from './authorization.js';
import type { ConsentChallenge } from '../lib/consent-contract.js';
import type { PaymentRequired } from '@x402/core/types';
import type { X402PaymentPayload } from '../payments/x402.js';

export interface AgentState { credential?: DelegationCredential; pending?: ConsentChallenge; challengeResult?: MerchantToolResult }
export const AGENT_STATE_FILE = path.join(VAR_DIR, 'agent', 'state.json');
export const readAgentState = (): AgentState => {
  // Ignore the obsolete first-use token in older local state without requiring
  // a reset or a disk write after an order has already been accepted.
  const { resumeToken: _legacyToken, ...state } = readJson<AgentState & { resumeToken?: unknown }>(AGENT_STATE_FILE) ?? {};
  return state;
};
export const saveAgentState = (state: AgentState): void => writeJsonAtomic(AGENT_STATE_FILE, state);
export const clearAgentState = (): void => { fs.rmSync(AGENT_STATE_FILE, { force: true }); };

/** Payment recovery survives grant resets; only the agent owns this journal. */
export interface AgentCheckout {
  id: string;
  protocol: 'x402' | 'ucp';
  rail: 'x402' | 'sandbox-token';
  product: string;
  quantity: number;
  merchantOrigin: string;
  audience: string;
  state: 'open' | 'submitted' | 'pending' | 'completed' | 'failed';
  termsDigest?: string;
  paymentRequired?: PaymentRequired;
  payload?: X402PaymentPayload;
  token?: string;
  createKey?: string;
  completeKey?: string;
  remoteId?: string;
  intent?: { product: string; quantity: number; checkout: { id: string; protocol: 'ucp'; termsDigest: string } };
  lastResult?: MerchantToolResult;
}
export const AGENT_COMMERCE_FILE = path.join(VAR_DIR, 'agent', 'commerce.json');
export const AGENT_PAYMENT_WALLET_FILE = path.join(VAR_DIR, 'agent', 'payment-wallet.json');
export function readAgentCheckouts(): Record<string, AgentCheckout> {
  return readJson<Record<string, AgentCheckout>>(AGENT_COMMERCE_FILE) ?? {};
}
export function readAgentCheckout(id: string): AgentCheckout | null {
  const checkouts = readAgentCheckouts();
  return checkouts[id] ?? Object.values(checkouts).find(checkout => checkout.remoteId === id) ?? null;
}
export function saveAgentCheckout(checkout: AgentCheckout): void {
  const checkouts = readAgentCheckouts();
  if (!checkouts[checkout.id] && Object.keys(checkouts).length >= 5000) throw new Error('AGENT_PAYMENT_STORAGE_FULL');
  checkouts[checkout.id] = checkout;
  writeJsonAtomic(AGENT_COMMERCE_FILE, checkouts);
}
