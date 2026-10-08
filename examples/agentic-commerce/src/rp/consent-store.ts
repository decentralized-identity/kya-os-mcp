/** Private RP consent state. Atomic writes preserve single-use human decisions. */
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { canonicalizeJSON, type DelegationCredential } from '@kya-os/mcp';
import { writeJsonAtomic } from '../lib/atomic-json.js';
import { parseDigitalLink } from '../lib/product.js';
import { VAR_DIR, rpOrigin } from '../lib/wiring.js';
import { isLoopbackHttp, publicOrigin } from '../lib/public-origin.js';

import type { ConsentBindings, ConsentChallenge } from '../lib/consent-contract.js';
export type { ConsentBindings, ConsentChallenge } from '../lib/consent-contract.js';
import { tokenReference } from '../lib/consent-evidence.js';
export interface ConsentFlow {
  challenge: ConsentChallenge;
  bindings: ConsentBindings;
  state: 'pending' | 'issuing' | 'approved' | 'denied' | 'consumed' | 'failed';
  authentication?: Record<string, unknown>;
  auditPayload?: Record<string, unknown>;
  /** The checked subset approved by the human, persisted before issuance. */
  approvedScopes?: string[];
  createdAt: string;
  decidedAt?: string;
  credentialId?: string;
  credentialDigest?: string;
  index?: number;
  file?: string;
}
export interface ConsentAuditEvent {
  id: string;
  type:
    | 'consent.approved'
    | 'consent.denied'
    | 'delegation.issued'
    | 'delegation.revoked'
    // Read compatibility only: new assertions are committed inside consent.approved.
    | 'credential.verified';
  actor: string;
  payload: Record<string, unknown>;
}
interface StoreData {
  flows: Record<string, ConsentFlow>;
  events: ConsentAuditEvent[];
}
export class ConsentFlowError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ConsentFlowError';
  }
}
export type ConsentFields = Record<string, unknown>;
type ApprovedScopes = [string, ...string[]];
export type ApprovedConsentFlow = ConsentFlow & { approvedScopes: ApprovedScopes };
export class ConsentFlowStore {
  readonly dir: string;
  private readonly now: () => number;
  private readonly authorizationOrigin: string;
  private readonly configuredOrigin: boolean;
  constructor(options: { dir?: string; now?: () => number; authorizationOrigin?: string } = {}) {
    this.dir = options.dir ?? path.join(VAR_DIR, 'rp', 'consent');
    this.now = options.now ?? Date.now;
    this.authorizationOrigin = publicOrigin(options.authorizationOrigin ?? rpOrigin());
    this.configuredOrigin = options.authorizationOrigin !== undefined;
  }
  private read(): StoreData {
    const file = path.join(this.dir, 'flows.json');
    return fs.existsSync(file)
      ? (JSON.parse(fs.readFileSync(file, 'utf8')) as StoreData)
      : { flows: {}, events: [] };
  }
  private write(data: StoreData): void {
    writeJsonAtomic(path.join(this.dir, 'flows.json'), data);
  }
  private lock(): () => void {
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const lock = path.join(this.dir, '.lock');
    const acquire = () => {
      fs.mkdirSync(lock);
      fs.writeFileSync(
        path.join(lock, 'owner.json'),
        JSON.stringify({ pid: process.pid }),
        { mode: 0o600 },
      );
    };
    try {
      acquire();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      let dead = false;
      try {
        const owner = JSON.parse(
          fs.readFileSync(path.join(lock, 'owner.json'), 'utf8'),
        ) as { pid: number };
        try {
          process.kill(owner.pid, 0);
        } catch (failure) {
          dead = (failure as NodeJS.ErrnoException).code === 'ESRCH';
        }
      } catch {
        dead = Date.now() - fs.statSync(lock).mtimeMs > 5000;
      }
      if (!dead)
        throw new ConsentFlowError(
          'consent_busy',
          'A consent decision is already being processed.',
        );
      // A killed issuer cannot leave a permanent lock. Pending `issuing` flows
      // remain unusable; reset invalidates them before a new stage run.
      const abandoned = `${lock}.${randomUUID()}.abandoned`;
      fs.renameSync(lock, abandoned);
      fs.rmSync(abandoned, { recursive: true });
      try {
        acquire();
      } catch {
        throw new ConsentFlowError(
          'consent_busy',
          'A consent decision is already being processed.',
        );
      }
    }
    return () => fs.rmSync(lock, { recursive: true });
  }
  private validToken(token: string): boolean {
    return /^[A-Za-z0-9_-]{32,256}$/.test(token);
  }
  private required(data: StoreData, token: string): ConsentFlow {
    const flow = this.validToken(token) ? data.flows[token] : undefined;
    if (!flow)
      throw new ConsentFlowError(
        'consent_missing',
        'Consent request does not exist.',
      );
    if (flow.state === 'pending' && flow.challenge.expiresAt <= Math.floor(this.now() / 1000))
      throw new ConsentFlowError(
        'consent_expired',
        'Consent decision deadline expired. Request a fresh authorization.',
      );
    return flow;
  }
  private pending(flow: ConsentFlow): void {
    if (flow.state !== 'pending')
      throw new ConsentFlowError(
        `consent_${flow.state}`,
        `Consent request is already ${flow.state}.`,
      );
  }
  validateFields(flow: ConsentFlow, fields: ConsentFields): void {
    let scopes: unknown;
    try {
      scopes = JSON.parse(String(fields['scopes']));
    } catch {
      scopes = null;
    }
    const expected: Record<string, unknown> = {
      tool: 'place_order',
      agent_did: flow.bindings.agentDid,
      session_id: flow.challenge.resumeToken,
      audience: flow.bindings.audience,
      product: flow.bindings.product,
      quantity: flow.bindings.quantity,
      cap: flow.bindings.cap,
      currency: flow.bindings.currency,
      productClass: flow.bindings.productClass,
    };
    const mismatch =
      !Array.isArray(scopes) ||
      scopes.length !== 1 ||
      scopes[0] !== flow.bindings.productClass ||
      ['tool', 'agent_did', 'session_id'].some(
        (key) => fields[key] !== expected[key],
      ) ||
      Object.keys(expected).some(
        (key) =>
          fields[key] !== undefined &&
          String(fields[key]) !== String(expected[key]),
      );
    if (mismatch)
      throw new ConsentFlowError(
        'consent_binding_mismatch',
        'Consent form binding differs from the signed authorization request.',
      );
  }
  selectedScopes(flow: ConsentFlow, fields: ConsentFields): ApprovedScopes {
    let selected: unknown;
    try {
      selected = JSON.parse(String(fields['selected_scopes']));
    } catch {
      selected = null;
    }
    if (
      !Array.isArray(selected) || selected.length === 0 ||
      !selected.every((scope): scope is string => typeof scope === 'string') ||
      new Set(selected).size !== selected.length ||
      selected.some((scope) => !flow.challenge.scopes.includes(scope) || parseDigitalLink(scope)?.classUri !== scope)
    ) throw new ConsentFlowError(
      'consent_selection_invalid',
      'Select a displayed GS1 product-class scope. Empty, added, duplicate, or noncanonical scopes are not accepted.',
    );
    const first = selected[0];
    if (typeof first !== 'string') throw new ConsentFlowError('consent_selection_invalid', 'No scope was selected.');
    return [first, ...selected.slice(1)];
  }
  create(
    input: ConsentBindings & { resumeToken?: string; expiresAt?: number },
  ): ConsentChallenge {
    const unlock = this.lock();
    try {
      const {
        resumeToken = randomBytes(32).toString('base64url'),
        expiresAt = Math.floor(this.now() / 1000) + 600,
        ...bindings
      } = input;
      if (
        !this.validToken(resumeToken) ||
        expiresAt <= Math.floor(this.now() / 1000)
      )
        throw new ConsentFlowError(
          'consent_invalid',
          'Invalid challenge token or expiry.',
        );
      let origin: string;
      try { origin = publicOrigin(input.authorizationOrigin ?? this.authorizationOrigin); }
      catch {
        throw new ConsentFlowError('consent_invalid', 'Invalid authorization origin. Use the configured RP origin.');
      }
      // Direct local fixtures can use their own loopback port. A configured RP
      // always pins the exact origin, including scheme and port.
      if (origin !== this.authorizationOrigin && (this.configuredOrigin
        || !isLoopbackHttp(new URL(origin)) || !isLoopbackHttp(new URL(this.authorizationOrigin))))
        throw new ConsentFlowError(
          'consent_invalid',
          'The authorization origin must match the configured RP origin.',
        );
      const url = new URL('/consent', origin);
      url.searchParams.set('resume_token', resumeToken);
      url.searchParams.set('agent_did', bindings.agentDid);
      url.searchParams.set('scopes', bindings.productClass);
      url.searchParams.set('tool', 'place_order');
      const challenge: ConsentChallenge = {
        error: 'needs_authorization',
        message:
          'Human approval is required before this agent may place an order.',
        authorizationUrl: url.toString(),
        resumeToken,
        expiresAt,
        scopes: [bindings.productClass],
        display: { title: 'Approve the shopping agent grant', hint: ['link'] },
      };
      const data = this.read();
      if (data.flows[resumeToken])
        throw new ConsentFlowError(
          'consent_duplicate',
          'Consent token already exists.',
        );
      data.flows[resumeToken] = {
        challenge,
        bindings,
        state: 'pending',
        createdAt: new Date(this.now()).toISOString(),
      };
      this.write(data);
      return challenge;
    } finally {
      unlock();
    }
  }
  get(token: string): ConsentFlow | undefined {
    return this.validToken(token) ? this.read().flows[token] : undefined;
  }
  requirePending(token: string): ConsentFlow {
    const flow = this.required(this.read(), token);
    this.pending(flow);
    return flow;
  }
  findByCredential(id: string): ConsentFlow | undefined {
    return Object.values(this.read().flows).find(
      (flow) => flow.credentialId === id,
    );
  }
  async approve(
    token: string,
    fields: ConsentFields,
    issue: (
      flow: ApprovedConsentFlow,
    ) => Promise<{
      file: string;
      vc: DelegationCredential;
      authentication?: Record<string, unknown>;
    }>,
  ): Promise<ConsentFlow> {
    const unlock = this.lock();
    try {
      const data = this.read();
      const flow = this.required(data, token);
      this.pending(flow);
      this.validateFields(flow, fields);
      const approvedScopes = this.selectedScopes(flow, fields);
      flow.approvedScopes = approvedScopes;
      flow.state = 'issuing';
      this.write(data);
      try {
        const { file, vc, authentication } = await issue({ ...flow, approvedScopes });
        flow.state = 'approved';
        flow.decidedAt = new Date(this.now()).toISOString();
        flow.file = file;
        flow.credentialId = vc.id;
        flow.credentialDigest = `sha256:${createHash('sha256').update(canonicalizeJSON(vc)).digest('hex')}`;
        flow.index = Number(vc.credentialStatus?.statusListIndex);
        const demoConsent = vc.credentialSubject?.delegation?.metadata?.['demoConsent'];
        const consent = vc.credentialSubject?.delegation?.metadata?.['consent'] as { consentRef?: string } | undefined;
        const payload = {
          resumeTokenHash: createHash('sha256').update(token).digest('hex'),
          consentRef: tokenReference(token),
          agentDid: flow.bindings.agentDid,
          audience: flow.bindings.audience,
          credentialId: vc.id,
          index: flow.index,
          scope: approvedScopes[0],
          approvedScopes,
          cap: flow.bindings.cap,
          currency: flow.bindings.currency,
          at: flow.decidedAt,
          ...(consent ? { consentRef: consent.consentRef } : {}),
          ...(authentication ? { authentication } : {}),
          ...(demoConsent ? { demoConsent } : {}),
        };
        flow.auditPayload = payload;
        if (authentication) flow.authentication = authentication;
        data.events.push({
          id: randomUUID(),
          type: 'consent.approved',
          actor:
            typeof vc.issuer === 'string' ? vc.issuer : (vc.issuer?.id ?? ''),
          payload,
        });
        data.events.push({
          id: randomUUID(),
          type: 'delegation.issued',
          actor:
            typeof vc.issuer === 'string' ? vc.issuer : (vc.issuer?.id ?? ''),
          payload,
        });
        this.write(data);
        return flow;
      } catch (error) {
        flow.state = 'failed';
        this.write(data);
        throw error;
      }
    } finally {
      unlock();
    }
  }
  deny(
    token: string,
    fields: ConsentFields,
    responsibleParty?: string,
  ): ConsentFlow {
    const unlock = this.lock();
    try {
      const data = this.read();
      const flow = this.required(data, token);
      this.pending(flow);
      this.validateFields(flow, fields);
      flow.state = 'denied';
      flow.decidedAt = new Date(this.now()).toISOString();
      data.events.push({
        id: randomUUID(),
        type: 'consent.denied',
        actor: responsibleParty ?? flow.bindings.agentDid,
        payload: {
          resumeTokenHash: createHash('sha256').update(token).digest('hex'),
          consentRef: tokenReference(token),
          agentDid: flow.bindings.agentDid,
          audience: flow.bindings.audience,
          scope: flow.bindings.productClass,
          at: flow.decidedAt,
        },
      });
      this.write(data);
      return flow;
    } finally {
      unlock();
    }
  }
  consume(
    token: string,
    bindings: {
      agentDid: string;
      audience: string;
      credentialId: string;
      credentialDigest: string;
    },
  ): ConsentFlow {
    const unlock = this.lock();
    try {
      const data = this.read();
      const flow = this.required(data, token);
      if (flow.state !== 'approved')
        throw new ConsentFlowError(
          `consent_${flow.state}`,
          `Consent request is ${flow.state}.`,
        );
      if (
        bindings.agentDid !== flow.bindings.agentDid ||
        bindings.audience !== flow.bindings.audience ||
        bindings.credentialId !== flow.credentialId ||
        !flow.credentialDigest || bindings.credentialDigest !== flow.credentialDigest
      )
        throw new ConsentFlowError(
          'consent_binding_mismatch',
          'Resume token binding differs from this agent, merchant, or approved credential.',
        );
      flow.state = 'consumed';
      this.write(data);
      return flow;
    } finally {
      unlock();
    }
  }
  appendEvent(event: Omit<ConsentAuditEvent, 'id'>): ConsentAuditEvent {
    const unlock = this.lock();
    try {
      const data = this.read();
      const entry = { ...event, id: randomUUID() };
      data.events.push(entry);
      this.write(data);
      return entry;
    } finally {
      unlock();
    }
  }
  invalidatePending(): void {
    const unlock = this.lock();
    try {
      const data = this.read();
      for (const flow of Object.values(data.flows))
        if (['pending', 'issuing', 'approved'].includes(flow.state))
          flow.state = 'failed';
      this.write(data);
    } finally {
      unlock();
    }
  }
  pendingEvents(): ConsentAuditEvent[] {
    return this.read().events;
  }
  acknowledgeEvents(ids: string[]): void {
    if (!ids.length) return;
    const unlock = this.lock();
    try {
      const data = this.read();
      data.events = data.events.filter((event) => !ids.includes(event.id));
      this.write(data);
    } finally {
      unlock();
    }
  }
}
