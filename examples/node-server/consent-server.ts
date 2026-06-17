#!/usr/bin/env npx tsx
/**
 * Consent HTTP Server (powered by @kya-os/consent)
 *
 * This is the core differentiator from consent-basic. It replaces 200+ lines
 * of hand-rolled HTML with a single generateConsentShell() call from
 * @kya-os/consent — multi-mode auth, loading skeleton, branding, and no-JS
 * fallback included.
 *
 * Routes:
 *   GET  /consent          — Consent page via @kya-os/consent
 *   GET  /consent.js       — Consent component bundle
 *   POST /consent/approve  — Issues a delegation VC (accepts FormData or JSON)
 *
 * Auth modes (AUTH_MODE env var):
 *   consent-only  (default) — Approve/deny only. Zero config.
 *   credentials             — Username/password + approve. Demo credentials: demo / demo123
 *
 * Related Spec: KYA-OS §4 (Delegation), §6 (Authorization)
 */

import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateConsentShell } from '@kya-os/consent/bundle/shell';
import { CONSENT_BUNDLE } from '@kya-os/consent/bundle/inline';
import type { ConsentConfig } from '@kya-os/consent/types';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';
import {
  createDelegationIssuerFromIdentity,
  type AgentIdentityConfig,
  type DelegationIssuerFactory,
} from './delegation-issuer.js';

export type AuthMode = 'consent-only' | 'credentials';

/** Delegation VC time-to-live in seconds (1 hour). */
const DELEGATION_TTL_SECONDS = 3600;

export interface DelegationStoreWriter {
  set(resumeToken: string, vc: unknown, ttlSeconds?: number): void;
}

export interface ConsentServerConfig {
  port: number;
  factory?: DelegationIssuerFactory;
  delegationStore?: DelegationStoreWriter;
  authMode?: AuthMode;
  branding?: { primaryColor?: string; companyName?: string };
}

export interface ConsentServer {
  server: http.Server;
  port: number;
  url: string;
  factory: DelegationIssuerFactory;
  close: () => Promise<void>;
}

/**
 * Create and start a consent HTTP server powered by @kya-os/consent.
 */
export async function startConsentServer(
  config: ConsentServerConfig,
): Promise<ConsentServer> {
  const authMode: AuthMode = config.authMode
    ?? (process.env['AUTH_MODE'] as AuthMode | undefined)
    ?? 'consent-only';

  let factory: DelegationIssuerFactory;
  if (config.factory) {
    factory = config.factory;
  } else {
    const crypto = new NodeCryptoProvider();
    const keyPair = await crypto.generateKeyPair();
    const did = generateDidKeyFromBase64(keyPair.publicKey);
    const identity: AgentIdentityConfig = {
      did,
      kid: `${did}#${did.replace('did:key:', '')}`,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
    };
    factory = createDelegationIssuerFromIdentity(crypto, identity);
  }

  const consentConfig: ConsentConfig = {
    branding: {
      primaryColor: config.branding?.primaryColor ?? process.env['BRAND_COLOR'] ?? '#2563EB',
      companyName: config.branding?.companyName ?? process.env['COMPANY_NAME'] ?? 'KYA-OS Demo',
    },
    ui: {
      title: 'Permission Request',
      description: '[AI Agent] is requesting access to resources on your behalf.',
      theme: 'auto',
    },
    terms: { required: false },
    expirationDays: 1,
  };

  const httpServer = http.createServer(async (req, res) => {
    // EXAMPLE ONLY — restrict to your consent page origin in production
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const addr = httpServer.address();
    const actualPort = typeof addr === 'object' && addr ? addr.port : config.port;
    const url = new URL(req.url ?? '/', `http://localhost:${actualPort}`);

    // GET /consent — consent page via @kya-os/consent
    if (url.pathname === '/consent' && req.method === 'GET') {
      const tool = url.searchParams.get('tool') ?? 'unknown';
      const scopesRaw = url.searchParams.get('scopes') ?? '';
      const agentDid = url.searchParams.get('agent_did') ?? 'unknown';
      const resumeToken = url.searchParams.get('resume_token') ?? '';
      const scopes = scopesRaw.split(',').map(s => s.trim()).filter(Boolean);

      const html = generateConsentShell({
        config: consentConfig,
        tool,
        scopes,
        agentDid,
        // @kya-os/consent uses session_id internally; maps 1:1 with KYA-OS resume_token
        sessionId: resumeToken,
        projectId: 'node-server-example',
        serverUrl: `http://localhost:${actualPort}`,
        authMode,
      });

      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }

    // GET /consent.js — serve the @kya-os/consent component bundle
    if (url.pathname === '/consent.js' && req.method === 'GET') {
      res.writeHead(200, {
        'Content-Type': 'application/javascript; charset=utf-8',
        'Cache-Control': 'public, max-age=3600',
      });
      res.end(CONSENT_BUNDLE);
      return;
    }

    // POST /consent/approve — issue delegation VC
    if (url.pathname === '/consent/approve' && req.method === 'POST') {
      try {
        const fields = await parseApprovalBody(req);
        const tool = fields['tool'];
        const scopesRaw = fields['scopes'];
        const agentDid = fields['agent_did'];
        const sessionId = fields['session_id'] ?? ''; // This is the resume_token
        const requestAuthMode = fields['auth_mode'] ?? 'consent-only';

        if (typeof tool !== 'string' || typeof scopesRaw !== 'string' || typeof agentDid !== 'string') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'missing_fields',
            message: 'tool, scopes, and agent_did are required',
          }));
          return;
        }

        // EXAMPLE ONLY — replace with real credential validation in production
        if (requestAuthMode === 'credentials') {
          const username = fields['username'] ?? '';
          const password = fields['password'] ?? '';
          if (username !== 'demo' || password !== 'demo123') {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              error: 'invalid_credentials',
              message: 'Invalid username or password',
            }));
            return;
          }
        }

        // Parse scopes — FormData sends as JSON string, plain strings also accepted
        let scopeList: string[];
        try {
          scopeList = JSON.parse(scopesRaw) as string[];
        } catch {
          scopeList = scopesRaw.split(',').map(s => s.trim()).filter(Boolean);
        }

        const delegationId = `delegation-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const nowSeconds = Math.floor(Date.now() / 1000);

        const vc = await factory.issuer.createAndIssueDelegation({
          id: delegationId,
          issuerDid: factory.identity.did,
          subjectDid: agentDid,
          constraints: {
            scopes: scopeList,
            notAfter: nowSeconds + DELEGATION_TTL_SECONDS,
          },
          metadata: { tool, approvedAt: new Date().toISOString() },
        });

        // Store VC in delegation store for auto-apply on retry
        if (sessionId && config.delegationStore) {
          config.delegationStore.set(sessionId, vc);
          process.stderr.write(`[consent] Stored delegation for resume_token: ${sessionId}\n`);
        }

        // Response includes delegation_id for the <mcp-consent> component's
        // success event (ConsentApproveDetail) and delegationToken for API clients.
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          delegation_id: delegationId,
          delegationToken: vc,
        }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'internal_error',
          message: err instanceof Error ? err.message : 'Unknown error',
        }));
      }
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found' }));
  });

  return new Promise((resolve, reject) => {
    httpServer.once('error', reject);
    httpServer.listen(config.port, () => {
      const addr = httpServer.address();
      const actualPort = typeof addr === 'object' && addr ? addr.port : config.port;
      const serverUrl = `http://localhost:${actualPort}`;

      process.stderr.write(`[consent] Consent server: ${serverUrl}\n`);
      process.stderr.write(`[consent] Auth mode: ${authMode}\n`);
      process.stderr.write(`[consent] Issuer DID: ${factory.identity.did}\n`);

      resolve({
        server: httpServer,
        port: actualPort,
        url: serverUrl,
        factory,
        close: () => new Promise<void>((res) => httpServer.close(() => res())),
      });
    });
  });
}

/**
 * Parse approval body — supports both FormData (from <mcp-consent>)
 * and JSON (from API clients/tests).
 */
async function parseApprovalBody(req: http.IncomingMessage): Promise<Record<string, string>> {
  const contentType = req.headers['content-type'] ?? '';
  const chunks: Buffer[] = [];
  let totalBytes = 0;

  for await (const chunk of req) {
    totalBytes += (chunk as Buffer).length;
    if (totalBytes > 1_048_576) throw new Error('Request body too large');
    chunks.push(chunk as Buffer);
  }

  const rawBody = Buffer.concat(chunks);

  // JSON bodies (from tests, API clients)
  if (contentType.includes('application/json')) {
    return JSON.parse(rawBody.toString('utf-8')) as Record<string, string>;
  }

  // FormData bodies (from <mcp-consent> web component) — use Web Request API
  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(req.headers)) {
    if (typeof value === 'string') headers[key] = value;
  }

  const webReq = new Request(`http://localhost${req.url}`, {
    method: 'POST',
    headers,
    body: rawBody,
  });

  const formData = await webReq.formData();
  const result: Record<string, string> = {};
  for (const [key, value] of formData.entries()) {
    if (typeof value === 'string') result[key] = value;
  }
  return result;
}

// Run standalone when executed directly
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const port = parseInt(process.env['CONSENT_PORT'] ?? '3001', 10);
  startConsentServer({ port }).catch((err) => {
    process.stderr.write(`Fatal: ${err}\n`);
    process.exit(1);
  });
}
