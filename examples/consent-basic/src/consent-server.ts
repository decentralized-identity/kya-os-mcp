#!/usr/bin/env npx tsx
/**
 * Consent HTTP Server
 *
 * Serves a consent page and issues W3C Delegation Credentials on approval.
 * This is the authorization endpoint in the MCP-I consent flow.
 *
 * Routes:
 *   GET  /consent  — Consent page with tool/scopes/agentDid injected
 *   POST /approve  — Issues a delegation VC and returns { delegationToken }
 *
 * Related Spec: MCP-I §4 (Delegation), §6 (Authorization)
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { NodeCryptoProvider } from '../../../src/providers/node-crypto.js';
import { generateDidKeyFromBase64 } from '../../../src/utils/did-helpers.js';
import {
  createDelegationIssuerFromIdentity,
  type AgentIdentityConfig,
  type DelegationIssuerFactory,
} from './delegation-issuer.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export interface DelegationStoreWriter {
  set(resumeToken: string, vc: unknown, ttlSeconds?: number): void;
}

export interface ConsentServerConfig {
  port: number;
  factory?: DelegationIssuerFactory;
  delegationStore?: DelegationStoreWriter;
}

export interface ConsentServer {
  server: http.Server;
  port: number;
  url: string;
  factory: DelegationIssuerFactory;
  close: () => Promise<void>;
}

/**
 * Create and start a consent HTTP server.
 *
 * @param config - Server configuration (port, optional pre-built factory)
 * @returns Running server with address info and cleanup handle
 */
export async function startConsentServer(
  config: ConsentServerConfig,
): Promise<ConsentServer> {
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

  const consentHtmlPath = path.resolve(__dirname, '..', 'public', 'consent.html');
  const consentTemplate = fs.readFileSync(consentHtmlPath, 'utf-8');

  const httpServer = http.createServer(async (req, res) => {
    // CORS headers for all responses
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url ?? '/', `http://localhost:${config.port}`);

    // GET /consent — serve consent page with query params injected
    if (url.pathname === '/consent' && req.method === 'GET') {
      const tool = url.searchParams.get('tool') ?? 'unknown';
      const scopes = url.searchParams.get('scopes') ?? 'unknown';
      const agentDid = url.searchParams.get('agent_did') ?? 'unknown';
      const sessionId = url.searchParams.get('session_id') ?? '';

      const html = consentTemplate
        .replaceAll('{{tool}}', escapeHtml(tool))
        .replaceAll('{{scopes}}', escapeHtml(scopes))
        .replaceAll('{{agentDid}}', escapeHtml(agentDid))
        .replaceAll('{{sessionId}}', escapeHtml(sessionId));

      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }

    // POST /approve — issue delegation VC
    if (url.pathname === '/approve' && req.method === 'POST') {
      try {
        const body = await readBody(req);
        const parsed = JSON.parse(body) as {
          tool?: string;
          scopes?: string;
          agentDid?: string;
          resumeToken?: string;
          format?: string;
        };
        const { tool, scopes, agentDid, resumeToken } = parsed;

        if (!tool || !scopes || !agentDid) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'missing_fields',
            message: 'tool, scopes, and agentDid are required',
          }));
          return;
        }

        const scopeList = scopes.split(',').map((s) => s.trim()).filter(Boolean);
        const subjectDid = agentDid;
        const delegationId = `delegation-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const nowSeconds = Math.floor(Date.now() / 1000);

        const delegationParams = {
          id: delegationId,
          issuerDid: factory.identity.did,
          subjectDid,
          constraints: {
            scopes: scopeList,
            notAfter: nowSeconds + 3600, // 1 hour expiry
          },
          metadata: { tool, approvedAt: new Date().toISOString() },
        };

        // Support VC-JWT format via ?format=jwt query param or body field
        const format = url.searchParams.get('format') ?? parsed.format;
        let delegationToken: unknown;

        if (format === 'jwt') {
          delegationToken = await factory.issueAsJWT(delegationParams);
        } else {
          delegationToken = await factory.issuer.createAndIssueDelegation(delegationParams);
        }

        // Store delegation so MCP server can auto-apply on retry
        if (resumeToken && config.delegationStore) {
          config.delegationStore.set(resumeToken, delegationToken);
          process.stderr.write(`[consent] Stored delegation for resume_token: ${resumeToken}\n`);
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ delegationToken }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'invalid_request',
          message: err instanceof Error ? err.message : 'Unknown error',
        }));
      }
      return;
    }

    // 404 for everything else
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

function readBody(req: http.IncomingMessage, maxBytes = 1_048_576): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    req.on('data', (chunk: Buffer) => {
      totalBytes += chunk.length;
      if (totalBytes > maxBytes) {
        req.destroy();
        reject(new Error('Request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
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
