import { describe, it, expect, vi } from 'vitest';
import {
  createKyaOsMiddleware,
  type KyaOsAuditTrail,
  type KyaOsDelegationConfig,
} from '../with-kya-os.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { MockFetchProvider } from '../../__tests__/utils/mock-providers.js';
import { generateDidKeyFromBase64 } from '../../utils/did-helpers.js';
import { DelegationCredentialIssuer } from '../../delegation/vc-issuer.js';
import type {
  CredentialStatus,
  DelegationCredential,
  Proof,
} from '../../types/protocol.js';
import {
  base64ToBytes,
  base64urlEncodeFromBytes,
} from '../../utils/base64.js';
import { AuditLogProvider, MemoryAuditLogProvider } from '../../providers/audit-log.js';
import { cheqdResolver } from '../../integrations/cheqd/index.js';
import { KYA_OS_PROOF_META_KEY, LEGACY_PROOF_META_KEY } from '../../proof/index.js';

async function createTestMiddleware(options?: {
  autoSession?: boolean;
  delegation?: KyaOsDelegationConfig;
  audit?: KyaOsAuditTrail | false;
  auditLog?: AuditLogProvider;
  emitLegacyProofKey?: boolean;
}) {
  const crypto = new NodeCryptoProvider();
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  const kid = `${did}#${did.replace('did:key:', '')}`;

  const middleware = createKyaOsMiddleware(
    {
      identity: { did, kid, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey },
      session: { sessionTtlMinutes: 60 },
      delegation: options?.delegation,
      audit: options?.audit,
      autoSession: options?.autoSession,
      auditLog: options?.auditLog,
      ...(options?.emitLegacyProofKey !== undefined
        ? { emitLegacyProofKey: options.emitLegacyProofKey }
        : {}),
    },
    crypto,
  );

  return { middleware, did, crypto };
}

async function createDelegationIssuer(options?: { did?: string; kid?: string }) {
  const crypto = new NodeCryptoProvider();
  const keyPair = await crypto.generateKeyPair();
  const did = options?.did ?? generateDidKeyFromBase64(keyPair.publicKey);
  const kid = options?.kid ?? `${did}#${did.replace('did:key:', '')}`;

  const signingFn = async (
    canonicalVC: string,
    _issuerDid: string,
    kidArg: string,
  ): Promise<Proof> => {
    const data = new TextEncoder().encode(canonicalVC);
    const sigBytes = await crypto.sign(data, keyPair.privateKey);
    const proofValue = base64urlEncodeFromBytes(sigBytes);
    return {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: kidArg,
      proofPurpose: 'assertionMethod',
      proofValue,
    };
  };

  const issuer = new DelegationCredentialIssuer(
    {
      getDid: () => did,
      getKeyId: () => kid,
      getPrivateKey: () => keyPair.privateKey,
    },
    signingFn,
  );

  return { crypto, keyPair, did, kid, issuer };
}

async function issueDelegationVC(options?: {
  issuer?: Awaited<ReturnType<typeof createDelegationIssuer>>;
  scopes?: string[];
  audience?: string | string[];
  parentId?: string;
  credentialStatus?: CredentialStatus;
  subjectDid?: string;
  crispScopes?: { resource: string; matcher: 'exact' | 'prefix' | 'regex' }[];
}): Promise<DelegationCredential> {
  const issuerIdentity = options?.issuer ?? await createDelegationIssuer();

  return issuerIdentity.issuer.createAndIssueDelegation(
    {
      id: `test-delegation-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      issuerDid: issuerIdentity.did,
      subjectDid: options?.subjectDid ?? issuerIdentity.did,
      parentId: options?.parentId,
      constraints: {
        scopes: options?.scopes ?? [],
        ...(options?.crispScopes ? { crisp: { scopes: options.crispScopes } } : {}),
        ...(options?.audience !== undefined && { audience: options.audience }),
        notAfter: Math.floor(Date.now() / 1000) + 3600,
      },
    },
    ...(options?.credentialStatus
      ? [{ credentialStatus: options.credentialStatus }]
      : []),
  );
}

describe('createKyaOsMiddleware', () => {
  describe('handleHandshake', () => {
    it('should establish a session with valid handshake', async () => {
      const { middleware: kyaos, did } = await createTestMiddleware();
      const result = await kyaos.handleHandshake({
        nonce: 'test-nonce',
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.success).toBe(true);
      expect(parsed.sessionId).toMatch(/^kyaos_/);
      expect(parsed.serverDid).toMatch(/^did:key:/);
    });

    it('should reject invalid handshake', async () => {
      const { middleware: kyaos } = await createTestMiddleware();
      const result = await kyaos.handleHandshake({ nonce: 'test' });

      expect(result.isError).toBe(true);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.success).toBe(false);
      expect(parsed.error.code).toBe('handshake_failed');
    });
  });

  describe('_kyaos unified tool', () => {
    it('should expose kyaOsTool with name "_kyaos"', async () => {
      const { middleware: kyaos } = await createTestMiddleware();
      expect(kyaos.kyaOsTool.name).toBe('_kyaos');
      expect(kyaos.kyaOsTool.inputSchema.properties?.action).toBeDefined();
      expect(
        (kyaos.kyaOsTool.inputSchema.properties?.action as { enum?: string[] })?.enum,
      ).toContain('handshake');
      expect(
        (kyaos.kyaOsTool.inputSchema.properties?.action as { enum?: string[] })?.enum,
      ).toContain('identity');
      expect(kyaos.kyaOsTool.inputSchema.required).toEqual(['action']);
    });

    it('should still expose handshakeTool as deprecated alias', async () => {
      const { middleware: kyaos } = await createTestMiddleware();
      expect(kyaos.handshakeTool).toBeDefined();
      expect(kyaos.handshakeTool.name).toBe('_kyaos_handshake');
    });

    it('should dispatch action: "handshake" to handleHandshake', async () => {
      const { middleware: kyaos, did } = await createTestMiddleware();
      const result = await kyaos.handleKyaOs({
        action: 'handshake',
        nonce: 'test-nonce',
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.success).toBe(true);
      expect(parsed.sessionId).toMatch(/^kyaos_/);
    });

    it('should dispatch action: "identity" and return server metadata', async () => {
      const { middleware: kyaos, did } = await createTestMiddleware();
      const result = await kyaos.handleKyaOs({ action: 'identity' });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.did).toBe(did);
      expect(parsed.kid).toMatch(/#z[\w]+$/);
      expect(parsed.capabilities).toContain('handshake');
      expect(parsed.capabilities).toContain('signing');
      expect(parsed.capabilities).toContain('verification');
      expect(parsed.auditAssurance).toEqual({ enabled: false, profile: 'AAP-0' });
    });

    it('should advertise the configured audit assurance and capabilities', async () => {
      const capabilities = {
        profile: 'AAP-2' as const,
        recorderTopology: 'self-hosted' as const,
        delivery: 'required' as const,
        journalDurability: 'durable' as const,
        atomicAppend: true,
        sourceHighWater: false,
        merkleCheckpoints: false,
        independentObservation: false,
        supportingAnchors: [],
        evidenceRetention: 'separate' as const,
      };
      const { middleware: kyaos } = await createTestMiddleware({
        audit: {
          record: async (event) => ({ status: 'pending', event: event as never }),
          capabilities,
        },
      });

      const result = await kyaos.handleKyaOs({ action: 'identity' });
      const parsed = JSON.parse(result.content[0].text);

      expect(parsed.auditAssurance).toEqual({
        enabled: true,
        profile: 'AAP-2',
        capabilities,
      });
    });

    it('should default an enabled audit adapter to AAP-1 without capabilities', async () => {
      const { middleware: kyaos } = await createTestMiddleware({
        audit: {
          record: async (event) => ({ status: 'pending', event: event as never }),
        },
      });

      const result = await kyaos.handleKyaOs({ action: 'identity' });
      const parsed = JSON.parse(result.content[0].text);

      expect(parsed.auditAssurance).toEqual({ enabled: true, profile: 'AAP-1' });
    });

    it('should let an explicit audit profile override capability inference', async () => {
      const { middleware: kyaos } = await createTestMiddleware({
        audit: {
          record: async (event) => ({ status: 'pending', event: event as never }),
          auditProfile: 'AAP-3',
        },
      });

      const result = await kyaos.handleKyaOs({ action: 'identity' });
      const parsed = JSON.parse(result.content[0].text);

      expect(parsed.auditAssurance).toEqual({ enabled: true, profile: 'AAP-3' });
    });

    it('should advertise AAP-0 when audit is explicitly disabled', async () => {
      const { middleware: kyaos } = await createTestMiddleware({ audit: false });

      const result = await kyaos.handleKyaOs({ action: 'identity' });
      const parsed = JSON.parse(result.content[0].text);

      expect(parsed.auditAssurance).toEqual({ enabled: false, profile: 'AAP-0' });
    });

    it('should return error for unknown action', async () => {
      const { middleware: kyaos } = await createTestMiddleware();
      const result = await kyaos.handleKyaOs({ action: 'does_not_exist' });

      expect(result.isError).toBe(true);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error.code).toBe('invalid_request');
    });

    it('should return error when action is missing', async () => {
      const { middleware: kyaos } = await createTestMiddleware();
      const result = await kyaos.handleKyaOs({});

      expect(result.isError).toBe(true);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error.code).toBe('invalid_request');
    });

    it('should return "not implemented" for action: "reputation"', async () => {
      const { middleware: kyaos } = await createTestMiddleware();
      const result = await kyaos.handleKyaOs({ action: 'reputation' });

      expect(result.isError).toBe(true);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error.code).toBe('runtime_error');
    });

    it('should still support handleHandshake() directly (backward compat)', async () => {
      const { middleware: kyaos, did } = await createTestMiddleware();
      const result = await kyaos.handleHandshake({
        nonce: 'legacy-nonce',
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.success).toBe(true);
    });
  });

  describe('wrapWithProof', () => {
    it('should attach proof in _meta after handshake', async () => {
      const { middleware: kyaos, did } = await createTestMiddleware();

      // Handshake first
      const hs = await kyaos.handleHandshake({
        nonce: 'test-nonce',
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });
      const sessionId = JSON.parse(hs.content[0].text).sessionId;

      // Call wrapped tool
      const handler = kyaos.wrapWithProof('greet', async (args) => ({
        content: [{ type: 'text', text: `Hello, ${args['name']}!` }],
      }));

      const result = await handler({ name: 'DIF' }, sessionId);

      // Tool result in content (single block)
      expect(result.content).toHaveLength(1);
      expect(result.content[0].text).toBe('Hello, DIF!');

      // Proof in _meta, not in content
      expect(result._meta).toBeDefined();
      expect(result._meta![KYA_OS_PROOF_META_KEY]).toBeDefined();
      const proof = result._meta![KYA_OS_PROOF_META_KEY] as { jws: string; meta: Record<string, unknown> };
      expect(proof.jws).toBeDefined();
      expect(proof.meta.did).toMatch(/^did:key:/);
      expect(proof.meta.sessionId).toBe(sessionId);
      expect(proof.meta.requestHash).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(proof.meta.responseHash).toMatch(/^sha256:[a-f0-9]{64}$/);
    });

    it('should not attach proof when result is an error', async () => {
      const { middleware: kyaos, did } = await createTestMiddleware();

      const hs = await kyaos.handleHandshake({
        nonce: 'test-nonce',
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });
      const sessionId = JSON.parse(hs.content[0].text).sessionId;

      const handler = kyaos.wrapWithProof('fail-tool', async () => ({
        content: [{ type: 'text', text: 'error' }],
        isError: true,
      }));

      const result = await handler({}, sessionId);
      expect(result.isError).toBe(true);
      expect(result._meta).toBeUndefined();
    });

    it('logs an audit record to the configured AuditLogProvider after a proofed call', async () => {
      const auditLog = new MemoryAuditLogProvider();
      const { middleware: kyaos, did } = await createTestMiddleware({ auditLog });

      const hs = await kyaos.handleHandshake({
        nonce: 'audit-nonce',
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });
      const sessionId = JSON.parse(hs.content[0].text).sessionId;

      const handler = kyaos.wrapWithProof('greet', async () => ({
        content: [{ type: 'text', text: 'hi' }],
      }));
      await handler({}, sessionId);

      expect(auditLog.records).toHaveLength(1);
      const rec = auditLog.records[0]!;
      expect(rec.version).toBe('audit.v1');
      expect(rec.session).toBe(sessionId);
      expect(rec.audience).toBe(did);
      expect(rec.did).toBe(did);
      expect(rec.verified).toBe('yes');
      expect(rec.reqHash).toMatch(/^sha256:[a-f0-9]{64}$/);
    });

    it('does not break the tool response when the audit sink throws', async () => {
      class ThrowingAuditLog extends AuditLogProvider {
        async logAuditRecord(): Promise<void> {
          throw new Error('sink down');
        }
        async logEvent(): Promise<void> {}
      }
      const { middleware: kyaos, did } = await createTestMiddleware({
        auditLog: new ThrowingAuditLog(),
      });

      const hs = await kyaos.handleHandshake({
        nonce: 'audit-nonce-2',
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });
      const sessionId = JSON.parse(hs.content[0].text).sessionId;

      const handler = kyaos.wrapWithProof('greet', async () => ({
        content: [{ type: 'text', text: 'hi' }],
      }));
      const result = await handler({}, sessionId);

      // The proofed response must be intact despite the sink failure.
      expect(result.content[0].text).toBe('hi');
      expect(result._meta![KYA_OS_PROOF_META_KEY]).toBeDefined();
    });

    it('records the delegation scope when threaded via call context', async () => {
      const auditLog = new MemoryAuditLogProvider();
      const { middleware: kyaos, did } = await createTestMiddleware({ auditLog });

      const hs = await kyaos.handleHandshake({
        nonce: 'audit-scope-nonce',
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });
      const sessionId = JSON.parse(hs.content[0].text).sessionId;

      const handler = kyaos.wrapWithProof('greet', async () => ({
        content: [{ type: 'text', text: 'hi' }],
      }));
      // wrapWithDelegation threads its scopeId as the 3rd (context) argument.
      await handler({}, sessionId, { scopeId: 'calendar:read' });

      expect(auditLog.records[0]!.scope).toBe('calendar:read');
    });

    it('should return result without proof when no session exists and autoSession is off', async () => {
      const { middleware: kyaos } = await createTestMiddleware({ autoSession: false });

      const handler = kyaos.wrapWithProof('greet', async () => ({
        content: [{ type: 'text', text: 'Hello!' }],
      }));

      const result = await handler({});
      expect(result.content[0].text).toBe('Hello!');
      expect(result._meta).toBeUndefined();
    });

    it('should surface proofError in _meta when proof generation fails', async () => {
      const { middleware: kyaos, did, crypto } = await createTestMiddleware();

      // Handshake first
      const hs = await kyaos.handleHandshake({
        nonce: 'test-nonce-proof-fail',
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });
      const sessionId = JSON.parse(hs.content[0].text).sessionId;

      // Make crypto.hash throw to break proof generation after handshake succeeds
      vi.spyOn(crypto, 'hash').mockRejectedValue(new Error('HSM unavailable'));

      const handler = kyaos.wrapWithProof('greet', async () => ({
        content: [{ type: 'text', text: 'Hello!' }],
      }));

      const result = await handler({}, sessionId);

      // Tool result still returned
      expect(result.content[0].text).toBe('Hello!');
      expect(result.isError).toBeUndefined();

      // But _meta signals the proof failure
      expect(result._meta).toBeDefined();
      expect(result._meta!.proofError).toBeDefined();
      expect(result._meta![KYA_OS_PROOF_META_KEY]).toBeUndefined();
    });
  });

  describe('wrapWithDelegation', () => {
    it('should return needs_authorization when no _kyaos_delegation arg is provided', async () => {
      const { middleware: kyaos } = await createTestMiddleware();

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      const result = await handler({ name: 'world' });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBe('needs_authorization');
      expect(parsed.authorizationUrl).toBe('https://example.com/consent');
      expect(parsed.scopes).toContain('test:scope');
      expect(typeof parsed.resumeToken).toBe('string');
      expect(typeof parsed.expiresAt).toBe('number');
    });

    it('should reject when VC has wrong scope', async () => {
      const { middleware: kyaos } = await createTestMiddleware();
      const vc = await issueDelegationVC({ scopes: ['wrong:scope'] });

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      const result = await handler({ _kyaos_delegation: vc });

      expect(result.isError).toBe(true);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBe('insufficient_scope');
    });

    it('emits a signed denial proof (outcome=denied) on insufficient scope', async () => {
      const { middleware: kyaos, did } = await createTestMiddleware();
      const hs = await kyaos.handleHandshake({
        nonce: 'test-nonce-denial',
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });
      const sessionId = JSON.parse(hs.content[0].text).sessionId;

      const vc = await issueDelegationVC({ scopes: ['wrong:scope'] });
      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      const result = await handler({ _kyaos_delegation: vc }, sessionId);

      expect(result.isError).toBe(true);
      const meta = (result as { _meta?: Record<string, { meta?: Record<string, unknown> } | undefined> })._meta;
      expect(meta?.[KYA_OS_PROOF_META_KEY]?.meta?.['outcome']).toBe('denied');
      expect(meta?.[KYA_OS_PROOF_META_KEY]?.meta?.['responseHash']).toBeUndefined();
    });

    it('emits a signed proof (outcome=needs_authorization) on the no-delegation challenge', async () => {
      const { middleware: kyaos, did } = await createTestMiddleware();
      const hs = await kyaos.handleHandshake({
        nonce: 'test-nonce-needsauth',
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });
      const sessionId = JSON.parse(hs.content[0].text).sessionId;

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      const result = await handler({ name: 'world' }, sessionId);

      // The challenge content is unchanged (still the needs_authorization JSON)...
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBe('needs_authorization');
      expect(parsed.authorizationUrl).toBe('https://example.com/consent');

      // ...and now carries a signed proof that BINDS the challenge content via
      // responseHash (covering the authorizationUrl) — option B, anti-MITM.
      const meta = (result as { _meta?: Record<string, { meta?: Record<string, unknown> } | undefined> })._meta;
      expect(meta?.[KYA_OS_PROOF_META_KEY]?.meta?.['outcome']).toBe('needs_authorization');
      expect(meta?.[KYA_OS_PROOF_META_KEY]?.meta?.['responseHash']).toBeDefined();
    });

    it('renders the challenge via formatChallenge and binds the proof over THAT content', async () => {
      const { middleware: kyaos, did } = await createTestMiddleware();
      const hs = await kyaos.handleHandshake({
        nonce: 'test-nonce-fmtchallenge',
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });
      const sessionId = JSON.parse(hs.content[0].text).sessionId;

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        {
          scopeId: 'test:scope',
          consentUrl: 'https://example.com/consent',
          // Render a markdown consent link (as the consent-* examples do for
          // LLM clients) instead of the default JSON challenge.
          formatChallenge: (challenge) => [
            {
              type: 'text',
              text: `Authorize at https://example.com/c?token=${challenge.resumeToken}`,
            },
          ],
        },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      const result = await handler({ name: 'world' }, sessionId);

      // The emitted content is the custom rendering, not the JSON challenge.
      expect(result.content[0].text).toContain('Authorize at https://example.com/c?token=');
      expect(() => JSON.parse(result.content[0].text)).toThrow();

      // The proof binds a responseHash over the rendered content (so a verifier
      // hashing what the client received matches) with outcome=needs_authorization.
      const meta = (result as { _meta?: Record<string, { meta?: Record<string, unknown> } | undefined> })._meta;
      expect(meta?.[KYA_OS_PROOF_META_KEY]?.meta?.['outcome']).toBe('needs_authorization');
      expect(meta?.[KYA_OS_PROOF_META_KEY]?.meta?.['responseHash']).toBeDefined();
    });

    it('falls back to the default JSON challenge when formatChallenge throws (no -32603)', async () => {
      const { middleware: kyaos, did } = await createTestMiddleware();
      const hs = await kyaos.handleHandshake({
        nonce: 'test-nonce-fmtthrows',
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });
      const sessionId = JSON.parse(hs.content[0].text).sessionId;

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        {
          scopeId: 'test:scope',
          consentUrl: 'https://example.com/consent',
          // A buggy renderer must never escalate to a JSON-RPC -32603 crash: the
          // challenge degrades to the default JSON shape, still proof-bound.
          formatChallenge: () => {
            throw new Error('boom in formatChallenge');
          },
        },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      const result = await handler({ name: 'world' }, sessionId);

      // Degrades to the default needs_authorization JSON, not an internal error.
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBe('needs_authorization');
      expect(parsed.authorizationUrl).toBe('https://example.com/consent');

      // Still carries a signed proof binding the (default) challenge content.
      const meta = (result as { _meta?: Record<string, { meta?: Record<string, unknown> } | undefined> })._meta;
      expect(meta?.[KYA_OS_PROOF_META_KEY]?.meta?.['outcome']).toBe('needs_authorization');
      expect(meta?.[KYA_OS_PROOF_META_KEY]?.meta?.['responseHash']).toBeDefined();
    });

    it('returns delegation_invalid (not a crash) for structurally malformed delegations', async () => {
      const { middleware: kyaos } = await createTestMiddleware();
      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      // Each previously threw "Cannot read properties of undefined (reading 'delegation')"
      // (object branch) or was already handled (string branch). None may crash.
      const malformed: unknown[] = [
        { bogus: true },
        { credentialSubject: {} },
        { credentialSubject: { delegation: null } },
        42,
        ['x'],
        'not-a-jwt',
      ];
      for (const bad of malformed) {
        const result = await handler({ _kyaos_delegation: bad });
        expect(result.isError).toBe(true);
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.error).toBe('delegation_invalid');
      }
    });

    it('attaches a signed denial proof (outcome=denied) for a malformed delegation', async () => {
      const { middleware: kyaos, did } = await createTestMiddleware();
      const hs = await kyaos.handleHandshake({
        nonce: 'test-nonce-malformed',
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });
      const sessionId = JSON.parse(hs.content[0].text).sessionId;

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      const result = await handler({ _kyaos_delegation: { bogus: true } }, sessionId);
      expect(result.isError).toBe(true);
      const meta = (result as { _meta?: Record<string, { meta?: Record<string, unknown> } | undefined> })._meta;
      expect(meta?.[KYA_OS_PROOF_META_KEY]?.meta?.['outcome']).toBe('denied');
    });

    it('returns delegation_invalid (not a crash) when a delegation accessor throws', async () => {
      const { middleware: kyaos } = await createTestMiddleware();
      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      // A getter that throws on property access must not escape as MCP -32603.
      const throwingDelegation = {};
      Object.defineProperty(throwingDelegation, 'credentialSubject', {
        get() {
          throw new Error('boom');
        },
        enumerable: true,
      });

      const result = await handler({ _kyaos_delegation: throwingDelegation });
      expect(result.isError).toBe(true);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBe('delegation_invalid');
    });

    it('sanitizes control characters from caller-derived values in the client reason', async () => {
      const { middleware: kyaos } = await createTestMiddleware();
      const vc = await issueDelegationVC({ scopes: ['test:scope'] });
      // A hostile credential embeds control chars (NUL, ESC, newline) in its id.
      // Tampering the id invalidates the signature; the resulting reason must not
      // reflect raw control chars into the client response (log-injection /
      // terminal-corruption risk). Built via fromCharCode to keep source ASCII.
      const ctrl = String.fromCharCode(0, 27, 10);
      (vc as unknown as { credentialSubject: { delegation: { id: string } } })
        .credentialSubject.delegation.id = `evil${ctrl}id`;

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );
      const result = await handler({ _kyaos_delegation: vc });

      expect(result.isError).toBe(true);
      const reason = JSON.parse(result.content[0].text).reason as string;
      const hasControlChar = [...reason].some((c) => {
        const o = c.charCodeAt(0);
        return o < 0x20 || (o >= 0x7f && o <= 0x9f);
      });
      expect(hasControlChar).toBe(false);
      expect(reason).toContain(String.fromCharCode(0xfffd));
    });

    it('returns delegation_invalid (not a crash) for a constraints-less leaf', async () => {
      const { middleware: kyaos } = await createTestMiddleware();
      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );
      // A hand-crafted leaf with NO constraints. The leaf shape guard rejects it
      // with delegation_invalid; without the guard, the constraints-less VC would
      // reach scopeSatisfies (which runs OUTSIDE the wrapper's backstop) and throw
      // a raw TypeError surfaced as MCP -32603. scopeSatisfies is also null-safe.
      const malformedLeaf = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        credentialSubject: {
          id: 'did:key:zSubject',
          delegation: {
            id: 'leaf-no-constraints',
            issuerDid: 'did:key:zIssuer',
            subjectDid: 'did:key:zSubject',
            parentId: 'parent-1',
            status: 'active',
          },
        },
        proof: { type: 'Ed25519Signature2020', proofValue: 'x' },
      } as unknown as DelegationCredential;

      const result = await handler({ _kyaos_delegation: malformedLeaf });
      expect(result.isError).toBe(true);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBe('delegation_invalid');
    });

    it('should accept when scope is granted via a crisp.scopes prefix matcher', async () => {
      const { middleware: kyaos } = await createTestMiddleware();
      const vc = await issueDelegationVC({
        scopes: [],
        crispScopes: [{ resource: 'test:', matcher: 'prefix' }],
      });

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async (args) => ({
          content: [{ type: 'text', text: `Called: ${JSON.stringify(args)}` }],
        }),
      );

      const result = await handler({ _kyaos_delegation: vc, name: 'DIF' });

      expect(result.isError).toBeUndefined();
    });

    it('should accept and call handler when VC has correct scope and valid signature', async () => {
      const { middleware: kyaos } = await createTestMiddleware();
      const vc = await issueDelegationVC({ scopes: ['test:scope', 'other:scope'] });

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async (args) => ({
          content: [{ type: 'text', text: `Called: ${JSON.stringify(args)}` }],
        }),
      );

      const result = await handler({ _kyaos_delegation: vc, name: 'DIF' });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text.replace('Called: ', ''));
      // _kyaos_delegation should be stripped from args
      expect(parsed['_kyaos_delegation']).toBeUndefined();
      expect(parsed['name']).toBe('DIF');
    });

    it('should reject credentials with credentialStatus when no status list resolver is configured', async () => {
      const { middleware: kyaos } = await createTestMiddleware();
      const vc = await issueDelegationVC({
        scopes: ['test:scope'],
        credentialStatus: {
          id: 'https://status.example.com/revocation/v1#0',
          type: 'StatusList2021Entry',
          statusPurpose: 'revocation',
          statusListIndex: '0',
          statusListCredential: 'https://status.example.com/revocation/v1',
        },
      });

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      const result = await handler({ _kyaos_delegation: vc });

      expect(result.isError).toBe(true);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBe('delegation_invalid');
      expect(parsed.reason).toContain('statusListResolver');
    });

    it('should reject delegations whose audience does not include the server DID', async () => {
      const { middleware: kyaos } = await createTestMiddleware();
      const vc = await issueDelegationVC({
        scopes: ['test:scope'],
        audience: 'did:web:other.example.com',
      });

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      const result = await handler({ _kyaos_delegation: vc });

      expect(result.isError).toBe(true);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBe('delegation_invalid');
      expect(parsed.reason).toContain('audience does not include server DID');
    });

    it('should reject parent delegations when no chain resolver is configured', async () => {
      const { middleware: kyaos } = await createTestMiddleware();
      const vc = await issueDelegationVC({
        scopes: ['test:scope'],
        parentId: 'parent-delegation',
      });

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      const result = await handler({ _kyaos_delegation: vc });

      expect(result.isError).toBe(true);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBe('delegation_invalid');
      expect(parsed.reason).toContain('resolveDelegationChain');
    });

    it('should reject delegation chains that widen parent scopes', async () => {
      const parentIssuer = await createDelegationIssuer();
      const childIssuer = await createDelegationIssuer();
      const leafSubject = (await createDelegationIssuer()).did;
      const parentVc = await issueDelegationVC({
        issuer: parentIssuer,
        scopes: ['test:scope'],
        subjectDid: childIssuer.did,
      });

      const { middleware: kyaos, did } = await createTestMiddleware({
        delegation: {
          resolveDelegationChain: async () => [parentVc],
        },
      });

      const childVc = await issueDelegationVC({
        issuer: childIssuer,
        scopes: ['test:scope', 'admin:scope'],
        parentId: parentVc.credentialSubject.delegation.id,
        subjectDid: leafSubject,
        audience: did,
      });

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      const result = await handler({ _kyaos_delegation: childVc });

      expect(result.isError).toBe(true);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBe('delegation_invalid');
      expect(parsed.reason).toContain('widens scopes');
    });

    it('should reject re-delegations that introduce crisp scope matchers absent from the parent', async () => {
      const parentIssuer = await createDelegationIssuer();
      const childIssuer = await createDelegationIssuer();
      const leafSubject = (await createDelegationIssuer()).did;

      // Audience binding on re-delegations is mandatory, so the middleware must
      // exist first to supply its DID as the re-delegation's audience.
      let parentVcRef!: DelegationCredential;
      const { middleware: kyaos, did: serverDid } = await createTestMiddleware({
        delegation: { resolveDelegationChain: async () => [parentVcRef] },
      });

      const parentVc = await issueDelegationVC({
        issuer: parentIssuer,
        scopes: ['test:scope'],
        subjectDid: childIssuer.did,
      });
      parentVcRef = parentVc;

      // Flat scopes do NOT widen, but the child sneaks in a crisp prefix matcher
      // with an empty resource that would match every scope — privilege escalation.
      const childVc = await issueDelegationVC({
        issuer: childIssuer,
        scopes: ['test:scope'],
        crispScopes: [{ resource: 'admin:', matcher: 'prefix' }],
        parentId: parentVc.credentialSubject.delegation.id,
        subjectDid: leafSubject,
        audience: serverDid,
      });

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      const result = await handler({ _kyaos_delegation: childVc });

      expect(result.isError).toBe(true);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBe('delegation_invalid');
      expect(parsed.reason).toContain('crisp scope matcher');
    });

    it('should accept did:web issuers when a fetch-backed resolver is available', async () => {
      const did = 'did:web:issuer.example.com';
      const kid = `${did}#key-1`;
      const issuer = await createDelegationIssuer({ did, kid });
      const vc = await issueDelegationVC({
        issuer,
        scopes: ['test:scope'],
      });
      const fetchProvider = new MockFetchProvider();
      fetchProvider.fetch = async () =>
        new Response(
          JSON.stringify({
            id: did,
            verificationMethod: [
              {
                id: kid,
                type: 'Ed25519VerificationKey2020',
                controller: did,
                publicKeyJwk: {
                  kty: 'OKP',
                  crv: 'Ed25519',
                  x: base64urlEncodeFromBytes(base64ToBytes(issuer.keyPair.publicKey)),
                },
              },
            ],
            authentication: [kid],
            assertionMethod: [kid],
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );

      const { middleware: kyaos } = await createTestMiddleware({
        delegation: { fetchProvider },
      });

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async (args) => ({
          content: [{ type: 'text', text: `Called: ${JSON.stringify(args)}` }],
        }),
      );

      const result = await handler({ _kyaos_delegation: vc, name: 'DIF' });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text.replace('Called: ', ''));
      expect(parsed['name']).toBe('DIF');
    });

    it('should accept did:cheqd issuers when a cheqd resolver is configured', async () => {
      const did = 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111';
      const kid = `${did}#key-1`;
      const issuer = await createDelegationIssuer({ did, kid });
      const vc = await issueDelegationVC({
        issuer,
        scopes: ['test:scope'],
      });
      const fetchProvider = new MockFetchProvider();
      fetchProvider.fetch = async () =>
        new Response(
          JSON.stringify({
            didDocument: {
              id: did,
              verificationMethod: [
                {
                  id: kid,
                  type: 'Ed25519VerificationKey2020',
                  controller: did,
                  publicKeyJwk: {
                    kty: 'OKP',
                    crv: 'Ed25519',
                    x: base64urlEncodeFromBytes(base64ToBytes(issuer.keyPair.publicKey)),
                  },
                },
              ],
              authentication: [kid],
              assertionMethod: [kid],
            },
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );

      const { middleware: kyaos } = await createTestMiddleware({
        delegation: {
          fetchProvider,
          didResolvers: {
            cheqd: cheqdResolver({ resolverUrl: 'https://resolver.cheqd.net' }),
          },
        },
      });

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async (args) => ({
          content: [{ type: 'text', text: `Called: ${JSON.stringify(args)}` }],
        }),
      );

      const result = await handler({ _kyaos_delegation: vc, name: 'DIF' });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text.replace('Called: ', ''));
      expect(parsed['name']).toBe('DIF');
    });

    it('should reject did:cheqd issuers when no cheqd resolver is configured', async () => {
      const did = 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111';
      const kid = `${did}#key-1`;
      const issuer = await createDelegationIssuer({ did, kid });
      const vc = await issueDelegationVC({
        issuer,
        scopes: ['test:scope'],
      });
      const { middleware: kyaos } = await createTestMiddleware();

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      const result = await handler({ _kyaos_delegation: vc });

      expect(result.isError).toBe(true);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBe('delegation_invalid');
      expect(parsed.reason).toContain(`Could not resolve issuer DID: ${did}`);
    });

    it('should reject credentialStatus when no status resolver is configured', async () => {
      const { middleware: kyaos } = await createTestMiddleware();
      const vc = await issueDelegationVC({
        scopes: ['test:scope'],
        credentialStatus: {
          id: 'https://status.example.com/revocation/v1#0',
          type: 'StatusList2021Entry',
          statusPurpose: 'revocation',
          statusListIndex: '0',
          statusListCredential: 'https://status.example.com/revocation/v1',
        },
      });

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      const result = await handler({ _kyaos_delegation: vc });
      expect(result.isError).toBe(true);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBe('delegation_invalid');
      expect(parsed.reason).toContain('statusListResolver');
    });
  });

  describe('autoSession', () => {
    it('should auto-create session and attach proof without handshake', async () => {
      const { middleware: kyaos } = await createTestMiddleware({ autoSession: true });

      const handler = kyaos.wrapWithProof('greet', async (args) => ({
        content: [{ type: 'text', text: `Hello, ${args['name']}!` }],
      }));

      // No handshake — call tool directly
      const result = await handler({ name: 'DIF' });

      expect(result.content).toHaveLength(1);
      expect(result.content[0].text).toBe('Hello, DIF!');

      // Proof should still be generated via auto-session
      expect(result._meta).toBeDefined();
      const proof = result._meta![KYA_OS_PROOF_META_KEY] as { jws: string; meta: Record<string, unknown> };
      expect(proof.jws).toBeDefined();
      expect(proof.meta.did).toMatch(/^did:key:/);
      expect(proof.meta.sessionId).toMatch(/^kyaos_/);
      // Nonce is now a base64url-encoded 16-byte random value
      expect(proof.meta.nonce).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should reuse auto-created session across multiple calls', async () => {
      const { middleware: kyaos } = await createTestMiddleware({ autoSession: true });

      const handler = kyaos.wrapWithProof('greet', async () => ({
        content: [{ type: 'text', text: 'Hello!' }],
      }));

      const result1 = await handler({});
      const result2 = await handler({});

      const proof1 = result1._meta![KYA_OS_PROOF_META_KEY] as { meta: Record<string, unknown> };
      const proof2 = result2._meta![KYA_OS_PROOF_META_KEY] as { meta: Record<string, unknown> };

      expect(proof1.meta.sessionId).toBe(proof2.meta.sessionId);
    });
  });

  describe('emitLegacyProofKey', () => {
    async function proofedMeta(emitLegacyProofKey?: boolean): Promise<Record<string, unknown>> {
      const { middleware, did } = await createTestMiddleware(
        emitLegacyProofKey === undefined ? {} : { emitLegacyProofKey },
      );
      const hs = await middleware.handleHandshake({
        nonce: `legacy-${Math.random().toString(16).slice(2)}`,
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });
      const sessionId = JSON.parse(hs.content[0].text).sessionId;
      const handler = middleware.wrapWithProof('greet', async () => ({
        content: [{ type: 'text', text: 'Hello!' }],
      }));
      const result = await handler({ name: 'DIF' }, sessionId);
      return result._meta as Record<string, unknown>;
    }

    it('by default emits the proof under BOTH keys with an identical value', async () => {
      const meta = await proofedMeta();
      expect(meta[KYA_OS_PROOF_META_KEY]).toBeDefined();
      expect(meta[LEGACY_PROOF_META_KEY]).toBeDefined();
      expect(meta[LEGACY_PROOF_META_KEY]).toEqual(meta[KYA_OS_PROOF_META_KEY]);
    });

    it('emits ONLY the namespaced key when emitLegacyProofKey is false', async () => {
      const meta = await proofedMeta(false);
      expect(meta[KYA_OS_PROOF_META_KEY]).toBeDefined();
      expect(meta[LEGACY_PROOF_META_KEY]).toBeUndefined();
    });

    it('the legacy mirror does not change the response hash (_meta is excluded from the hash)', async () => {
      const both = await proofedMeta(true);
      const single = await proofedMeta(false);
      const responseHashOf = (m: Record<string, unknown>): string | undefined =>
        (m[KYA_OS_PROOF_META_KEY] as { meta: { responseHash?: string } }).meta.responseHash;
      // Same tool + same args ⇒ identical responseHash regardless of the _meta mirror.
      expect(responseHashOf(both)).toBeDefined();
      expect(responseHashOf(both)).toBe(responseHashOf(single));
    });
  });

  describe('proof attribution safety (F5)', () => {
    it('attributes the proof to the single session when exactly one exists', async () => {
      const { middleware: kyaos, did } = await createTestMiddleware();
      await kyaos.handleHandshake({
        nonce: `f5-single-${Math.random().toString(16).slice(2)}`,
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });
      const handler = kyaos.wrapWithProof('greet', async () => ({
        content: [{ type: 'text', text: 'Hello!' }],
      }));
      // No threaded sessionId, but exactly one session ⇒ unambiguous ⇒ proof attached.
      const result = await handler({});
      expect(result._meta![KYA_OS_PROOF_META_KEY]).toBeDefined();
    });

    it('does NOT borrow activeSessionId when multiple sessions exist and none is threaded', async () => {
      const { middleware: kyaos, did } = await createTestMiddleware();
      await kyaos.handleHandshake({
        nonce: `f5-a-${Math.random().toString(16).slice(2)}`,
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });
      await kyaos.handleHandshake({
        nonce: `f5-b-${Math.random().toString(16).slice(2)}`,
        audience: did,
        timestamp: Math.floor(Date.now() / 1000),
      });
      const handler = kyaos.wrapWithProof('greet', async () => ({
        content: [{ type: 'text', text: 'Hello!' }],
      }));
      // Two sessions + no threaded id ⇒ ambiguous ⇒ proof skipped (not mis-attributed).
      const result = await handler({});
      expect(result.content[0].text).toBe('Hello!');
      expect(result._meta?.[KYA_OS_PROOF_META_KEY]).toBeUndefined();
    });
  });
});

describe('withPolicyGate', () => {
  const text = (r: { content: Array<{ text: string }> }) => r.content[0].text;

  it('allows a reversible, low-severity action', async () => {
    const { middleware: kyaos } = await createTestMiddleware();
    const handler = kyaos.withPolicyGate!('repo.read', async (args) => ({
      content: [{ type: 'text', text: `ran:${JSON.stringify(args)}` }],
    }), { scopeMatched: true });
    const result = await handler({ id: 1 });
    expect(result.isError).toBeUndefined();
    expect(text(result)).toContain('ran:');
  });

  it('denies an unclassified (unknown) action — fail-closed', async () => {
    const { middleware: kyaos } = await createTestMiddleware();
    const handler = kyaos.withPolicyGate!('frobnicate', async () => ({
      content: [{ type: 'text', text: 'ran' }],
    }), { scopeMatched: true });
    const result = await handler({});
    expect(result.isError).toBe(true);
    expect(JSON.parse(text(result)).error).toBe('policy_denied');
  });

  it('requires step-up (needs_approval) for a destructive prod action', async () => {
    const { middleware: kyaos } = await createTestMiddleware();
    const handler = kyaos.withPolicyGate(
      'db.drop',
      async () => ({ content: [{ type: 'text', text: 'ran' }] }),
      { resolveNamespace: () => 'prod', scopeMatched: true },
    );
    const result = await handler({ table: 'users' });
    expect(result.isError).toBe(true);
    const body = JSON.parse(text(result));
    expect(body.error).toBe('needs_approval');
    expect(typeof body.requestHash).toBe('string');
    expect(body.quorum.n).toBe(1);
  });

  it('proceeds once a valid approval grant bound to the requestHash is supplied', async () => {
    const { middleware: kyaos } = await createTestMiddleware();
    const handler = kyaos.withPolicyGate(
      'db.drop',
      async (args) => ({ content: [{ type: 'text', text: `ran:${JSON.stringify(args)}` }] }),
      { resolveNamespace: () => 'prod', isValidApprovalSignature: async () => true, scopeMatched: true },
    );

    const first = await handler({ table: 'users' });
    const { requestHash } = JSON.parse(text(first));

    const grant = {
      approvalRequestId: 'r1',
      approverDid: 'did:example:approver',
      requestHash,
      decision: 'approve',
      ts: 1,
      signature: 'sig',
    };
    const second = await handler({ table: 'users', _kyaos_approvals: [grant] });
    expect(second.isError).toBeUndefined();
    expect(text(second)).toContain('ran:');
  });

  it('rejects an approval grant bound to a different requestHash (TOCTOU)', async () => {
    const { middleware: kyaos } = await createTestMiddleware();
    const handler = kyaos.withPolicyGate(
      'db.drop',
      async () => ({ content: [{ type: 'text', text: 'ran' }] }),
      { resolveNamespace: () => 'prod', isValidApprovalSignature: async () => true, scopeMatched: true },
    );
    const grant = {
      approvalRequestId: 'r1',
      approverDid: 'did:example:approver',
      requestHash: 'sha256:WRONG',
      decision: 'approve',
      ts: 1,
      signature: 'sig',
    };
    const result = await handler({ table: 'users', _kyaos_approvals: [grant] });
    expect(result.isError).toBe(true);
    expect(JSON.parse(text(result)).error).toBe('needs_approval');
  });
});
