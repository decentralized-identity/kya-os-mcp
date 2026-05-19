import { describe, it, expect, vi } from 'vitest';
import {
  createKyaOsMiddleware,
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

async function createTestMiddleware(options?: {
  autoSession?: boolean;
  delegation?: KyaOsDelegationConfig;
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
      autoSession: options?.autoSession,
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
      expect(result._meta!.proof).toBeDefined();
      const proof = result._meta!.proof as { jws: string; meta: Record<string, unknown> };
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
      expect(result._meta!.proof).toBeUndefined();
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

    it('should allow parent delegations in legacy mode without a chain resolver', async () => {
      const { middleware: kyaos } = await createTestMiddleware({
        delegation: { allowLegacyUnsafeDelegation: true },
      });
      const vc = await issueDelegationVC({
        scopes: ['test:scope'],
        parentId: 'parent-delegation',
      });

      const handler = kyaos.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'legacy-ok' }] }),
      );

      const result = await handler({ _kyaos_delegation: vc });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toBe('legacy-ok');
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
      const childVc = await issueDelegationVC({
        issuer: childIssuer,
        scopes: ['test:scope', 'admin:scope'],
        parentId: parentVc.credentialSubject.delegation.id,
        subjectDid: leafSubject,
      });

      const { middleware: kyaos } = await createTestMiddleware({
        delegation: {
          resolveDelegationChain: async () => [parentVc],
        },
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

    it('should allow credentialStatus without status resolver in legacy mode', async () => {
      const { middleware: kyaos } = await createTestMiddleware({
        delegation: { allowLegacyUnsafeDelegation: true },
      });
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
        async () => ({ content: [{ type: 'text', text: 'legacy-status-ok' }] }),
      );

      const result = await handler({ _kyaos_delegation: vc });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toBe('legacy-status-ok');
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
      const proof = result._meta!.proof as { jws: string; meta: Record<string, unknown> };
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

      const proof1 = result1._meta!.proof as { meta: Record<string, unknown> };
      const proof2 = result2._meta!.proof as { meta: Record<string, unknown> };

      expect(proof1.meta.sessionId).toBe(proof2.meta.sessionId);
    });
  });
});
