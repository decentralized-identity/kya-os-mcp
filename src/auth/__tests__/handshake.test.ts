import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  verifyOrHints,
  MemoryResumeTokenStore,
  type AuthHandshakeConfig,
  type ResumeTokenStore,
} from '../handshake.js';

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function createConfig(overrides?: {
  minReputationScore?: number;
  unknownAgentPolicy?: 'deny' | 'require-consent' | 'allow';
  reputationApiUrl?: string;
}): AuthHandshakeConfig {
  return {
    delegationVerifier: {
      verify: vi.fn().mockResolvedValue({ valid: false, reason: 'No delegation' }),
    },
    resumeTokenStore: new MemoryResumeTokenStore(),
    reputationService: {
      apiUrl: overrides?.reputationApiUrl ?? 'https://reputation.example.com',
    },
    authorization: {
      authorizationUrl: 'https://example.com/consent',
      minReputationScore: overrides?.minReputationScore ?? 30,
      unknownAgentPolicy: overrides?.unknownAgentPolicy,
    },
  };
}

function mockReputationResponse(score: number, status = 200) {
  mockFetch.mockResolvedValueOnce({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: async () => ({ score }),
  });
}

function mockReputationNotFound() {
  mockFetch.mockResolvedValueOnce({
    ok: false,
    status: 404,
    statusText: 'Not Found',
  });
}

function mockReputationNetworkError() {
  mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));
}

describe('verifyOrHints — unknownAgentPolicy', () => {
  const agentDid = 'did:key:z6MkTest';
  const scopes = ['read:data'];

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('known agents (reputation service returns a score)', () => {
    it('should reject known agent with score below threshold', async () => {
      const config = createConfig({ minReputationScore: 30 });
      mockReputationResponse(10);

      const result = await verifyOrHints(agentDid, scopes, config);

      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('Low reputation score');
      expect(result.reputation?.score).toBe(10);
    });

    it('should allow known agent with score above threshold to proceed to delegation', async () => {
      const config = createConfig({ minReputationScore: 30 });
      mockReputationResponse(80);

      const result = await verifyOrHints(agentDid, scopes, config);

      // Not authorized (no delegation), but passed reputation gate
      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('No delegation');
      expect(result.reputation?.score).toBe(80);
    });
  });

  describe('unknown agents (404 from reputation service)', () => {
    it('should deny unknown agent when policy is "deny"', async () => {
      const config = createConfig({ unknownAgentPolicy: 'deny' });
      mockReputationNotFound();

      const result = await verifyOrHints(agentDid, scopes, config);

      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('Unknown agent — policy: deny');
      expect(result.reputation?.score).toBeNull();
    });

    it('should require consent for unknown agent when policy is "require-consent"', async () => {
      const config = createConfig({ unknownAgentPolicy: 'require-consent' });
      mockReputationNotFound();

      const result = await verifyOrHints(agentDid, scopes, config);

      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('Unknown agent — policy: require-consent');
      expect(result.authError).toBeDefined();
      expect(result.reputation?.score).toBeNull();
    });

    it('should default to "require-consent" when no policy is set', async () => {
      const config = createConfig(); // no unknownAgentPolicy
      mockReputationNotFound();

      const result = await verifyOrHints(agentDid, scopes, config);

      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('Unknown agent — policy: require-consent');
    });

    it('should allow unknown agent when policy is "allow"', async () => {
      const config = createConfig({ unknownAgentPolicy: 'allow' });
      mockReputationNotFound();

      const result = await verifyOrHints(agentDid, scopes, config);

      // Not authorized (no delegation), but passed reputation gate
      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('No delegation');
      expect(result.reputation?.score).toBeNull();
    });
  });

  describe('reputation service unreachable (network error)', () => {
    it('should treat network errors as unknown agent', async () => {
      const config = createConfig({ unknownAgentPolicy: 'deny' });
      mockReputationNetworkError();

      const result = await verifyOrHints(agentDid, scopes, config);

      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('Unknown agent — policy: deny');
      expect(result.reputation?.score).toBeNull();
      expect(result.reputation?.riskLevel).toBe('unknown');
    });

    it('should route to consent on network error with default policy', async () => {
      const config = createConfig(); // default = require-consent
      mockReputationNetworkError();

      const result = await verifyOrHints(agentDid, scopes, config);

      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('Unknown agent — policy: require-consent');
      expect(result.authError).toBeDefined();
    });

    it('should allow through on network error when policy is "allow"', async () => {
      const config = createConfig({ unknownAgentPolicy: 'allow' });
      mockReputationNetworkError();

      const result = await verifyOrHints(agentDid, scopes, config);

      // Passes reputation gate, fails on delegation
      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('No delegation');
    });
  });

  describe('no reputation service configured', () => {
    it('should skip reputation check entirely when no service configured', async () => {
      const config: AuthHandshakeConfig = {
        delegationVerifier: {
          verify: vi.fn().mockResolvedValue({ valid: false, reason: 'No delegation' }),
        },
        resumeTokenStore: new MemoryResumeTokenStore(),
        // No reputationService
        authorization: {
          authorizationUrl: 'https://example.com/consent',
          minReputationScore: 30,
        },
      };

      const result = await verifyOrHints(agentDid, scopes, config);

      expect(result.reputation).toBeUndefined();
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });
});

describe('verifyOrHints — needs_authorization challenge', () => {
  const agentDid = 'did:key:z6MkTest';
  const scopes = ['read:data'];

  async function challenge() {
    const config: AuthHandshakeConfig = {
      delegationVerifier: {
        verify: vi.fn().mockResolvedValue({ valid: false, reason: 'No delegation' }),
      },
      resumeTokenStore: new MemoryResumeTokenStore(),
      authorization: { authorizationUrl: 'https://example.com/consent' },
    };
    const result = await verifyOrHints(agentDid, scopes, config);
    if (!result.authError) throw new Error('expected a needs_authorization challenge');
    return result.authError;
  }

  it('states expiresAt in Unix seconds, per the needs-authorization schema', async () => {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const { expiresAt } = await challenge();

    expect(Number.isInteger(expiresAt)).toBe(true);
    expect(expiresAt).toBeGreaterThan(nowSeconds);
    expect(expiresAt).toBeLessThanOrEqual(nowSeconds + 600);
  });

  it('keeps the resume token out of third-party QR services', async () => {
    const authError = await challenge();

    // qrUrl is the URL to encode as a QR code; the client renders it locally.
    expect(authError.display?.qrUrl).toBe(authError.authorizationUrl);
    expect(new URL(authError.display!.qrUrl!).origin).toBe('https://example.com');
  });

  it('does not derive a display code from the resume token', async () => {
    const authError = await challenge();
    const prefix = authError.resumeToken.substring(0, 8).toUpperCase();

    expect(authError.display?.authorizationCode).toBeUndefined();
    expect(JSON.stringify(authError.display)).not.toContain(prefix);
  });

  it('advertises the expiry the token store enforces, not the configured fallback', async () => {
    const store = new MemoryResumeTokenStore(60_000);
    const config: AuthHandshakeConfig = {
      delegationVerifier: {
        verify: vi.fn().mockResolvedValue({ valid: false, reason: 'No delegation' }),
      },
      resumeTokenStore: store,
      authorization: { authorizationUrl: 'https://example.com/consent', resumeTokenTtl: 3_600_000 },
    };

    const { authError } = await verifyOrHints(agentDid, scopes, config);
    const stored = await store.get(authError!.resumeToken);

    expect(authError!.expiresAt).toBe(Math.floor(stored!.expiresAt / 1000));
    expect(authError!.expiresAt).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 60);
  });

  it('falls back to resumeTokenTtl when the store cannot report a usable expiry', async () => {
    const reports: Array<() => Promise<Awaited<ReturnType<ResumeTokenStore['get']>>>> = [
      async () => { throw new Error('store unavailable'); },
      async () => null,
      // Seconds instead of milliseconds: already in the past as an instant.
      async () => ({ agentDid, scopes, createdAt: 0, expiresAt: Math.floor(Date.now() / 1000) + 60 }),
    ];
    for (const report of reports) {
      const store: ResumeTokenStore = {
        create: async () => 'rt_custom',
        get: report,
        fulfill: async () => undefined,
      };
      const before = Math.floor(Date.now() / 1000);
      const { authError } = await verifyOrHints(agentDid, scopes, {
        delegationVerifier: {
          verify: vi.fn().mockResolvedValue({ valid: false, reason: 'No delegation' }),
        },
        resumeTokenStore: store,
        authorization: { authorizationUrl: 'https://example.com/consent', resumeTokenTtl: 120_000 },
      });
      const after = Math.floor(Date.now() / 1000);

      expect(authError!.expiresAt).toBeGreaterThanOrEqual(before + 120);
      expect(authError!.expiresAt).toBeLessThanOrEqual(after + 120);
    }
  });
});

describe('MemoryResumeTokenStore', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  const size = (store: MemoryResumeTokenStore) =>
    (store as unknown as { tokens: Map<string, unknown> }).tokens.size;

  it('drops expired tokens as new ones are created, without a read, and keeps live ones', async () => {
    vi.useFakeTimers();
    const store = new MemoryResumeTokenStore(1_000);
    for (let i = 0; i < 100; i++) {
      await store.create('did:key:zAnyone', ['tool:x']);
      vi.advanceTimersByTime(10_000);
    }
    expect(size(store)).toBe(1);

    const live = new MemoryResumeTokenStore(60_000);
    const first = await live.create('did:key:zA', ['tool:x']);
    vi.advanceTimersByTime(30_000);
    await live.create('did:key:zB', ['tool:x']);
    expect(await live.get(first)).not.toBeNull();
  });

  it('drops a token once fulfilled', async () => {
    const store = new MemoryResumeTokenStore();
    const token = await store.create('did:key:zA', ['tool:x']);
    await store.fulfill(token);
    expect(await store.get(token)).toBeNull();
    expect(size(store)).toBe(0);
  });
});
