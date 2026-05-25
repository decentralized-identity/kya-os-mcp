/**
 * Tests for the warn-once behavior on the two unsafe delegation knobs.
 *
 * These warnings are observability — they don't change protocol behavior,
 * they just make unsafe configuration visible in production logs. The
 * dedupe logic uses module-level flags, so we reload the middleware module
 * between tests to get a fresh warned-state.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { generateDidKeyFromBase64 } from '../../utils/did-helpers.js';
import type { KyaOsDelegationConfig } from '../with-kya-os.js';

async function freshMiddleware(delegation?: KyaOsDelegationConfig) {
  vi.resetModules();
  const mod = await import('../with-kya-os.js');
  const crypto = new NodeCryptoProvider();
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  const kid = `${did}#${did.replace('did:key:', '')}`;
  return mod.createKyaOsMiddleware(
    {
      identity: { did, kid, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey },
      session: { sessionTtlMinutes: 60 },
      delegation,
    },
    crypto,
  );
}

async function wrapNoop(middleware: Awaited<ReturnType<typeof freshMiddleware>>) {
  return middleware.wrapWithDelegation(
    'noop_tool',
    { scopeId: 'noop', consentUrl: 'https://example.com/consent' },
    async () => ({ content: [{ type: 'text', text: 'ok' }] }),
  );
}

describe('Unsafe delegation mode warnings', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  describe('allowLegacyUnsafeDelegation', () => {
    it('warns once on first wrapWithDelegation when set to true', async () => {
      const middleware = await freshMiddleware({ allowLegacyUnsafeDelegation: true });
      await wrapNoop(middleware);

      const legacyWarnings = warnSpy.mock.calls.filter(
        (call) => typeof call[0] === 'string' && call[0].includes('allowLegacyUnsafeDelegation'),
      );
      expect(legacyWarnings).toHaveLength(1);
      expect(legacyWarnings[0][0]).toContain('unsafe for production');
      expect(legacyWarnings[0][0]).toContain('SECURITY.md');
    });

    it('does not re-warn on subsequent wrapWithDelegation calls in the same process', async () => {
      const middleware = await freshMiddleware({ allowLegacyUnsafeDelegation: true });
      await wrapNoop(middleware);
      await wrapNoop(middleware);
      await wrapNoop(middleware);

      const legacyWarnings = warnSpy.mock.calls.filter(
        (call) => typeof call[0] === 'string' && call[0].includes('allowLegacyUnsafeDelegation'),
      );
      expect(legacyWarnings).toHaveLength(1);
    });

    it('does not warn when set to false', async () => {
      const middleware = await freshMiddleware({ allowLegacyUnsafeDelegation: false });
      await wrapNoop(middleware);

      const legacyWarnings = warnSpy.mock.calls.filter(
        (call) => typeof call[0] === 'string' && call[0].includes('allowLegacyUnsafeDelegation'),
      );
      expect(legacyWarnings).toHaveLength(0);
    });

    it('does not warn when omitted (default is false)', async () => {
      const middleware = await freshMiddleware();
      await wrapNoop(middleware);

      const legacyWarnings = warnSpy.mock.calls.filter(
        (call) => typeof call[0] === 'string' && call[0].includes('allowLegacyUnsafeDelegation'),
      );
      expect(legacyWarnings).toHaveLength(0);
    });
  });

  describe('requireAudienceOnRedelegation opt-out', () => {
    it('warns once on first wrapWithDelegation when explicitly set to false', async () => {
      const middleware = await freshMiddleware({ requireAudienceOnRedelegation: false });
      await wrapNoop(middleware);

      const audienceWarnings = warnSpy.mock.calls.filter(
        (call) =>
          typeof call[0] === 'string' && call[0].includes('requireAudienceOnRedelegation'),
      );
      expect(audienceWarnings).toHaveLength(1);
      expect(audienceWarnings[0][0]).toContain('confused-deputy');
      expect(audienceWarnings[0][0]).toContain('SECURITY.md');
    });

    it('does not re-warn on subsequent wrapWithDelegation calls in the same process', async () => {
      const middleware = await freshMiddleware({ requireAudienceOnRedelegation: false });
      await wrapNoop(middleware);
      await wrapNoop(middleware);
      await wrapNoop(middleware);

      const audienceWarnings = warnSpy.mock.calls.filter(
        (call) =>
          typeof call[0] === 'string' && call[0].includes('requireAudienceOnRedelegation'),
      );
      expect(audienceWarnings).toHaveLength(1);
    });

    it('does not warn when omitted (defaults to true — strict)', async () => {
      const middleware = await freshMiddleware();
      await wrapNoop(middleware);

      const audienceWarnings = warnSpy.mock.calls.filter(
        (call) =>
          typeof call[0] === 'string' && call[0].includes('requireAudienceOnRedelegation'),
      );
      expect(audienceWarnings).toHaveLength(0);
    });

    it('does not warn when explicitly set to true', async () => {
      const middleware = await freshMiddleware({ requireAudienceOnRedelegation: true });
      await wrapNoop(middleware);

      const audienceWarnings = warnSpy.mock.calls.filter(
        (call) =>
          typeof call[0] === 'string' && call[0].includes('requireAudienceOnRedelegation'),
      );
      expect(audienceWarnings).toHaveLength(0);
    });
  });

  describe('default safe configuration', () => {
    it('emits no delegation warnings when both knobs are at their safe defaults', async () => {
      const middleware = await freshMiddleware();
      await wrapNoop(middleware);

      const delegationWarnings = warnSpy.mock.calls.filter(
        (call) =>
          typeof call[0] === 'string' &&
          (call[0].includes('allowLegacyUnsafeDelegation') ||
            call[0].includes('requireAudienceOnRedelegation')),
      );
      expect(delegationWarnings).toHaveLength(0);
    });
  });

  describe('both unsafe modes together', () => {
    it('emits both warnings (one each) when both knobs are set unsafely', async () => {
      const middleware = await freshMiddleware({
        allowLegacyUnsafeDelegation: true,
        requireAudienceOnRedelegation: false,
      });
      await wrapNoop(middleware);

      const legacyWarnings = warnSpy.mock.calls.filter(
        (call) => typeof call[0] === 'string' && call[0].includes('allowLegacyUnsafeDelegation'),
      );
      const audienceWarnings = warnSpy.mock.calls.filter(
        (call) =>
          typeof call[0] === 'string' && call[0].includes('requireAudienceOnRedelegation'),
      );
      expect(legacyWarnings).toHaveLength(1);
      expect(audienceWarnings).toHaveLength(1);
    });
  });
});
