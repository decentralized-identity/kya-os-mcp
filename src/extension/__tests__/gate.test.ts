/**
 * The admission gate (SPEC-MCP-EXTENSION.md §4) and the JSON-RPC error surface
 * (§5): required mode answers absence with core -32021 and the
 * `extension_not_declared` reason; optional mode degrades to core behavior;
 * proof-gate failures map their snake_case codes onto `error.data.reason`
 * verbatim and never allocate from the MCP-reserved code range.
 */

import { describe, it, expect } from 'vitest';
import { PROOF_PROFILE_ID } from '../../card/schema.js';
import {
  DEFAULT_EXEMPT_METHODS,
  KYA_OS_DOMAIN_ERROR_CODE,
  missingRequiredCapabilityError,
  proofGateToJsonRpcError,
  requireExtension,
} from '../gate.js';
import {
  EXTENSION_NOT_DECLARED_REASON,
  KYA_OS_EXTENSION_ID,
  MCP_CLIENT_CAPABILITIES_META_KEY,
  MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
} from '../settings.js';

function metaDeclaring(entry: unknown): Record<string, unknown> {
  return {
    [MCP_CLIENT_CAPABILITIES_META_KEY]: { extensions: { [KYA_OS_EXTENSION_ID]: entry } },
  };
}

describe('requireExtension - optional mode (default)', () => {
  const guard = requireExtension({});

  it('admits a declared peer and reports the declaration', () => {
    const verdict = guard({ meta: metaDeclaring({ version: '1.0.0' }) });
    expect(verdict.ok).toBe(true);
    if (verdict.ok) {
      expect(verdict.declaration?.carriage).toBe('stateless');
      expect(verdict.declaration?.settings.version).toBe('1.0.0');
    }
  });

  it('admits an undeclared peer as core traffic', () => {
    const verdict = guard({});
    expect(verdict).toEqual({ ok: true });
  });

  it('degrades a malformed declaration to core behavior, never a rejection', () => {
    const verdict = guard({ meta: metaDeclaring('malformed') });
    expect(verdict).toEqual({ ok: true });
  });
});

describe('requireExtension - required mode', () => {
  const guard = requireExtension({ required: true });

  it('admits a declared peer', () => {
    const verdict = guard({ meta: metaDeclaring({}) });
    expect(verdict.ok).toBe(true);
  });

  it('admits an empty-object declaration (SEP-2133 default configuration)', () => {
    const verdict = guard({ meta: metaDeclaring({}) });
    expect(verdict.ok).toBe(true);
  });

  it('rejects an undeclared peer with the exact -32021 shape', () => {
    const verdict = guard({});
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      expect(verdict.error.code).toBe(MISSING_REQUIRED_CLIENT_CAPABILITY_CODE);
      expect(verdict.error.message).toContain(KYA_OS_EXTENSION_ID);
      expect(verdict.error.data.reason).toBe(EXTENSION_NOT_DECLARED_REASON);
      expect(verdict.error.data.extension).toBe(KYA_OS_EXTENSION_ID);
    }
  });

  it('rejects a stripped-to-malformed declaration exactly like an absent one', () => {
    const verdict = guard({ meta: metaDeclaring({ didMethods: ['web'] }) });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      expect(verdict.error.code).toBe(MISSING_REQUIRED_CLIENT_CAPABILITY_CODE);
    }
  });

  it('accepts the initialize-era carriage', () => {
    const verdict = guard({
      initializeCapabilities: { extensions: { [KYA_OS_EXTENSION_ID]: {} } },
    });
    expect(verdict.ok).toBe(true);
    if (verdict.ok) {
      expect(verdict.declaration?.carriage).toBe('initialize');
    }
  });

  it('names an overridden extension id in the rejection', () => {
    const id = 'io.modelcontextprotocol/decentralized-authority';
    const overridden = requireExtension({ required: true }, { extensionId: id });
    const verdict = overridden({});
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      expect(verdict.error.data.extension).toBe(id);
      expect(verdict.error.message).toContain(id);
    }
  });

  it.each(DEFAULT_EXEMPT_METHODS)('never gates the exempt method %s (§4.2)', (method) => {
    expect(guard({ method })).toEqual({ ok: true });
  });

  it('still gates non-exempt methods for undeclared peers', () => {
    const verdict = guard({ method: 'tools/call' });
    expect(verdict.ok).toBe(false);
  });

  it('still reports the declaration on an exempt method when one is present', () => {
    const verdict = guard({ method: 'server/discover', meta: metaDeclaring({}) });
    expect(verdict.ok).toBe(true);
    if (verdict.ok) {
      expect(verdict.declaration?.carriage).toBe('stateless');
    }
  });

  it('honors an exemptMethods override, including an empty list', () => {
    const strict = requireExtension({ required: true }, { exemptMethods: [] });
    expect(strict({ method: 'server/discover' }).ok).toBe(false);
  });
});

describe('requireExtension - own-settings validation', () => {
  it('throws on malformed server settings (programmer error, fail fast)', () => {
    expect(() => requireExtension({ version: 'not-semver' })).toThrow(KYA_OS_EXTENSION_ID);
  });
});

describe('missingRequiredCapabilityError', () => {
  it('produces the canonical §4.2 error object, core requiredCapabilities included', () => {
    expect(missingRequiredCapabilityError()).toEqual({
      code: -32021,
      message: `Missing required client capability: ${KYA_OS_EXTENSION_ID}`,
      data: {
        requiredCapabilities: { extensions: { [KYA_OS_EXTENSION_ID]: {} } },
        reason: EXTENSION_NOT_DECLARED_REASON,
        extension: KYA_OS_EXTENSION_ID,
      },
    });
  });

  it('keys requiredCapabilities.extensions by an overridden extension id', () => {
    const id = 'io.modelcontextprotocol/decentralized-authority';
    const error = missingRequiredCapabilityError(id);
    expect(error.data.requiredCapabilities).toEqual({ extensions: { [id]: {} } });
  });
});

describe('proofGateToJsonRpcError', () => {
  const gateError = {
    code: 'proof_missing',
    message: 'no org.kya-os/request-proof in _meta',
    reasons: ['proof_missing'],
  };

  it('carries the snake_case code verbatim in error.data.reason', () => {
    const error = proofGateToJsonRpcError(gateError);
    expect(error.code).toBe(KYA_OS_DOMAIN_ERROR_CODE);
    expect(error.message).toBe(gateError.message);
    expect(error.data.reason).toBe('proof_missing');
    expect(error.data.profile).toBe(PROOF_PROFILE_ID);
    expect(error.data.reasons).toEqual(['proof_missing']);
  });

  it('omits empty diagnostics', () => {
    const error = proofGateToJsonRpcError({ code: 'proof_invalid', message: 'nope', reasons: [] });
    expect(error.data.reasons).toBeUndefined();
  });

  it('accepts an implementation-defined code override', () => {
    expect(proofGateToJsonRpcError(gateError, { code: -32005 }).code).toBe(-32005);
  });

  it.each([-32020, -32021, -32099])(
    'refuses the MCP-reserved code %d (SPEC-MCP-EXTENSION.md §5.1)',
    (code) => {
      expect(() => proofGateToJsonRpcError(gateError, { code })).toThrow('MCP-reserved');
    },
  );

  it('allows codes outside the JSON-RPC reserved range', () => {
    expect(proofGateToJsonRpcError(gateError, { code: -31005 }).code).toBe(-31005);
  });

  it('defaults to a code outside the JSON-RPC reserved range', () => {
    expect(KYA_OS_DOMAIN_ERROR_CODE).toBeGreaterThan(-32000);
  });
});
