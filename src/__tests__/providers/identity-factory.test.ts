/**
 * Tests for identity provisioning helpers
 *
 * Covers did:key + did:web provisioning, option propagation
 * (clock, metadata, kidFragment), did:web argument validation, and
 * end-to-end round-trips with `resolveDidKeySync` and
 * `buildDidWebDocument` to lock the produced shape against the
 * resolvers that consume it.
 */

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
  createDidKeyIdentity,
  createDidWebIdentity,
  createIdentity,
} from '../../providers/identity-factory.js';
import type {
  CreateIdentityRequest,
  ProvisionedIdentity,
} from '../../providers/identity-factory.js';
import { NodeCryptoProvider } from '../../providers/node-crypto.js';
import { ClockProvider, CryptoProvider } from '../../providers/base.js';
import type { Identity } from '../../providers/base.js';
import {
  resolveDidKeySync,
  extractPublicKeyFromDidKey,
} from '../../delegation/did-key-resolver.js';
import {
  buildDidWebDocument,
  parseDidWeb,
  didWebToUrl,
} from '../../delegation/did-web-resolver.js';
import { bytesToBase64 } from '../../utils/base64.js';

const crypto = new NodeCryptoProvider();

/** Fixed-instant clock used to assert deterministic `createdAt` stamping. */
class FixedClock extends ClockProvider {
  constructor(private readonly fixedMs: number) {
    super();
  }
  now(): number {
    return this.fixedMs;
  }
  isWithinSkew(_timestamp: number, _skewSeconds: number): boolean {
    return true;
  }
  hasExpired(_expiresAt: number): boolean {
    return false;
  }
  calculateExpiry(ttlSeconds: number): number {
    return this.fixedMs + ttlSeconds * 1000;
  }
  format(timestamp: number): string {
    return new Date(timestamp).toISOString();
  }
}

describe('createDidKeyIdentity', () => {
  it('produces an Identity whose DID is a valid Ed25519 did:key', async () => {
    const identity = await createDidKeyIdentity(crypto);

    expect(identity.did.startsWith('did:key:z6Mk')).toBe(true);
  });

  it('produces a kid that references the produced DID', async () => {
    const identity = await createDidKeyIdentity(crypto);

    expect(identity.kid.startsWith(`${identity.did}#`)).toBe(true);
  });

  it('returns the private key alongside the public key', async () => {
    const identity = await createDidKeyIdentity(crypto);

    expect(identity.privateKey.length).toBeGreaterThan(0);
    expect(identity.publicKey.length).toBeGreaterThan(0);
  });

  it('stamps createdAt with an ISO-8601 timestamp from the host clock by default', async () => {
    const before = Date.now();
    const identity = await createDidKeyIdentity(crypto);
    const after = Date.now();

    const parsed = Date.parse(identity.createdAt);
    expect(Number.isFinite(parsed)).toBe(true);
    expect(parsed).toBeGreaterThanOrEqual(before);
    expect(parsed).toBeLessThanOrEqual(after);
  });

  it('honours an injected clock for deterministic createdAt', async () => {
    const fixedMs = Date.UTC(2026, 0, 1, 12, 0, 0);
    const identity = await createDidKeyIdentity(crypto, {
      clock: new FixedClock(fixedMs),
    });

    expect(identity.createdAt).toBe(new Date(fixedMs).toISOString());
  });

  it('attaches metadata when supplied and omits the field otherwise', async () => {
    const withMetadata = await createDidKeyIdentity(crypto, {
      metadata: { source: 'unit-test' },
    });
    const withoutMetadata = await createDidKeyIdentity(crypto);

    expect(withMetadata.metadata).toEqual({ source: 'unit-test' });
    expect(Object.prototype.hasOwnProperty.call(withoutMetadata, 'metadata')).toBe(false);
  });

  it('produces a DID that resolves via resolveDidKeySync', async () => {
    const identity = await createDidKeyIdentity(crypto);

    const document = resolveDidKeySync(identity.did);

    expect(document).not.toBeNull();
    expect(document?.id).toBe(identity.did);
    expect(document?.verificationMethod?.[0]?.controller).toBe(identity.did);
  });

  it('produces a public key that extracts back to 32 raw Ed25519 bytes', async () => {
    const identity = await createDidKeyIdentity(crypto);

    const extracted = extractPublicKeyFromDidKey(identity.did);
    expect(extracted).not.toBeNull();
    expect(extracted?.length).toBe(32);

    // The extracted bytes, re-encoded as base64, must match the identity's publicKey.
    expect(bytesToBase64(extracted!)).toBe(identity.publicKey);
  });
});

describe('createDidWebIdentity', () => {
  describe('happy path', () => {
    it('produces did:web:<domain> when no path is supplied', async () => {
      const identity = await createDidWebIdentity(crypto, { domain: 'example.com' });

      expect(identity.did).toBe('did:web:example.com');
      expect(identity.kid).toBe('did:web:example.com#keys-1');
    });

    it('joins path segments with ":" to form the DID', async () => {
      const identity = await createDidWebIdentity(crypto, {
        domain: 'example.com',
        path: ['users', 'alice'],
      });

      expect(identity.did).toBe('did:web:example.com:users:alice');
      expect(identity.kid).toBe('did:web:example.com:users:alice#keys-1');
    });

    it('preserves percent-encoded ports in the authority component', async () => {
      const identity = await createDidWebIdentity(crypto, {
        domain: 'example.com%3A8080',
        path: ['agents', 'bot1'],
      });

      expect(identity.did).toBe('did:web:example.com%3A8080:agents:bot1');
    });

    it('honours a custom kidFragment', async () => {
      const identity = await createDidWebIdentity(
        crypto,
        { domain: 'example.com' },
        { kidFragment: 'primary' }
      );

      expect(identity.kid).toBe('did:web:example.com#primary');
    });

    it('honours an injected clock for deterministic createdAt', async () => {
      const fixedMs = Date.UTC(2026, 0, 1, 12, 0, 0);
      const identity = await createDidWebIdentity(
        crypto,
        { domain: 'example.com' },
        { clock: new FixedClock(fixedMs) }
      );

      expect(identity.createdAt).toBe(new Date(fixedMs).toISOString());
    });

    it('returns the private key alongside the public key', async () => {
      const identity = await createDidWebIdentity(crypto, { domain: 'example.com' });

      expect(identity.privateKey.length).toBeGreaterThan(0);
      expect(identity.publicKey.length).toBeGreaterThan(0);
    });

    it('attaches metadata when supplied and omits the field otherwise', async () => {
      const withMetadata = await createDidWebIdentity(
        crypto,
        { domain: 'example.com' },
        { metadata: { source: 'unit-test' } }
      );
      const withoutMetadata = await createDidWebIdentity(crypto, { domain: 'example.com' });

      expect(withMetadata.metadata).toEqual({ source: 'unit-test' });
      expect(Object.prototype.hasOwnProperty.call(withoutMetadata, 'metadata')).toBe(false);
    });

    it('produces an Identity that buildDidWebDocument accepts', async () => {
      const identity = await createDidWebIdentity(crypto, {
        domain: 'example.com',
        path: ['users', 'alice'],
      });

      const document = buildDidWebDocument(identity);

      expect(document.id).toBe(identity.did);
      expect(document.verificationMethod?.[0]?.id).toBe(identity.kid);
      expect(document.verificationMethod?.[0]?.controller).toBe(identity.did);
    });
  });

  describe('domain validation — surface checks', () => {
    it('throws when domain is empty', async () => {
      await expect(
        createDidWebIdentity(crypto, { domain: '' })
      ).rejects.toThrow(/must not be empty/);
    });

    it('throws when domain includes a scheme prefix', async () => {
      await expect(
        createDidWebIdentity(crypto, { domain: 'https://example.com' })
      ).rejects.toThrow(/must not include a scheme/);
    });

    it('throws when domain contains "/"', async () => {
      await expect(
        createDidWebIdentity(crypto, { domain: 'example.com/users' })
      ).rejects.toThrow(/must not contain "\/"/);
    });

    it.each([':example.com', 'example.com:', 'example.com:8080', 'a:b:c'])(
      'throws when domain contains a literal ":" (%s)',
      async (domain) => {
        await expect(
          createDidWebIdentity(crypto, { domain })
        ).rejects.toThrow(/must not contain ":"; percent-encode ports as "%3A"/);
      }
    );
  });

  describe('domain validation — percent-encoding traversal', () => {
    it.each(['%', '%G1', 'example.com%', 'example.com%2'])(
      'throws on invalid or incomplete percent-encoding (%s)',
      async (domain) => {
        await expect(
          createDidWebIdentity(crypto, { domain })
        ).rejects.toThrow(/invalid percent-encoded byte sequence/);
      }
    );

    it.each([
      ['%2F..%2Fevil.com', '"/", "\\\\", or NUL'],
      ['%2f..%2fevil.com', '"/", "\\\\", or NUL'],
      ['example.com%00', '"/", "\\\\", or NUL'],
      ['example.com%5Cevil.com', '"/", "\\\\", or NUL'],
    ])(
      'rejects encoded traversal sequences (%s)',
      async (domain, expected) => {
        await expect(
          createDidWebIdentity(crypto, { domain })
        ).rejects.toThrow(new RegExp(expected));
      }
    );
  });

  describe('domain validation — RFC 3986 reg-name grammar', () => {
    it.each([
      'example com',         // space
      '-example.com',         // leading hyphen on first label
      'example-.com',         // trailing hyphen on first label
      'example..com',         // empty label
      '.example.com',         // leading dot → empty first label
      'example.com.',         // trailing dot → empty last label
      '-',                     // hyphen-only label
      '.',                     // empty labels around dot
    ])('rejects invalid hostname shape (%s)', async (domain) => {
      await expect(
        createDidWebIdentity(crypto, { domain })
      ).rejects.toThrow(/invalid hostname|must not decode|containing/);
    });

    it('rejects hostnames over 253 characters', async () => {
      const longLabel = 'a'.repeat(60);
      const domain = `${longLabel}.${longLabel}.${longLabel}.${longLabel}.${longLabel}`; // 304 chars
      await expect(
        createDidWebIdentity(crypto, { domain })
      ).rejects.toThrow(/invalid hostname/);
    });

    it('rejects labels over 63 characters', async () => {
      const longLabel = 'a'.repeat(64);
      await expect(
        createDidWebIdentity(crypto, { domain: `${longLabel}.com` })
      ).rejects.toThrow(/invalid hostname/);
    });
  });

  describe('domain validation — port grammar', () => {
    it('accepts a valid percent-encoded port', async () => {
      const identity = await createDidWebIdentity(crypto, {
        domain: 'example.com%3A8080',
      });
      expect(identity.did).toBe('did:web:example.com%3A8080');
    });

    it.each(['example.com%3A99999', 'example.com%3Aabc', 'example.com%3A'])(
      'rejects invalid ports (%s)',
      async (domain) => {
        await expect(
          createDidWebIdentity(crypto, { domain })
        ).rejects.toThrow(/invalid port/);
      }
    );
  });

  describe('path-segment validation', () => {
    it('throws when a path segment is empty', async () => {
      await expect(
        createDidWebIdentity(crypto, { domain: 'example.com', path: ['users', ''] })
      ).rejects.toThrow(/path segments must be non-empty/);
    });

    it.each(['alice:bob', 'a:b:c'])(
      'rejects raw ":" in segment (%s)',
      async (segment) => {
        await expect(
          createDidWebIdentity(crypto, {
            domain: 'example.com',
            path: [segment],
          })
        ).rejects.toThrow(/must not contain ":"/);
      }
    );

    it('rejects raw "/" in segment', async () => {
      await expect(
        createDidWebIdentity(crypto, {
          domain: 'example.com',
          path: ['alice/bob'],
        })
      ).rejects.toThrow(/must not contain "\/"/);
    });

    it.each(['..', '.'])(
      'rejects relative-path segment (%s)',
      async (segment) => {
        await expect(
          createDidWebIdentity(crypto, {
            domain: 'example.com',
            path: [segment],
          })
        ).rejects.toThrow(/relative path component|disallowed by did:web/);
      }
    );

    it.each([
      '%2E%2E',           // .. encoded
      '%2e%2e',           // .. encoded (lowercase hex)
      '%2Fevil',          // / encoded
      'foo%00bar',        // NUL encoded
      'foo%5Cevil',       // backslash encoded
    ])('rejects encoded traversal in segment (%s)', async (segment) => {
      await expect(
        createDidWebIdentity(crypto, {
          domain: 'example.com',
          path: [segment],
        })
      ).rejects.toThrow(/relative path component|must not decode|containing/);
    });

    it.each(['%', '%G1', 'foo%', 'foo%2'])(
      'rejects invalid percent-encoding in segment (%s)',
      async (segment) => {
        await expect(
          createDidWebIdentity(crypto, {
            domain: 'example.com',
            path: [segment],
          })
        ).rejects.toThrow(/invalid percent-encoded byte sequence/);
      }
    );

    it('accepts valid percent-encoded segments', async () => {
      const identity = await createDidWebIdentity(crypto, {
        domain: 'example.com',
        path: ['users', 'alice%20smith'],
      });
      expect(identity.did).toBe('did:web:example.com:users:alice%20smith');
    });

    it.each([
      '%2E',      // single dot, uppercase hex
      '%2e',      // single dot, lowercase hex
    ])(
      'rejects single-dot segment via encoded form (%s) — symmetry with %2E%2E',
      async (segment) => {
        // The exact-string check `decoded === '.'` catches it, but
        // pinning the symmetry with the existing `%2E%2E` rejection
        // ensures a future refactor that loosens one without the
        // other gets caught by CI.
        await expect(
          createDidWebIdentity(crypto, {
            domain: 'example.com',
            path: [segment],
          })
        ).rejects.toThrow(/relative path component/);
      }
    );

    it.each([
      'alice!bob',         // sub-delim "!"
      "O'Brien",           // sub-delim "'"
      'c++',               // sub-delim "+"
      'cost,benefit',      // sub-delim ","
      'key=value',         // sub-delim "="
      'fn(arg)',           // sub-delims "()"
      '$pecial',           // sub-delim "$"
      'user@host',         // pchar "@"
      'nested;mark',       // sub-delim ";"
      'ampersand&here',    // sub-delim "&"
      'multiplier*here',   // sub-delim "*"
    ])(
      'accepts RFC 3986 pchar segment character class (%s)',
      async (segment) => {
        // Widened from the prior `unreserved + pct-encoded` set to the
        // full pchar grammar minus `:` (the path separator). Pins the
        // spec-conformant surface: any segment another implementation
        // can legally emit must round-trip through this helper.
        const identity = await createDidWebIdentity(crypto, {
          domain: 'example.com',
          path: [segment],
        });
        expect(identity.did).toBe(`did:web:example.com:${segment}`);
      }
    );

    it.each([
      'has space',         // SP — not in pchar
      'has\ttab',          // HT — control char
      'lt<gt',             // "<" — not in pchar (gen-delim)
      'pipe|here',         // "|" — not in pchar
      'caret^here',        // "^" — not in pchar
      'has`backtick',      // "`" — not in pchar
      'sq[bracket',        // "[" — gen-delim, not in pchar
      'curly{brace',       // "{" — not in pchar
      'question?mark',     // "?" — in fragment grammar but not in pchar
      'hash#mark',         // "#" — gen-delim, not in pchar
    ])(
      'rejects characters outside RFC 3986 pchar via the final structural regex (%s)',
      async (segment) => {
        // These inputs survive the surface checks (no raw ":" or "/"),
        // survive percent-decoding (no "%" to decode), and survive the
        // decoded-traversal checks — they must still be rejected by
        // the final pchar regex. Without this coverage that branch was
        // reached by nothing in the suite.
        await expect(
          createDidWebIdentity(crypto, {
            domain: 'example.com',
            path: [segment],
          })
        ).rejects.toThrow(/disallowed by RFC 3986 pchar grammar/);
      }
    );
  });

  describe('domain validation — multi-delimiter ordering', () => {
    it('reports "multiple \\":\\"" before "invalid port" for a%3Ab%3Ac', async () => {
      // The post-decode multi-colon check used to live after the port
      // check, where it was unreachable (`portPart` containing `:`
      // would fail `isValidPort` first). Reordering makes the check
      // reachable AND produces a more specific error for the input.
      await expect(
        createDidWebIdentity(crypto, { domain: 'a%3Ab%3Ac' })
      ).rejects.toThrow(/multiple ":" delimiters/);
    });
  });

  describe('kidFragment validation', () => {
    it('throws when kidFragment is the empty string', async () => {
      await expect(
        createDidWebIdentity(
          crypto,
          { domain: 'example.com' },
          { kidFragment: '' }
        )
      ).rejects.toThrow(/kidFragment must not be empty/);
    });

    it.each([
      'foo#bar',          // "#" — only one fragment delimiter per URI
      'has space',        // whitespace not in pchar
      'tab\there',        // tab control char
      'line\nfeed',       // LF control char
      'null byte',   // NUL control char
      'foo%G1',           // invalid percent escape
      'foo%',             // bare percent
    ])('rejects fragments outside RFC 3986 grammar (%s)', async (kidFragment) => {
      await expect(
        createDidWebIdentity(
          crypto,
          { domain: 'example.com' },
          { kidFragment }
        )
      ).rejects.toThrow(/disallowed by RFC 3986 fragment grammar/);
    });

    it.each([
      'keys-1',
      'verification-method-1',
      'controller-2024',
      'auth:primary',      // ":" is in pchar
      'keys/main',         // "/" is allowed by fragment grammar
      'keys.v1',
      'key_~tilde',
    ])('accepts fragments inside RFC 3986 grammar (%s)', async (kidFragment) => {
      const identity = await createDidWebIdentity(
        crypto,
        { domain: 'example.com' },
        { kidFragment }
      );
      expect(identity.kid).toBe(`did:web:example.com#${kidFragment}`);
    });
  });
});

describe('cryptographic correctness', () => {
  it('createDidKeyIdentity produces a keypair that signs and verifies', async () => {
    const identity = await createDidKeyIdentity(crypto);
    const message = new TextEncoder().encode('cryptographic sanity check');

    const signature = await crypto.sign(message, identity.privateKey);
    const valid = await crypto.verify(message, signature, identity.publicKey);

    expect(valid).toBe(true);
  });

  it('createDidWebIdentity produces a keypair that signs and verifies', async () => {
    const identity = await createDidWebIdentity(crypto, {
      domain: 'example.com',
      path: ['users', 'alice'],
    });
    const message = new TextEncoder().encode('cryptographic sanity check');

    const signature = await crypto.sign(message, identity.privateKey);
    const valid = await crypto.verify(message, signature, identity.publicKey);

    expect(valid).toBe(true);
  });

  it('signatures do not verify against a different identity', async () => {
    const a = await createDidKeyIdentity(crypto);
    const b = await createDidKeyIdentity(crypto);
    const message = new TextEncoder().encode('cross-identity isolation');

    const signedByA = await crypto.sign(message, a.privateKey);
    const verifiesAgainstB = await crypto.verify(message, signedByA, b.publicKey);

    expect(verifiesAgainstB).toBe(false);
  });
});

describe('metadata isolation', () => {
  /**
   * One test per helper, each asserting the strong property: the
   * produced `metadata` is a deep clone — distinct reference at the top
   * level AND at every nested level — so subsequent caller mutations
   * cannot leak in. A shallow clone would pass top-level reference
   * inequality but fail the nested mutation assertion.
   */

  it('createDidKeyIdentity deep-clones metadata (top-level + nested)', async () => {
    const nested = { ttlSeconds: 60 };
    const metadata: Record<string, unknown> = { policy: nested };

    const identity = await createDidKeyIdentity(crypto, { metadata });

    expect(identity.metadata).not.toBe(metadata);
    expect(identity.metadata?.['policy']).not.toBe(nested);

    nested.ttlSeconds = 999;
    expect(
      (identity.metadata?.['policy'] as { ttlSeconds: number }).ttlSeconds
    ).toBe(60);
  });

  it('createDidWebIdentity deep-clones metadata (top-level + nested)', async () => {
    const nested = { ttlSeconds: 60 };
    const metadata: Record<string, unknown> = { policy: nested };

    const identity = await createDidWebIdentity(
      crypto,
      { domain: 'example.com' },
      { metadata }
    );

    expect(identity.metadata).not.toBe(metadata);
    expect(identity.metadata?.['policy']).not.toBe(nested);

    nested.ttlSeconds = 999;
    expect(
      (identity.metadata?.['policy'] as { ttlSeconds: number }).ttlSeconds
    ).toBe(60);
  });
});

describe('CryptoProvider error propagation', () => {
  class FailingCryptoProvider extends CryptoProvider {
    async sign(): Promise<Uint8Array> {
      throw new Error('unused in this test');
    }
    async verify(): Promise<boolean> {
      throw new Error('unused in this test');
    }
    async generateKeyPair(): Promise<{ privateKey: string; publicKey: string }> {
      throw new Error('crypto subsystem unavailable');
    }
    async hash(): Promise<string> {
      throw new Error('unused in this test');
    }
    async randomBytes(): Promise<Uint8Array> {
      throw new Error('unused in this test');
    }
  }

  it('createDidKeyIdentity rejects when the provider fails to generate a key pair', async () => {
    await expect(createDidKeyIdentity(new FailingCryptoProvider())).rejects.toThrow(
      /crypto subsystem unavailable/
    );
  });

  it('createDidWebIdentity rejects when the provider fails to generate a key pair', async () => {
    await expect(
      createDidWebIdentity(new FailingCryptoProvider(), { domain: 'example.com' })
    ).rejects.toThrow(/crypto subsystem unavailable/);
  });

  it('createDidWebIdentity surfaces validation errors before invoking the provider', async () => {
    // Argument validation runs synchronously inside the async function,
    // so a CryptoProvider that throws on every call should not be
    // reached when the inputs are themselves invalid.
    const provider = new FailingCryptoProvider();

    await expect(
      createDidWebIdentity(provider, { domain: 'https://example.com' })
    ).rejects.toThrow(/must not include a scheme prefix/);
  });
});

describe('type contract', () => {
  it('Identity is NOT assignable to ProvisionedIdentity (privateKey is narrowed to required)', () => {
    // A base Identity without `privateKey` must fail to assign to
    // ProvisionedIdentity. The `@ts-expect-error` directive flips the
    // failure mode: if a future refactor weakens ProvisionedIdentity
    // (e.g. removes the `& { privateKey: string }` narrowing), the
    // directive becomes unused and the build fails.
    //
    // The reverse direction — `ProvisionedIdentity` → `Identity` — is
    // tautological for intersection types (always satisfied by
    // construction), so it would not catch a regression of this kind.
    const identityOnly: Identity = {
      did: 'did:key:z6Mk',
      kid: 'did:key:z6Mk#z6Mk',
      publicKey: 'pk',
      createdAt: '2026-01-01T00:00:00.000Z',
    };

    // @ts-expect-error — Identity has optional privateKey;
    // ProvisionedIdentity requires it.
    const _narrowed: ProvisionedIdentity = identityOnly;

    expect(_narrowed.did).toBe('did:key:z6Mk');
  });

  it('a fully-formed ProvisionedIdentity satisfies its declared shape', () => {
    // Sanity-check that the runtime shape carrying every documented
    // field still type-checks. This is intentionally a tautology — its
    // job is to fail compilation if any field is renamed or removed
    // from the public type.
    const provisioned: ProvisionedIdentity = {
      did: 'did:key:z6Mk',
      kid: 'did:key:z6Mk#z6Mk',
      publicKey: 'pk',
      privateKey: 'sk',
      createdAt: '2026-01-01T00:00:00.000Z',
    };

    expect(provisioned.privateKey).toBe('sk');
  });
});

describe('did:web resolver round-trip', () => {
  /**
   * The produced DID must survive a parse-rebuild via the existing
   * `parseDidWeb` and `didWebToUrl` helpers. This catches encoding
   * mistakes that `buildDidWebDocument` (a different consumer) would
   * not surface — e.g. a `kid` whose fragment slips a `/` into the
   * resolution URL.
   */

  it('produces a DID that round-trips through parseDidWeb and didWebToUrl', async () => {
    const identity = await createDidWebIdentity(crypto, {
      domain: 'example.com%3A8080',
      path: ['users', 'alice'],
    });

    const parsed = parseDidWeb(identity.did);
    expect(parsed?.domain).toBe('example.com:8080');
    expect(parsed?.path).toEqual(['users', 'alice']);

    const url = didWebToUrl(identity.did);
    expect(url).toBe('https://example.com:8080/users/alice/did.json');
  });

  it('kidFragment with a "/" character does not corrupt the resolution URL', async () => {
    // RFC 3986 allows "/" in fragment grammar; verify the slash stays
    // in the fragment (after "#") and never bleeds into the path-side
    // of the DID where it would change `didWebToUrl` output.
    const identity = await createDidWebIdentity(
      crypto,
      { domain: 'example.com', path: ['users', 'alice'] },
      { kidFragment: 'keys/main' }
    );

    expect(identity.did).toBe('did:web:example.com:users:alice');
    expect(identity.kid).toBe('did:web:example.com:users:alice#keys/main');
    expect(didWebToUrl(identity.did)).toBe(
      'https://example.com/users/alice/did.json'
    );
  });
});

describe('input-shape defensive checks', () => {
  it('throws a helper-prefixed error when args.path is not an array', async () => {
    // Plain-JS callers can pass non-array values that TypeScript's
    // `readonly string[]` signature would otherwise reject. Surface a
    // construction-throws message rather than a cryptic platform
    // `TypeError` from `.map`.
    await expect(
      createDidWebIdentity(crypto, {
        domain: 'example.com',
        path: 'users' as unknown as readonly string[],
      })
    ).rejects.toThrow(/args\.path must be an array of strings/);
  });

  it('wraps structuredClone failures with a helper-prefixed message', async () => {
    // Functions and other host-bound values cannot be structurally
    // cloned. The platform raises a `DataCloneError`/`DOMException`;
    // the helper wraps that in a consistent construction-throws Error
    // so callers see the same message shape as the validators.
    const metadata = { policy: () => 'not-cloneable' };

    await expect(
      createDidKeyIdentity(crypto, { metadata })
    ).rejects.toThrow(
      /metadata contains values that cannot be structurally cloned/
    );

    await expect(
      createDidWebIdentity(crypto, { domain: 'example.com' }, { metadata })
    ).rejects.toThrow(
      /metadata contains values that cannot be structurally cloned/
    );
  });
});

describe('providers barrel re-exports', () => {
  it('exposes the factory through @kya-os/mcp/providers', async () => {
    const barrel = await import('../../providers/index.js');

    expect(barrel.createDidKeyIdentity).toBe(createDidKeyIdentity);
    expect(barrel.createDidWebIdentity).toBe(createDidWebIdentity);
    expect(barrel.createIdentity).toBe(createIdentity);
  });
});

/* ============================================================
 * createIdentity dispatching surface
 * ============================================================
 *
 * The dispatcher exists so future DID methods (did:jwk, did:peer,
 * did:ion) can be added by extending the discriminated union rather
 * than by adding new top-level exports. These tests pin three
 * properties: (1) each branch produces the same output as the
 * method-specific helper, (2) options propagate per method, (3) the
 * discriminated-union argument shape catches caller mistakes at
 * compile time.
 */

describe('createIdentity dispatcher', () => {
  it('did:key branch produces the same Identity shape as createDidKeyIdentity', async () => {
    const fixedMs = Date.UTC(2026, 0, 1);
    const a = await createIdentity(crypto, {
      method: 'did:key',
      clock: new FixedClock(fixedMs),
      metadata: { source: 'dispatcher' },
    });
    const b = await createDidKeyIdentity(crypto, {
      clock: new FixedClock(fixedMs),
      metadata: { source: 'helper' },
    });

    // Shape parity (modulo the key material, which is freshly minted
    // on each call).
    expect(a.did).toMatch(/^did:key:z6Mk/);
    expect(b.did).toMatch(/^did:key:z6Mk/);
    expect(a.kid.startsWith(`${a.did}#`)).toBe(true);
    expect(a.createdAt).toBe(b.createdAt);
    expect(a.metadata).toEqual({ source: 'dispatcher' });
  });

  it('did:web branch produces the same Identity shape as createDidWebIdentity', async () => {
    const fixedMs = Date.UTC(2026, 0, 1);
    const a = await createIdentity(crypto, {
      method: 'did:web',
      domain: 'example.com',
      path: ['users', 'alice'],
      clock: new FixedClock(fixedMs),
      kidFragment: 'keys-1',
    });
    const b = await createDidWebIdentity(
      crypto,
      { domain: 'example.com', path: ['users', 'alice'] },
      { clock: new FixedClock(fixedMs), kidFragment: 'keys-1' }
    );

    expect(a.did).toBe('did:web:example.com:users:alice');
    expect(a.did).toBe(b.did);
    expect(a.kid).toBe(b.kid);
    expect(a.createdAt).toBe(b.createdAt);
  });

  it('did:key branch rejects kidFragment at compile time (W3C did:key §3 fixes the fragment)', () => {
    // The W3C CCG did:key specification fixes the fragment to the
    // multibase public-key id; allowing an override would violate
    // that contract. The discriminated request type makes the
    // misuse a compile error — replacing the prior runtime "silent
    // ignore" behaviour with build-time rejection.
    //
    // The `@ts-expect-error` directive flips the failure mode: if a
    // future refactor weakens the union (e.g. flattens kidFragment
    // onto the shared options), the directive becomes unused and
    // the build fails.

    // @ts-expect-error — `kidFragment` does not exist on the did:key branch.
    void { method: 'did:key', kidFragment: 'overridden' } satisfies CreateIdentityRequest;

    expect(true).toBe(true);
  });

  it('rejects did:web through the dispatcher with the same error as the direct helper', async () => {
    await expect(
      createIdentity(crypto, {
        method: 'did:web',
        domain: 'https://example.com',
      })
    ).rejects.toThrow(/must not include a scheme/);
  });

  it('request shape enforces method-specific required fields at compile time', () => {
    // @ts-expect-error — did:web requires `domain`; this object is missing it.
    const _bad: CreateIdentityRequest = { method: 'did:web' };
    expect(_bad.method).toBe('did:web');

    // did:key with no extra fields type-checks as a minimal request.
    const ok: CreateIdentityRequest = { method: 'did:key' };
    expect(ok.method).toBe('did:key');
  });
});

/* ============================================================
 * Error-message sanitisation
 * ============================================================
 *
 * Identity-protocol error pipelines flow into logs that downstream
 * operators read. Caller-controlled input that contains control
 * characters, NULs, or ANSI escapes could spoof log entries or break
 * structured-log parsers. The helper sanitises every echoed input.
 */

describe('error-message sanitisation', () => {
  it('truncates over-long input to ~60 chars with an ellipsis', async () => {
    const longDomain = 'a'.repeat(200);
    try {
      await createDidWebIdentity(crypto, { domain: longDomain });
      expect.fail('should have rejected');
    } catch (err) {
      const msg = (err as Error).message;
      // The echoed portion must not exceed the truncation cap.
      const echo = msg.match(/"([^"]*)"/);
      expect(echo).not.toBeNull();
      expect(echo![1]!.length).toBeLessThanOrEqual(60);
      expect(echo![1]!.endsWith('...')).toBe(true);
    }
  });

  it('hex-encodes C0 control characters in the echoed input', async () => {
    // Embedded NUL is the canonical log-injection vector. The
    // sanitiser must replace it with `\x00` so a downstream log
    // parser sees the literal bytes "\x00", not an embedded NUL.
    const domainWithNul = `evil${String.fromCharCode(0)}example.com`;
    try {
      await createDidWebIdentity(crypto, { domain: domainWithNul });
      expect.fail('should have rejected');
    } catch (err) {
      const msg = (err as Error).message;
      expect(msg).toContain('\\x00');
      expect(msg.includes(String.fromCharCode(0))).toBe(false);
    }
  });

  it('hex-encodes C1 control characters (e.g. CSI 0x9B)', async () => {
    // A C1 control byte like 0x9B (Control Sequence Introducer) is
    // not a printable character and can drive an ANSI-capable
    // terminal into an unsafe state if logged unfiltered.
    const domainWithCsi = `evil${String.fromCharCode(0x9b)}example.com`;
    try {
      await createDidWebIdentity(crypto, { domain: domainWithCsi });
      expect.fail('should have rejected');
    } catch (err) {
      const msg = (err as Error).message;
      expect(msg).toContain('\\x9B');
      expect(msg.includes(String.fromCharCode(0x9b))).toBe(false);
    }
  });

  it('passes through printable ASCII unchanged', async () => {
    // Regression guard: the sanitiser must not over-strict by
    // mangling normal printable characters. Use an invalid
    // percent-encoding (`%XX` — `XX` is not hex) so the validator
    // reaches the echoing throw site at `validateDidWebDomain`
    // step 2 (`decodeURIComponent` failure), past the surface checks
    // that would short-circuit on raw `/` or `:`.
    const printableDomain = 'EXAMPLE.com%XX';
    try {
      await createDidWebIdentity(crypto, { domain: printableDomain });
      expect.fail('should have rejected');
    } catch (err) {
      const msg = (err as Error).message;
      expect(msg).toContain('EXAMPLE.com%XX');
    }
  });

  it('hex-escapes bidi-override characters (Trojan-Source class)', async () => {
    // The Trojan-Source family of attacks (CVE-2021-42574) splices
    // bidi-override characters into source / log streams to reverse
    // the rendered display. The sanitiser must hex-escape these
    // bytes alongside C0/C1 controls — otherwise the docstring's
    // log-spoofing defence claim is false.
    //
    // We use a domain failing percent-decoding (`%XX`) so the
    // validator reaches the echoing throw site and exercises the
    // sanitiser on caller-controlled bytes that contain a bidi
    // override (U+202E, RIGHT-TO-LEFT OVERRIDE).
    const domainWithBidiOverride = `evil‮txt%XX`;
    try {
      await createDidWebIdentity(crypto, { domain: domainWithBidiOverride });
      expect.fail('should have rejected');
    } catch (err) {
      const msg = (err as Error).message;
      expect(msg).toContain('\\u202E');
      expect(msg.includes('‮')).toBe(false);
    }
  });

  it.each([
    ['​', 'U+200B'], // ZWSP (zero-width space)
    ['‎', 'U+200E'], // LRM (left-to-right mark)
    ['‪', 'U+202A'], // LRE (left-to-right embedding)
    ['‭', 'U+202D'], // LRO (left-to-right override)
    ['⁦', 'U+2066'], // LRI (left-to-right isolate)
    ['⁩', 'U+2069'], // PDI (pop directional isolate)
  ])(
    'hex-escapes zero-width / direction-mark / isolate %s (%s)',
    async (rawChar, codePointLabel) => {
      void codePointLabel;
      const expectedEscape = `\\u${rawChar
        .charCodeAt(0)
        .toString(16)
        .padStart(4, '0')
        .toUpperCase()}`;

      try {
        await createDidWebIdentity(crypto, { domain: `evil${rawChar}txt%XX` });
        expect.fail('should have rejected');
      } catch (err) {
        const msg = (err as Error).message;
        expect(msg).toContain(expectedEscape);
        expect(msg.includes(rawChar)).toBe(false);
      }
    }
  );

  it('truncates by code points, not UTF-16 code units (no surrogate-pair split)', async () => {
    // String.prototype.slice cuts in the middle of surrogate pairs;
    // a sanitiser that uses it can emit lone high surrogates —
    // invalid UTF-16 that downstream JSON loggers may double-encode
    // or corrupt. Build an input whose 57th UTF-16 code unit is the
    // high surrogate of a 4-byte (astral) character; the truncator
    // must NOT slice between the high and low surrogates.
    //
    // 56 ASCII chars + astral emoji (U+1F600, 2 code units) + `%XX`
    // (forces validator rejection) = 61 code units, with the emoji
    // straddling the 57th code unit boundary.
    const astral = '\u{1F600}'; // GRINNING FACE
    const domain = `${'a'.repeat(56)}${astral}%XX`;

    try {
      await createDidWebIdentity(crypto, { domain });
      expect.fail('should have rejected');
    } catch (err) {
      const msg = (err as Error).message;
      const echo = msg.match(/"([^"]*)"/)?.[1] ?? '';
      // Either the astral character is present in full, or it is
      // entirely absent — never a lone surrogate. We assert the
      // string is well-formed UTF-16 by re-encoding it through
      // TextEncoder; a lone surrogate triggers a replacement char.
      const reencoded = new TextDecoder('utf-8', { fatal: false }).decode(
        new TextEncoder().encode(echo)
      );
      expect(reencoded).toBe(echo);
    }
  });
});

/* ============================================================
 * Spec-anchored fixture vector
 * ============================================================
 *
 * A frozen (publicKey, privateKey) → did:key triple. If this test
 * ever fails, the encoding pipeline has drifted (base64 vs base64url,
 * multibase prefix, multicodec varint, etc.) and downstream
 * implementations that mirror this reference impl will interoperate
 * incorrectly. Generated once with NodeCryptoProvider on a Node 22
 * runtime; the value is the contract.
 */

describe('spec-anchored fixture vector (did:key)', () => {
  /**
   * A deterministic CryptoProvider that returns a known Ed25519
   * keypair. Used to anchor the encoding pipeline against drift.
   */
  class DeterministicCryptoProvider extends CryptoProvider {
    constructor(
      private readonly fixedPublicKey: string,
      private readonly fixedPrivateKey: string
    ) {
      super();
    }
    async sign(): Promise<Uint8Array> {
      throw new Error('unused in this test');
    }
    async verify(): Promise<boolean> {
      throw new Error('unused in this test');
    }
    async generateKeyPair(): Promise<{ privateKey: string; publicKey: string }> {
      return { publicKey: this.fixedPublicKey, privateKey: this.fixedPrivateKey };
    }
    async hash(): Promise<string> {
      throw new Error('unused in this test');
    }
    async randomBytes(): Promise<Uint8Array> {
      throw new Error('unused in this test');
    }
  }

  // Frozen test vector. Update only when the protocol's encoding
  // changes intentionally — never as a side-effect of refactoring.
  const FIXTURE_PUBLIC_KEY = 'ckFn+mgrgQA4IP49QprCHXx9gjpWs5H0O2N8vOrD/Sw=';
  const FIXTURE_PRIVATE_KEY = 'vRzbvcUsJyIO8zz49pkwI3iwQVip1dssHLVuepE1w5s=';
  const FIXTURE_EXPECTED_DID =
    'did:key:z6Mkn9GNL7fid2os9RRZje6rGTqhuNb1gfsv3GzZbqYdwwaB';

  it('createDidKeyIdentity produces the byte-frozen DID for the fixture keypair', async () => {
    const deterministic = new DeterministicCryptoProvider(
      FIXTURE_PUBLIC_KEY,
      FIXTURE_PRIVATE_KEY
    );

    const identity = await createDidKeyIdentity(deterministic);

    expect(identity.did).toBe(FIXTURE_EXPECTED_DID);
    expect(identity.kid).toBe(
      `${FIXTURE_EXPECTED_DID}#${FIXTURE_EXPECTED_DID.slice('did:key:'.length)}`
    );
    expect(identity.publicKey).toBe(FIXTURE_PUBLIC_KEY);
    expect(identity.privateKey).toBe(FIXTURE_PRIVATE_KEY);
  });

  it('the fixture DID survives byte-for-byte through the createIdentity dispatcher', async () => {
    const deterministic = new DeterministicCryptoProvider(
      FIXTURE_PUBLIC_KEY,
      FIXTURE_PRIVATE_KEY
    );

    const identity = await createIdentity(deterministic, { method: 'did:key' });

    expect(identity.did).toBe(FIXTURE_EXPECTED_DID);
  });
});

/* ============================================================
 * Property tests (fast-check)
 * ============================================================
 *
 * Table-driven cases catch regressions on inputs the author already
 * thought about. Property tests catch regressions on inputs the
 * author did not. Each property below asserts an invariant the
 * validator contract guarantees over an entire input class.
 */

describe('property tests', () => {
  it('createDidKeyIdentity always produces a valid Ed25519 did:key', async () => {
    // No input parameter — the property is over the implicit random
    // seed of `crypto.generateKeyPair()`. Run a small number of
    // iterations to keep the suite fast.
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 0, max: 1000 }), async () => {
        const identity = await createDidKeyIdentity(crypto);
        return (
          identity.did.startsWith('did:key:z6Mk') &&
          identity.kid.startsWith(`${identity.did}#`)
        );
      }),
      { numRuns: 20 }
    );
  });

  it('createDidWebIdentity rejects any domain containing raw ":" or "/"', async () => {
    // Construction-throws contract: literal delimiters in the
    // authority MUST be rejected at call time, no matter what surrounds
    // them. The property generates arbitrary strings containing at
    // least one such delimiter and asserts rejection.
    await fc.assert(
      fc.asyncProperty(
        fc.tuple(
          fc.string({ minLength: 1, maxLength: 20 }),
          fc.constantFrom(':', '/'),
          fc.string({ minLength: 0, maxLength: 20 })
        ),
        async ([prefix, delim, suffix]) => {
          const domain = `${prefix}${delim}${suffix}`;
          try {
            await createDidWebIdentity(crypto, { domain });
            return false;
          } catch {
            return true;
          }
        }
      ),
      { numRuns: 30 }
    );
  });

  it('any accepted path segment appears verbatim in the produced DID', async () => {
    // Round-trip invariant: if the validator accepts a segment, the
    // produced DID must contain that segment unchanged (no silent
    // re-encoding). This is the property that guarantees the
    // construction-throws contract is honest about its outputs.
    //
    // Generator filters out segments that the validator legitimately
    // rejects (`.`, `..`) — those are tested as negative cases
    // elsewhere; here we only assert the round-trip on accepted
    // inputs.
    const pcharChar = fc.constantFrom(
      'a', 'B', '1', '-', '.', '_', '~',
      '!', '$', '&', "'", '(', ')', '*', '+', ',', ';', '=', '@'
    );

    await fc.assert(
      fc.asyncProperty(
        fc
          .array(pcharChar, { minLength: 1, maxLength: 20 })
          .filter((chars) => {
            const s = chars.join('');
            return s !== '.' && s !== '..';
          }),
        async (chars) => {
          const segment = chars.join('');
          const identity = await createDidWebIdentity(crypto, {
            domain: 'example.com',
            path: [segment],
          });
          return identity.did === `did:web:example.com:${segment}`;
        }
      ),
      { numRuns: 30 }
    );
  });
});
