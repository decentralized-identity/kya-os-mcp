/**
 * `buildOutboundDelegationHeaders` and the delegation credential (SPEC §8.1).
 *
 * A downstream service that follows §8.1 derives authorization from the
 * `KYA-OS-Delegation-Credential` header: the delegation credential as a
 * VC-JWT, verified with the library's own `verifyDelegationJwt`. The chain and
 * scope headers are advisory and never read for a decision. Every party is a
 * did:key with a real Ed25519 key, so nothing is read over a network.
 */

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildOutboundDelegationHeaders, type OutboundDelegationContext } from '../outbound-headers.js';
import { DelegationCredentialVerifier } from '../vc-verifier.js';
import { createDidKeyResolver } from '../did-key-resolver.js';
import { parseVCJWT } from '../utils.js';
import { scopeSatisfies } from '../scope-matcher.js';
import { logger } from '../../logging/index.js';
import { createRealCryptoProvider, createRealIdentity } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { delegationRecord, signedJwt } from '../../__tests__/utils/delegation-credentials.js';
import type { AgentIdentity } from '../../providers/base.js';
import type { DelegationCredential, DelegationRecord } from '../../types/protocol.js';

const GRANTED = 'orders:read';
const NOT_GRANTED = 'orders:write';

let owner: AgentIdentity;
let agent: AgentIdentity;
let server: AgentIdentity;
let delegation: DelegationRecord;
let credentialJwt: string;

beforeAll(async () => {
  const crypto = createRealCryptoProvider();
  [owner, agent, server] = await Promise.all([createRealIdentity(crypto), createRealIdentity(crypto), createRealIdentity(crypto)]);
  delegation = delegationRecord(owner.did, { subjectDid: agent.did, constraints: { scopes: [GRANTED], notAfter: Math.floor(Date.now() / 1000) + 3600 } });
  credentialJwt = await signedJwt(owner, { record: delegation, kid: owner.kid });
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** What the forwarding server passes, with `overrides` set over it. */
function context(overrides: Partial<OutboundDelegationContext> = {}): OutboundDelegationContext {
  return {
    session: {
      sessionId: 'kyaos_outbound-credential',
      audience: server.did,
      nonce: 'nonce-outbound-credential',
      timestamp: Math.floor(Date.now() / 1000),
      createdAt: Date.now(),
      lastActivity: Date.now(),
      ttlMinutes: 30,
      identityState: 'authenticated',
      agentDid: agent.did,
    },
    delegation,
    serverIdentity: { did: server.did, kid: server.kid, privateKey: server.privateKey },
    targetUrl: 'https://orders.example/v1/orders',
    ...overrides,
  };
}

const verifier = new DelegationCredentialVerifier({ didResolver: createDidKeyResolver() });

/**
 * The decision of a downstream service that follows SPEC §8.1 on a request for
 * `scope` carrying `headers`: granted scopes from the verified credential only.
 */
async function authorize(headers: Readonly<Record<string, string | undefined>>, scope: string): Promise<string> {
  const credential = headers['KYA-OS-Delegation-Credential'];
  if (credential === undefined) return 'refused: no KYA-OS-Delegation-Credential header';
  const verified = await verifier.verifyDelegationJwt(credential, { skipCache: true });
  if (!verified.valid) return `refused: ${verified.reason}`;
  const vc = parseVCJWT(credential)?.payload.vc as unknown as DelegationCredential;
  if (vc.credentialSubject.id !== headers['KYA-OS-Agent-DID']) return 'refused: the credential names another agent';
  return scopeSatisfies(scope, vc).satisfied ? 'authorized' : 'refused: scope not granted';
}

describe('a service that follows SPEC §8.1, given what buildOutboundDelegationHeaders sends', () => {
  it('authorizes a scope the delegation credential grants', async () => {
    const headers = await buildOutboundDelegationHeaders(context({ credentialJwt }));
    expect(await authorize(headers, GRANTED)).toBe('authorized');
  });

  it('refuses a scope the credential does not grant, whatever the advisory headers say', async () => {
    const headers = await buildOutboundDelegationHeaders(context({ credentialJwt }));
    expect(await authorize({ ...headers, 'KYA-OS-Granted-Scopes': NOT_GRANTED }, NOT_GRANTED)).toBe('refused: scope not granted');
  });

  it('refuses every request when the caller passes no credential', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const headers = await buildOutboundDelegationHeaders(context());
    expect(await authorize(headers, GRANTED)).toBe('refused: no KYA-OS-Delegation-Credential header');
  });
});

describe('buildOutboundDelegationHeaders with credentialJwt', () => {
  it('sends the credential unchanged in KYA-OS-Delegation-Credential', async () => {
    const headers = await buildOutboundDelegationHeaders(context({ credentialJwt }));
    expect(headers['KYA-OS-Delegation-Credential']).toBe(credentialJwt);
  });

  const notVcJwt: [string, () => unknown][] = [
    ['an empty string', () => ''],
    ['the credential as JSON text', () => JSON.stringify(parseVCJWT(credentialJwt)?.payload.vc)],
    ['a JWT with no vc claim', () => `${credentialJwt.split('.')[0]}.${Buffer.from('{"iss":"did:example:x"}').toString('base64url')}.c2ln`],
    ['a VC-JWT followed by another header line', () => `${credentialJwt}\r\nX-Injected: 1`],
    ['a credential object', () => parseVCJWT(credentialJwt)?.payload.vc],
  ];

  it.each(notVcJwt)('refuses %s with a TypeError that does not echo it', async (_name, value) => {
    const error: unknown = await buildOutboundDelegationHeaders(context({ credentialJwt: value() as string })).catch((thrown: unknown) => thrown);
    expect(error).toBeInstanceOf(TypeError);
    const { message } = error as TypeError;
    expect(message).toMatch(/^OutboundDelegationContext\.credentialJwt must be the delegation credential as a compact VC-JWT/);
    expect(message).not.toMatch(/did:|X-Injected|\{/);
  });
});

describe('buildOutboundDelegationHeaders without credentialJwt', () => {
  const WARNED = Symbol.for('@kya-os/mcp/outbound-credential-warned');
  const registry = globalThis as { [WARNED]?: true };
  let previous: true | undefined;

  beforeEach(() => {
    previous = registry[WARNED];
    delete registry[WARNED];
  });

  afterEach(() => {
    if (previous === undefined) delete registry[WARNED];
    else registry[WARNED] = previous;
  });

  it('sends no credential header at all, so none reads as "undefined" on the wire', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const headers = await buildOutboundDelegationHeaders(context());
    expect(Object.keys(headers)).not.toContain('KYA-OS-Delegation-Credential');
    expect(new Headers(headers as unknown as Record<string, string>).has('KYA-OS-Delegation-Credential')).toBe(false);
  });

  it('warns once per process, across copies of the package, in words that hold nothing the caller passed', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const forged = 'did:key:z6Mk\n[kya-os] forged log line';
    const crafted = context({
      session: { ...context().session, agentDid: forged, sessionId: 'kyaos_\nforged-session' },
      targetUrl: 'https://forged-host.example/\nforged-path',
    });
    await buildOutboundDelegationHeaders(crafted);
    await buildOutboundDelegationHeaders(crafted);

    expect(warn).toHaveBeenCalledTimes(1);
    const [args] = warn.mock.calls;
    expect(args).toHaveLength(1);
    const [message] = args as [string];
    expect(message).toMatch(/^\[kya-os\] buildOutboundDelegationHeaders was given no credentialJwt/);
    expect(message).toMatch(/KYA-OS-Delegation-Credential/);
    expect(message).not.toMatch(/forged|\n/);

    vi.resetModules();
    const reloaded = await import('../outbound-headers.js');
    const logging = await import('../../logging/index.js');
    const reloadedWarn = vi.spyOn(logging.logger, 'warn').mockImplementation(() => {});
    await reloaded.buildOutboundDelegationHeaders(context());
    expect(reloadedWarn).not.toHaveBeenCalled();
  });

  it('does not warn when the credential is passed', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    await buildOutboundDelegationHeaders(context({ credentialJwt }));
    expect(warn).not.toHaveBeenCalled();
  });
});
