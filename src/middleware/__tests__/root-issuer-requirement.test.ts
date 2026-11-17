/**
 * A server that accepts delegations must say whose authority it trusts. `delegation.trustedRootIssuers`
 * names the DIDs allowed to grant authority (SPEC §6); without it the gate would accept a delegation
 * from any issuer, including one an agent signs for itself. So outside development, wrapping a tool
 * with `wrapWithDelegation` throws until the list is set, unless `delegation.allowAnyRootIssuer: true`
 * opts out by name. In development, and with the opt-out, the server starts and warns once. A server
 * that gates no tool on a delegation needs none of it. Every test uses the package's public exports,
 * as an adopter would.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  createKyaOsMiddleware,
  generateIdentity,
  logger,
  NodeCryptoProvider,
  serveInProcess,
  withKyaOs,
  type DelegationCredential,
  type KyaOsConfig,
  type KyaOsDelegationConfig,
  type KyaOsMiddleware,
} from '../../index.js';
import { ARGS, CONSENT, released, TOOL } from './helpers/delegated-call.js';
import { delegate, party, type Party } from './helpers/delegating-party.js';

const crypto = new NodeCryptoProvider();

/** What every trust-root warning says, whichever setting let the server start. */
const WARNING = 'delegation.trustedRootIssuers is not set';

/** The refusal `wrapWithDelegation` throws for `tool`, outside development, with neither setting. */
const refusal = (tool: string) =>
  `[kya-os] delegation.trustedRootIssuers is not set, so wrapWithDelegation("${tool}") would accept a delegation ` +
  'from any issuer, including one an agent signs for itself. Set delegation.trustedRootIssuers to the DIDs ' +
  'allowed to grant authority; in local development, set development: true; to accept any issuer anyway, set ' +
  'delegation.allowAnyRootIssuer: true.';

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

/** Watch the logger, and return the trust-root warnings logged since. */
function watchWarnings(): () => string[] {
  const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  return () => warn.mock.calls.map(([message]) => String(message)).filter((message) => message.includes(WARNING));
}

/** A middleware with a fresh identity and `config`. */
async function middleware(config: Partial<Omit<KyaOsConfig, 'identity'>> = {}): Promise<KyaOsMiddleware> {
  return createKyaOsMiddleware({ identity: await generateIdentity(crypto), ...config }, crypto);
}

/** A middleware whose `delegation` options are `delegation`. */
const delegating = (delegation: KyaOsDelegationConfig, config: Partial<Omit<KyaOsConfig, 'identity' | 'delegation'>> = {}) =>
  middleware({ ...config, delegation });

/** `tool` on `kyaos`, gated on a delegation. */
const gate = (kyaos: KyaOsMiddleware, tool = TOOL) => kyaos.wrapWithDelegation(tool, CONSENT, released);

/** Whether `kyaos`'s gated tool runs for a caller that presents `delegation`. */
async function runs(kyaos: KyaOsMiddleware, delegation: DelegationCredential): Promise<boolean> {
  const local = serveInProcess(kyaos);
  try {
    const result = await local.tool(TOOL, gate(kyaos))({ ...ARGS, _kyaos_delegation: delegation });
    return result.isError !== true;
  } finally {
    await local.close();
  }
}

/** The delegation `issuer` signs to `agent` for `kyaos`. */
const delegationFor = (kyaos: KyaOsMiddleware, issuer: Party, agent: Party) =>
  delegate(issuer, agent.did, { audience: kyaos.identity.did });

describe('a server that gates no tool on a delegation', () => {
  it('starts with no configuration, proves its tools and warns of no trust root', async () => {
    const warnings = watchWarnings();
    const kyaos = await middleware();
    const local = serveInProcess(kyaos);
    const proved = local.tool('notes.list', kyaos.wrapWithProof('notes.list', released));
    const gated = local.tool('notes.purge', kyaos.withPolicyGate!('notes.purge', released, { scopeMatched: true }));
    expect((await proved(ARGS)).isError).not.toBe(true);
    await gated(ARGS);
    await local.close();
    expect(warnings()).toEqual([]);
  });

  it('starts under withKyaOs, in production too, and warns of no trust root', async () => {
    const warnings = watchWarnings();
    await withKyaOs(new McpServer({ name: 'notes', version: '1.0.0' }), { crypto });
    vi.stubEnv('NODE_ENV', 'production');
    await withKyaOs(new McpServer({ name: 'notes', version: '1.0.0' }), { crypto });
    expect(warnings()).toEqual([]);
  });
});

describe('a server that gates a tool on a delegation, outside development', () => {
  it('refuses to wrap the tool while trustedRootIssuers is unset, naming every fix', async () => {
    const warnings = watchWarnings();
    const kyaos = await middleware();
    expect(() => gate(kyaos, 'orders.place')).toThrow(refusal('orders.place'));
    expect(() => gate(kyaos, 'orders.place')).not.toThrow(TypeError);
    expect(warnings()).toEqual([]);
  });

  it('refuses it under NODE_ENV=production, through withKyaOs as well', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    const identity = await generateIdentity(crypto);
    expect(() => gate(createKyaOsMiddleware({ identity }, crypto))).toThrow(refusal(TOOL));
    const kyaos = await withKyaOs(new McpServer({ name: 'orders', version: '1.0.0' }), { crypto, delegation: {} });
    expect(() => gate(kyaos)).toThrow(refusal(TOOL));
  });

  it('refuses every tool it is asked to wrap, not only the first', async () => {
    const kyaos = await delegating({ allowAnyRootIssuer: false });
    expect(() => gate(kyaos, 'orders.place')).toThrow(refusal('orders.place'));
    expect(() => gate(kyaos, 'orders.cancel')).toThrow(refusal('orders.cancel'));
  });

  it('with trustedRootIssuers set, wraps silently, accepts a chain rooted at a listed DID and refuses a self-issued one', async () => {
    const warnings = watchWarnings();
    const [owner, agent] = [await party(), await party()];
    const kyaos = await delegating({ trustedRootIssuers: [owner.did], allowAnyRootIssuer: false });
    expect(await runs(kyaos, await delegationFor(kyaos, owner, agent))).toBe(true);
    expect(await runs(kyaos, await delegationFor(kyaos, agent, agent))).toBe(false);
    expect(warnings()).toEqual([]);
  });

  it('with an empty trustedRootIssuers, wraps silently and trusts no issuer', async () => {
    const warnings = watchWarnings();
    const [owner, agent] = [await party(), await party()];
    const kyaos = await delegating({ trustedRootIssuers: [] });
    expect(await runs(kyaos, await delegationFor(kyaos, owner, agent))).toBe(false);
    expect(warnings()).toEqual([]);
  });
});

describe('delegation.allowAnyRootIssuer: true', () => {
  it('starts, in production too, accepts any issuer and warns once, when the first tool is wrapped', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    const warnings = watchWarnings();
    const agent = await party();
    const kyaos = await delegating({ allowAnyRootIssuer: true });
    expect(warnings()).toEqual([]);
    gate(kyaos, 'orders.cancel');
    expect(await runs(kyaos, await delegationFor(kyaos, agent, agent))).toBe(true);
    expect(warnings()).toEqual([
      '[kya-os] delegation.trustedRootIssuers is not set, so a delegation from any issuer is accepted, including ' +
        'one an agent signs for itself, because delegation.allowAnyRootIssuer is true. Set ' +
        'delegation.trustedRootIssuers to the DIDs allowed to grant authority.',
    ]);
  });

  it('warns once for each middleware', async () => {
    const warnings = watchWarnings();
    for (const kyaos of [await delegating({ allowAnyRootIssuer: true }), await delegating({ allowAnyRootIssuer: true })]) {
      gate(kyaos, 'orders.place');
      gate(kyaos, 'orders.cancel');
    }
    expect(warnings()).toHaveLength(2);
  });

  it('is refused beside trustedRootIssuers, an empty list included, when the middleware is created', async () => {
    const owner = await party();
    for (const trustedRootIssuers of [[owner.did], []]) {
      await expect(delegating({ allowAnyRootIssuer: true, trustedRootIssuers })).rejects.toThrow(
        new TypeError(
          '[kya-os] delegation.allowAnyRootIssuer is true and delegation.trustedRootIssuers is set, and they ' +
            'contradict each other: the list names the only issuers to trust, and allowAnyRootIssuer trusts every ' +
            'issuer. Set one or the other.',
        ),
      );
    }
  });

  it('is refused when it is not a boolean, when the middleware is created, through withKyaOs as well', async () => {
    const got = new Map<unknown, string>([['true', 'a value "true"'], [1, 'a value of type number'], [null, 'a value of type null']]);
    for (const [value, described] of got) {
      const delegation = { allowAnyRootIssuer: value } as unknown as KyaOsDelegationConfig;
      const error = new TypeError(`[kya-os] delegation.allowAnyRootIssuer must be true or false (got ${described})`);
      await expect(delegating(delegation)).rejects.toThrow(error);
      await expect(withKyaOs(new McpServer({ name: 'orders', version: '1.0.0' }), { crypto, delegation })).rejects.toThrow(error);
    }
  });

  it('is refused for a trustedRootIssuers that is not a list before it is compared with one', async () => {
    const delegation = { allowAnyRootIssuer: true, trustedRootIssuers: null } as unknown as KyaOsDelegationConfig;
    await expect(delegating(delegation)).rejects.toThrow(/^\[kya-os\] delegation\.trustedRootIssuers must be an array of DIDs/);
  });
});

describe('development: true, with neither setting', () => {
  it('starts, accepts any issuer and warns once, when the first tool is wrapped', async () => {
    const warnings = watchWarnings();
    const agent = await party();
    const kyaos = await middleware({ development: true });
    expect(warnings()).toEqual([]);
    gate(kyaos, 'orders.cancel');
    expect(await runs(kyaos, await delegationFor(kyaos, agent, agent))).toBe(true);
    expect(warnings()).toEqual([
      '[kya-os] delegation.trustedRootIssuers is not set, so a delegation from any issuer is accepted, including ' +
        'one an agent signs for itself, because development is true; outside development, wrapWithDelegation ' +
        'throws without it. Set delegation.trustedRootIssuers to the DIDs allowed to grant authority.',
    ]);
  });

  it('starts through withKyaOs, and warns once for the opt-out beside it', async () => {
    const warnings = watchWarnings();
    const kyaos = await withKyaOs(new McpServer({ name: 'orders', version: '1.0.0' }), {
      crypto,
      development: true,
      delegation: { allowAnyRootIssuer: true },
    });
    gate(kyaos, 'orders.place');
    gate(kyaos, 'orders.cancel');
    expect(warnings()).toHaveLength(1);
    expect(warnings()[0]).toContain('because delegation.allowAnyRootIssuer is true');
  });
});
