/**
 * An adopter gates a tool on a delegation with `withKyaOs` and `wrapWithDelegation`, and learns at
 * startup whose authority the server must name. A server with no delegated tool needs no setting.
 * One that gates a tool throws, outside development, until `delegation.trustedRootIssuers` names
 * the DIDs allowed to grant authority, and the error names every fix; `development: true` and
 * `delegation.allowAnyRootIssuer: true` start it with one warning. Every party is a did:key, so
 * nothing is read over a network, and the warnings are read where an adopter sees them, on the
 * console.
 */
import assert from 'node:assert/strict';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { serveInProcess, withKyaOs, type DelegationCredential, type KyaOsMiddleware, type WithKyaOsOptions } from '@kya-os/mcp';
import { runCases } from './shared/cases.js';
import { issueDelegation } from './shared/credentials.js';
import { crypto, didKeyParty, type Party } from './shared/keys.js';
import { buildInProduction, isProductionChild, reportProductionBuild } from './shared/production.js';

const TOOL = 'orders.place';
const SCOPE = 'orders:place';
const CONSENT = { scopeId: SCOPE, consentUrl: 'https://orders.example/consent' };

/** A `withKyaOs` server with `options`, beside the crypto every fixture uses. */
const serverWith = (options: Omit<WithKyaOsOptions, 'crypto'> = {}): Promise<KyaOsMiddleware> =>
  withKyaOs(new McpServer({ name: 'orders', version: '1.0.0' }), { crypto, ...options });

/** `kyaos` with {@link TOOL} gated on a delegation, as a server sets its tools up. */
const gateTool = (kyaos: KyaOsMiddleware) =>
  kyaos.wrapWithDelegation(TOOL, CONSENT, async () => ({ content: [{ type: 'text', text: 'placed' }] }));

/** Run `work`, and return what it returned with the console warnings about trust roots it caused. */
async function watchingWarnings<T>(work: () => Promise<T>): Promise<{ value: T; warnings: string[] }> {
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => {
    const text = args.map(String).join(' ');
    if (text.includes('trustedRootIssuers')) warnings.push(text);
  };
  try {
    return { value: await work(), warnings };
  } finally {
    console.warn = original;
  }
}

/** Whether the gated tool of a server set up with `options` runs for a caller presenting `delegation(server)`. */
async function runsFor(
  options: Omit<WithKyaOsOptions, 'crypto'>,
  delegation: (kyaos: KyaOsMiddleware) => Promise<DelegationCredential>,
): Promise<{ ran: boolean; warnings: string[] }> {
  const { value: ran, warnings } = await watchingWarnings(async () => {
    const kyaos = await serverWith(options);
    const local = serveInProcess(kyaos);
    try {
      const placeOrder = local.tool(TOOL, gateTool(kyaos));
      // A second delegated tool, as a server gates each of its tools: the warning still comes once.
      gateTool(kyaos);
      const result = await placeOrder({ item: 'book', _kyaos_delegation: await delegation(kyaos) });
      return result.isError !== true;
    } finally {
      await local.close();
    }
  });
  return { ran, warnings };
}

/** A delegation of {@link SCOPE} that `issuer` signs to `agent` for `kyaos`. */
const delegationFrom = (issuer: Party, agent: Party) => (kyaos: KyaOsMiddleware) =>
  issueDelegation(issuer, { id: `${issuer.did}:orders`, subjectDid: agent.did, scopes: [SCOPE], audience: kyaos.identity.did });

if (isProductionChild()) {
  await reportProductionBuild(async () => gateTool(await serverWith()));
} else {
  const owner = await didKeyParty();
  const agent = await didKeyParty();
  const selfIssued = delegationFrom(agent, agent);

  await runCases('trusted-root-issuers', 'a delegated tool needs trustedRootIssuers outside development, every fix is named, and each opt-out warns once', [
    {
      name: 'a server with no delegated tool starts with no configuration and logs no trust-root warning',
      run: async () => {
        const { warnings } = await watchingWarnings(async () => {
          const kyaos = await serverWith();
          const local = serveInProcess(kyaos);
          const listOrders = local.tool('orders.list', kyaos.wrapWithProof('orders.list', async () => ({ content: [{ type: 'text', text: 'none' }] })));
          assert.notEqual((await listOrders({})).isError, true);
          await local.close();
        });
        assert.deepEqual(warnings, []);
      },
    },
    {
      name: 'under NODE_ENV=production, wrapping a tool with no setting throws, naming trustedRootIssuers, development: true and allowAnyRootIssuer',
      run: () => {
        const build = buildInProduction(import.meta.url);
        assert.equal(build.threw, true, 'the server wrapped a delegated tool with no trusted root issuers in production');
        for (const fix of ['delegation.trustedRootIssuers', 'development: true', 'delegation.allowAnyRootIssuer: true']) {
          assert.ok(build.message.includes(fix), `the error does not name ${fix}: ${build.message}`);
        }
      },
    },
    {
      name: 'without NODE_ENV=production, outside development, it throws the same',
      run: async () => {
        const kyaos = await serverWith();
        assert.throws(() => gateTool(kyaos), /delegation\.trustedRootIssuers is not set/);
      },
    },
    {
      name: 'development: true starts, accepts any issuer and warns once',
      run: async () => {
        const { ran, warnings } = await runsFor({ development: true }, selfIssued);
        assert.equal(ran, true, 'a self-issued delegation was refused in development');
        assert.equal(warnings.length, 1, warnings.join('\n'));
      },
    },
    {
      name: 'allowAnyRootIssuer: true starts, accepts any issuer and warns once',
      run: async () => {
        const { ran, warnings } = await runsFor({ delegation: { allowAnyRootIssuer: true } }, selfIssued);
        assert.equal(ran, true, 'a self-issued delegation was refused with allowAnyRootIssuer: true');
        assert.equal(warnings.length, 1, warnings.join('\n'));
        assert.match(warnings[0] ?? '', /allowAnyRootIssuer is true/);
      },
    },
    {
      name: 'trustedRootIssuers set starts silently, accepts a chain rooted at a listed DID and refuses a self-issued one',
      run: async () => {
        const trusted = { delegation: { trustedRootIssuers: [owner.did] } };
        const listed = await runsFor(trusted, delegationFrom(owner, agent));
        assert.equal(listed.ran, true, 'a delegation from the listed root was refused');
        const self = await runsFor(trusted, selfIssued);
        assert.equal(self.ran, false, 'a self-issued delegation was accepted');
        assert.deepEqual([...listed.warnings, ...self.warnings], []);
      },
    },
    {
      name: 'allowAnyRootIssuer: true beside trustedRootIssuers is refused at startup',
      run: async () => {
        await assert.rejects(serverWith({ delegation: { allowAnyRootIssuer: true, trustedRootIssuers: [owner.did] } }), TypeError);
      },
    },
  ]);
}
