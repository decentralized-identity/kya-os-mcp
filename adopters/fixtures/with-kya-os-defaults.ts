/**
 * An adopter adds KYA-OS to an MCP server with `withKyaOs` and its defaults, pins the one root it
 * trusts, and calls a delegated tool in process through `serveInProcess`, as a script or a test
 * does. Every party is a did:key, so nothing is read over a network. A root it does not trust is
 * refused with the error code a client sees, `delegation_invalid`, while the operator's log line
 * says why in a code: `untrusted_root`. `KyaOsConfig` takes `development: true`, and refuses it at
 * startup in production.
 */
import assert from 'node:assert/strict';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  createKyaOsMiddleware,
  generateIdentity,
  serveInProcess,
  withKyaOs,
  type DelegationCredential,
  type KyaOsConfig,
} from '@kya-os/mcp';
import { runCases } from './shared/cases.js';
import { issueDelegation } from './shared/credentials.js';
import { crypto, didKeyParty, type Party } from './shared/keys.js';
import { buildInProduction, isProductionChild, reportProductionBuild } from './shared/production.js';

const TOOL = 'notes.read';
const SCOPE = 'notes:read';

/**
 * What `work` comes to, and the lines it writes to the console as warnings and errors, where the
 * library's default logger writes the lines an operator reads.
 */
async function withOperatorLines<T>(work: () => Promise<T>): Promise<{ value: T; lines: unknown[][] }> {
  const lines: unknown[][] = [];
  const { warn, error } = console;
  console.warn = (...line: unknown[]) => void lines.push(line);
  console.error = (...line: unknown[]) => void lines.push(line);
  try {
    return { value: await work(), lines };
  } finally {
    console.warn = warn;
    console.error = error;
  }
}

/** The middleware configuration a developer runs locally: the defaults, and `development: true`. */
const developmentConfig = async (): Promise<KyaOsConfig> => ({ identity: await generateIdentity(crypto), development: true });

if (isProductionChild()) {
  const config = await developmentConfig();
  await reportProductionBuild(() => createKyaOsMiddleware(config, crypto));
} else {
  const owner = await didKeyParty();
  const stranger = await didKeyParty();
  const agent = await didKeyParty();
  const worker = await didKeyParty();
  /** Each root's credential, by the delegation id a re-delegation names as its parent. */
  const ancestorsByParent = new Map<string, DelegationCredential[]>();

  const server = new McpServer({ name: 'notes', version: '1.0.0' });
  const kyaos = await withKyaOs(server, {
    crypto,
    delegation: {
      trustedRootIssuers: [owner.did],
      resolveDelegationChain: async (leaf) => ancestorsByParent.get(leaf.credentialSubject.delegation.parentId ?? '') ?? [],
    },
  });

  /**
   * A chain from `root` through the agent to the worker, for this server, whose DID `withKyaOs`
   * generated: the root's credential, kept for the chain resolver, and the leaf the worker presents.
   */
  const chainFrom = async (root: Party, rootId: string): Promise<DelegationCredential> => {
    const terms = { scopes: [SCOPE], audience: kyaos.identity.did };
    const rootCredential = await issueDelegation(root, { ...terms, id: rootId, subjectDid: agent.did });
    ancestorsByParent.set(rootId, [rootCredential]);
    return issueDelegation(agent, { ...terms, id: `${rootId}:worker`, subjectDid: worker.did, parentId: rootId });
  };
  const ownerLeaf = await chainFrom(owner, 'owner-to-agent');
  const strangerLeaf = await chainFrom(stranger, 'stranger-to-agent');
  const local = serveInProcess(kyaos);
  const readNote = local.tool(
    TOOL,
    kyaos.wrapWithDelegation(TOOL, { scopeId: SCOPE, consentUrl: 'https://notes.example/consent' }, async (args) => ({
      content: [{ type: 'text', text: `note ${String(args['id'])}` }],
    })),
  );

  await runCases('with-kya-os-defaults', 'withKyaOs with its defaults allows a call under the pinned root, refuses another root and logs why in a code, and takes development: true', [
    {
      name: 'a delegated call under the pinned root is allowed',
      run: async () => {
        const result = await readNote({ id: '7', _kyaos_delegation: ownerLeaf });
        assert.notEqual(result.isError, true, `refused: ${result.content[0]?.text}`);
        assert.equal(result.content[0]?.text, 'note 7');
      },
    },
    {
      name: 'a call whose root is not trusted is refused as delegation_invalid, and logged as untrusted_root',
      run: async () => {
        const { value: result, lines } = await withOperatorLines(() => readNote({ id: '7', _kyaos_delegation: strangerLeaf }));
        assert.equal(result.isError, true, 'the call under an untrusted root was allowed');
        const refusal = JSON.parse(result.content[0]?.text ?? '{}') as Record<string, unknown>;
        assert.equal(refusal.error, 'delegation_invalid', String(refusal.reason));
        assert.deepEqual(Object.keys(refusal).sort(), ['error', 'reason'], 'the client was told more than before');
        const logged = lines.find(([text]) => String(text).startsWith('[kya-os] Delegation verification failed'));
        assert.ok(logged, `no refusal was logged: ${JSON.stringify(lines)}`);
        assert.deepEqual(logged[1], { code: 'untrusted_root', transient: false }, String(logged[0]));
      },
    },
    {
      name: 'KyaOsConfig takes development: true outside production',
      run: async () => {
        createKyaOsMiddleware(await developmentConfig(), crypto);
      },
    },
    {
      name: 'under NODE_ENV=production, development: true throws at startup',
      run: () => {
        const build = buildInProduction(import.meta.url);
        assert.equal(build.threw, true, 'the middleware started with development: true in production');
        assert.match(build.message, /development/);
      },
    },
  ]);
}
