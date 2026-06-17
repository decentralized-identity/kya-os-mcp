/**
 * Shared identity, durable stores, and the per-instance middleware factory.
 *
 * The whole point of this example: TWO server instances (and the same instance
 * after a restart) share ONE file-backed GrantStore + PendingFlowStore and ONE
 * identity. Each instance builds its own KYA-OS middleware over those shared
 * stores, with NO per-example delegation Map (contrast examples/consent-basic).
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createKyaOsMiddleware,
  NodeCryptoProvider,
  generateDidKeyFromBase64,
  generateRequestProof,
  type KyaOsMiddleware,
  type KyaOsToolHandler,
  type DetachedProof,
} from '@kya-os/mcp';
import { FileGrantStore } from './file-grant-store.js';
import { FilePendingFlowStore } from './file-pending-flow-store.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const IDENTITY_PATH = path.resolve(__dirname, '..', '.kya-os', 'identity.json');

export interface AgentIdentity {
  did: string;
  kid: string;
  privateKey: string;
  publicKey: string;
}

export const SCOPE = 'cart:write';
export const TOOL = 'checkout';

/** Load the persisted identity, or generate an ephemeral one (both instances must share it). */
export async function loadIdentity(): Promise<AgentIdentity> {
  const crypto = new NodeCryptoProvider();
  if (fs.existsSync(IDENTITY_PATH)) {
    return JSON.parse(fs.readFileSync(IDENTITY_PATH, 'utf-8')) as AgentIdentity;
  }
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  return {
    did,
    kid: `${did}#${did.replace('did:key:', '')}`,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
  };
}

export interface SharedStores {
  grantStore: FileGrantStore;
  pendingFlowStore: FilePendingFlowStore;
  dataDir: string;
}

/** Create the file-backed stores under `dataDir` (shared by every instance). */
export function createStores(dataDir: string): SharedStores {
  return {
    grantStore: new FileGrantStore(path.join(dataDir, 'grants.json')),
    pendingFlowStore: new FilePendingFlowStore(path.join(dataDir, 'pending-flows.json')),
    dataDir,
  };
}

export interface Instance {
  label: string;
  middleware: KyaOsMiddleware;
  /** Protected `checkout` handler (requires a cart:write grant). */
  checkout: KyaOsToolHandler;
}

/**
 * Build one server instance over the shared identity + grant store. The
 * `checkout` tool is protected by the package's own wrapWithDelegation — the
 * no-paste retry comes from the injected grantStore (§A.2), not example code.
 */
export function createInstance(opts: {
  label: string;
  identity: AgentIdentity;
  grantStore: FileGrantStore;
  consentUrl: string;
}): Instance {
  const crypto = new NodeCryptoProvider();
  const middleware = createKyaOsMiddleware(
    {
      identity: opts.identity,
      session: { sessionTtlMinutes: 60 },
      grantStore: opts.grantStore,
      // Holder-of-key is the GENUINE cross-instance mechanism: the agent proves
      // possession of its key per request (_kyaos_proof), so a retry resolves an
      // agent-anchored grant via getByAgent with NO shared server session. (This
      // is what makes the "retry on either instance / after a restart, no
      // re-paste" promise actually hold over a stateless HTTP transport.)
      delegation: { holderBinding: 'enforce' },
      // Dev clarity: emit the proof under only the namespaced `org.kya-os/proof`
      // key. The library default mirrors it under legacy bare `proof` for
      // pre-1.1 back-compat; examples keep the Inspector view single-key.
      emitLegacyProofKey: false,
    },
    crypto,
  );

  const checkout = middleware.wrapWithDelegation(
    TOOL,
    {
      scopeId: SCOPE,
      consentUrl: opts.consentUrl,
      formatChallenge: (challenge) => {
        const url = new URL(opts.consentUrl);
        url.searchParams.set('tool', TOOL);
        url.searchParams.set('scopes', challenge.scopes.join(','));
        url.searchParams.set('agent_did', opts.identity.did);
        url.searchParams.set('resume_token', challenge.resumeToken);
        return [
          {
            type: 'text' as const,
            text: `Authorization required.\n\n[Authorize checkout](${url.toString()})\n\nRetry after authorizing — no re-paste needed.`,
          },
        ];
      },
    },
    middleware.wrapWithProof(TOOL, async (args) => ({
      content: [
        {
          type: 'text',
          text: `Order confirmed for item: ${args['item'] ?? 'unknown'}. Thank you! (served by instance ${opts.label})`,
        },
      ],
    })),
  );

  return { label: opts.label, middleware, checkout };
}

/**
 * Mint the per-request holder-of-key proof a KYA-OS agent attaches to a checkout
 * call. The agent signs `toHolderBindingRequest(checkout, args)` with its key;
 * the server re-proves possession per request, so an agent-anchored grant
 * resolves on ANY instance with no shared server session. (Single trust domain
 * here: the server DID and the agent DID are the same shared identity.)
 */
export async function mintCheckoutProof(
  identity: AgentIdentity,
  args: Record<string, unknown>,
): Promise<DetachedProof> {
  return generateRequestProof({
    identity,
    crypto: new NodeCryptoProvider(),
    toolName: TOOL,
    args,
    audience: identity.did,
    sessionId: 'kyaos_agent_local', // structural only — holder-of-key needs no server session
  });
}
