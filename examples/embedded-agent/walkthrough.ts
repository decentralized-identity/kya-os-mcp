#!/usr/bin/env npx tsx
/**
 * The EMBEDDED model — an agent that holds its OWN key and signs its OWN
 * holder-of-key proofs IN-PROCESS, talking directly to a KYA-OS server. No proxy.
 *
 * This is the counterpart to a proxy adapter (e.g. kya-os-inspector, for clients
 * you cannot modify): here the agent *is* the holder-of-key. It imports
 * `@kya-os/mcp`, mints a fresh `_kyaos_proof` per call via `generateRequestProof`,
 * and runs the full no-paste loop against a server that is a DISTINCT party:
 *
 *     call → needs_authorization → approve once → retry → success
 *
 * Runs as a NARRATED walkthrough by default — it shows the real `_kyaos_proof`,
 * a fresh nonce per call, the server's challenge, and the no-paste retry. Pass
 * `--quiet` (or `QUIET=1`) for the terse PASS/FAIL form suitable for CI.
 *
 * Headless + deterministic: prints PASS/FAIL per check, exits 0 on success, 1 on
 * failure.
 *
 * Run: npx tsx examples/embedded-agent/walkthrough.ts          # narrated
 *      npx tsx examples/embedded-agent/walkthrough.ts --quiet   # terse (CI)
 */

import {
  createKyaOsMiddleware,
  NodeCryptoProvider,
  generateDidKeyFromBase64,
  generateRequestProof,
  MemoryGrantStore,
  DelegationCredentialIssuer,
  base64urlEncodeFromBytes,
  logger,
  type Grant,
  type DetachedProof,
  type Proof,
  type VCSigningFunction,
} from '@kya-os/mcp';

const SCOPE = 'cart:write';
const TOOL = 'checkout';

/** Narrated by default; `--quiet` / `QUIET=1` prints only PASS/FAIL + the verdict (CI form). */
const QUIET = process.argv.includes('--quiet') || process.env['QUIET'] === '1';

// Quiet the package's own startup notices (e.g. the in-memory nonce-cache warning) —
// this walkthrough narrates its own story; real errors still surface.
logger.configure({ level: 'error' });

interface Identity {
  did: string;
  kid: string;
  privateKey: string;
  publicKey: string;
}

// ── output ────────────────────────────────────────────────────────────────────
let failed = false;
/** A verified assertion — always printed (this is the CI signal + the exit code). */
function check(label: string, ok: boolean): void {
  process.stdout.write(`${ok ? 'PASS' : 'FAIL'}  ${label}\n`);
  if (!ok) failed = true;
}
/** Narration — suppressed under `--quiet` so the terse CI form stays grep-clean. */
function say(line = ''): void {
  if (!QUIET) process.stdout.write(`${line}\n`);
}
function indent(text: string, n = 2): string {
  const pad = ' '.repeat(n);
  return text
    .split('\n')
    .map((l) => (l.length ? pad + l : l))
    .join('\n');
}
function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…(${s.length} chars)` : s;
}

/**
 * Show the REAL DetachedProof the agent just minted — the compact JWS (truncated
 * for the eye) plus its full signed `meta`. The fields that carry the security:
 * `nonce` (fresh CSPRNG per call → replay-safe), `requestHash` (binds the args →
 * tamper-evident), and `audience` (the server it is addressed to).
 */
function showProof(proof: DetachedProof): void {
  const m = proof.meta;
  const on = process.stdout.isTTY === true && !process.env['NO_COLOR'];
  const paint = (code: string, str: string): string => (on ? `\x1b[${code}m${str}\x1b[0m` : str);
  const dim = (str: string): string => paint('2', str);
  const cyan = (str: string): string => paint('36', str);
  const green = (str: string): string => paint('32', str);
  const s = (v: string, h = 12, t = 6): string => (v.length > h + t + 1 ? `${v.slice(0, h)}…${v.slice(-t)}` : v);
  const row = (label: string, value: string, tag: string): string =>
    `${dim(label.padEnd(9))}${cyan(value.padEnd(24))}${dim(tag)}`;
  say(indent(dim('proof the agent signed — a UI client cannot forge this:'), 2));
  say(indent(row('call', `${TOOL} {item:"laptop"}`, ''), 4));
  say(indent(row('hash', s(m.requestHash, 16, 6), 'the exact args'), 4));
  say(indent(row('nonce', s(m.nonce, 16, 4), 'single-use'), 4));
  say(indent(row('audience', s(m.audience), 'this server only'), 4));
  say(indent(row('key', s(m.did), "the agent's own key"), 4));
  say(indent(row('sig', s(proof.jws, 14, 8), 'detached JWS'), 4));
  say(indent(green('→ server recomputes the hash and verifies the signature'), 2));
}

type ToolResult = { content: Array<{ text: string }>; isError?: boolean };
const textOf = (r: ToolResult): string => r.content[0]?.text ?? '';
const isChallenge = (r: ToolResult): boolean => textOf(r).includes('Authorization required');
const isConfirmed = (r: ToolResult): boolean => !r.isError && textOf(r).includes('Order confirmed');

/** Generate a fresh did:key identity (an agent — or a server — controls its own key). */
async function newIdentity(): Promise<Identity> {
  const crypto = new NodeCryptoProvider();
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  return {
    did,
    kid: `${did}#${did.replace('did:key:', '')}`,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
  };
}

/**
 * The embedded move: the agent mints its OWN per-request holder-of-key proof,
 * in-process, addressed to the server's DID. This is the one thing a KYA-OS agent
 * does that a generic client cannot — and it needs no proxy.
 */
async function mintProof(
  agent: Identity,
  serverDid: string,
  args: Record<string, unknown>,
): Promise<DetachedProof> {
  return generateRequestProof({
    identity: agent,
    crypto: new NodeCryptoProvider(),
    toolName: TOOL,
    args,
    audience: serverDid, // who the call is addressed to (a DISTINCT party from the agent)
    sessionId: 'kyaos_agent_local', // structural only — holder-of-key needs no server session
  });
}

/** A minimal holder-of-key KYA-OS server with a single protected `checkout` tool. */
function createServer(server: Identity, grantStore: MemoryGrantStore): {
  checkout: (args: Record<string, unknown>) => Promise<ToolResult>;
} {
  const middleware = createKyaOsMiddleware(
    {
      identity: server,
      session: { sessionTtlMinutes: 60 },
      grantStore,
      delegation: { holderBinding: 'enforce' }, // require a per-request holder-of-key proof
      emitLegacyProofKey: false,
    },
    new NodeCryptoProvider(),
  );

  const checkout = middleware.wrapWithDelegation(
    TOOL,
    {
      scopeId: SCOPE,
      consentUrl: 'http://consent.local/consent',
      formatChallenge: (challenge) => [
        {
          type: 'text' as const,
          text: `Authorization required.\n\n[Authorize checkout](http://consent.local/consent?resume_token=${challenge.resumeToken})\n\nRetry after authorizing — no re-paste needed.`,
        },
      ],
    },
    middleware.wrapWithProof(TOOL, async (args) => ({
      content: [{ type: 'text' as const, text: `Order confirmed for item: ${args['item'] ?? 'unknown'}.` }],
    })),
  );

  return { checkout: checkout as (args: Record<string, unknown>) => Promise<ToolResult> };
}

/** Approve once: mint the delegation VC and bind an agent-anchored grant. */
async function approve(server: Identity, agentDid: string, grantStore: MemoryGrantStore): Promise<void> {
  const crypto = new NodeCryptoProvider();
  const sign: VCSigningFunction = async (canonicalVC, _issuerDid, kid): Promise<Proof> => {
    const sig = await crypto.sign(new TextEncoder().encode(canonicalVC), server.privateKey);
    return {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: kid,
      proofPurpose: 'assertionMethod',
      proofValue: base64urlEncodeFromBytes(sig),
    };
  };
  const issuer = new DelegationCredentialIssuer(
    { getDid: () => server.did, getKeyId: () => server.kid, getPrivateKey: () => server.privateKey },
    sign,
  );
  const notAfter = Math.floor(Date.now() / 1000) + 3600;
  await issuer.createAndIssueDelegation({
    id: `del-${Date.now()}`,
    issuerDid: server.did,
    subjectDid: agentDid,
    constraints: { scopes: [SCOPE], notAfter },
  });

  // Agent-anchored grant (no sessionId) — resolved per request via getByAgent
  // behind the agent's holder-of-key proof.
  const grant: Grant = {
    id: `grant_${Date.now()}`,
    agentDid,
    scopes: [SCOPE],
    authorization: { type: 'delegation', provider: 'embedded-agent' },
    issuedAt: Date.now(),
    expiresAt: notAfter * 1000,
    status: 'active',
  };
  await grantStore.bind(grant);
}

async function main(): Promise<void> {
  const agent = await newIdentity(); // the agent owns its key
  const server = await newIdentity(); // the server is a DISTINCT party
  const grantStore = new MemoryGrantStore();
  const { checkout } = createServer(server, grantStore);

  say('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  say('KYA-OS · Embedded Agent — holder-of-key, in-process (no proxy)');
  say('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  say('Two DISTINCT parties — neither can act as the other:');
  say(`  agent  : ${agent.did}`);
  say(`  server : ${server.did}   (holderBinding: 'enforce')`);
  say('');

  // 1. The agent signs its own proof in-process and calls — no grant yet → challenge.
  say('── Step 1 · The agent signs its OWN call, in-process ──────────────');
  say(`It mints a holder-of-key proof for ${TOOL}({ item: 'laptop' }) and attaches it as _kyaos_proof:`);
  const proof1 = await mintProof(agent, server.did, { item: 'laptop' });
  showProof(proof1);
  const first = await checkout({ item: 'laptop', _kyaos_proof: proof1 });
  say('  server replies:');
  say(indent(textOf(first), 4));
  say('');
  check('first call (agent-signed proof, no grant) → needs_authorization', isChallenge(first));

  // 2. Approve once — binds an agent-anchored grant.
  say('\n── Step 2 · Approve once (one-time) ───────────────────────────────');
  say(`A delegation VC is issued (server → agent, scope '${SCOPE}') and an agent-anchored grant is bound.`);
  say('Nothing is handed back to the agent — no token, no session to re-paste.');
  await approve(server, agent.did, grantStore);
  say('  ✓ grant bound to the agent DID');
  say('');

  // 3. Retry with a FRESH in-process proof → success. No re-paste, no session.
  say('── Step 3 · Retry with a FRESH proof → success ────────────────────');
  const proof2 = await mintProof(agent, server.did, { item: 'laptop' });
  say('Same agent, brand-new proof. The nonce differs from Step 1 — each call is independently replay-safe:');
  say(`  Step 1 nonce: ${proof1.meta.nonce}`);
  say(`  Step 3 nonce: ${proof2.meta.nonce}  ${proof1.meta.nonce !== proof2.meta.nonce ? '← different ✓' : '← SAME ✗'}`);
  const retry = await checkout({ item: 'laptop', _kyaos_proof: proof2 });
  say('  server replies:');
  say(indent(textOf(retry), 4));
  say('');
  check('each call uses a fresh nonce (replay-safe)', proof1.meta.nonce !== proof2.meta.nonce);
  check('retry (fresh agent-signed proof) resolves the grant → success, no re-paste', isConfirmed(retry));

  // 4. Confused-deputy guard: a call WITHOUT a proof cannot resolve the agent grant.
  say('\n── Step 4 · Confused-deputy guard ─────────────────────────────────');
  say('A call with NO proof cannot inherit the agent grant:');
  const noProof = await checkout({ item: 'laptop' });
  say('  server replies:');
  say(indent(textOf(noProof), 4));
  say('');
  check('a call WITHOUT a holder-of-key proof is NOT auto-authorized', isChallenge(noProof));

  process.stdout.write(
    failed
      ? '\n✗ EMBEDDED-AGENT DEMO FAILED\n'
      : '\n✓ EMBEDDED-AGENT DEMO PASSED — the agent signed every call itself, in-process.\n' +
          '  No proxy sat in the middle and no credential was re-pasted: the agent proved possession\n' +
          '  of its key on each call, so the approved grant resolved automatically on retry, while a\n' +
          '  call carrying no proof was refused.\n',
  );
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  process.stderr.write(`Error: ${err}\n`);
  process.exit(1);
});
