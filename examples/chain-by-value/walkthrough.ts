#!/usr/bin/env npx tsx
/**
 * KYA-OS: carry the delegation chain with the request (SPEC-ENTITY-CARD §10.5).
 *
 * Acme delegates `orders.place` to its procurement agent, which re-delegates a narrower slice to
 * a checkout worker. The worker calls a merchant's MCP server. The merchant is a different
 * organization: it knows Acme's DID, but it has no account on Acme's delegation registry and no
 * business querying it. The walkthrough runs five calls against the merchant:
 *
 *   1. By reference: the worker sends only its request proof. The merchant has to ask Acme's
 *      registry for the chain, the registry refuses, and the call fails `delegation_unresolvable`.
 *   2. By value: the worker sends the chain in `_meta['org.kya-os/delegation-chain']`. The merchant
 *      checks every hop's signature against the delegator's own DID and recomputes the
 *      Responsible Party (Acme) from the root. Accepted.
 *   3. The worker raises its own limit after signing. The new value still sits inside Acme's, so
 *      attenuation passes; the agent's signature does not, and the call fails.
 *   4. Another agent replays the worker's chain under its own, valid request proof. The leaf
 *      names the worker's key, not this one, and the call fails.
 *   5. Acme revokes the root hop in its public Bitstring Status List. The carried chain is byte for
 *      byte the one accepted in step 2, and the call fails `delegation_revoked`: carrying the chain
 *      does not freeze it.
 *
 * Every key is a real Ed25519 did:key, every hop and the status list are signed with
 * `eddsa-jcs-2022` through the SDK, and the merchant runs the shipped `requireProof` and
 * `requireDelegation` guards. Only the network is in memory: the merchant can reach Acme's status
 * list, as anyone can, and nothing else at Acme.
 *
 * Run: npm run example:chain-by-value   (or: npx tsx examples/chain-by-value/walkthrough.ts)
 */

import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { exportJWK, generateKeyPair } from 'jose';
import {
  buildCardProof,
  createDelegationProofVerifier,
  createRevocationChecker,
  createStatusListProofVerifier,
  DELEGATION_CONTEXT_V2,
  ed25519SignerFromJwk,
  InMemoryNonceCache,
  KYA_OS_DELEGATION_CONTEXT,
  requireDelegation,
  requireProof,
  signDelegationCredential,
  signStatusListCredential,
  toDelegationChainMeta,
  ZCAP_CONTEXT,
  type DelegationChain,
  type DelegationCredential,
  type Ed25519PrivateJwk,
  type ProofSigner,
  type SafeFetch,
  type UnsignedDelegationCredential,
} from '../../src/card/index.js';
import { createDidKeyResolver, verificationMethodJwk } from '../../src/delegation/index.js';
import { generateDidKeyFromBytes } from '../../src/utils/did-helpers.js';
import { base64urlDecodeToBytes } from '../../src/utils/base64.js';

/** The merchant's MCP server: the resource every hop targets and the audience of every proof. */
export const MERCHANT_DID = 'did:web:merchant.example';
/** Acme's delegation registry. Private to Acme, so the merchant cannot read it. */
export const ACME_REGISTRY_URL = 'https://registry.acme.example/delegations';
/** Acme's revocation list. Public by design: a Bitstring Status List reveals nothing per holder. */
export const ACME_STATUS_URL = 'https://acme.example/status/1';

const ROOT_STATUS_INDEX = 3;
const LEAF_STATUS_INDEX = 7;
const VALID_UNTIL = '2027-01-01T00:00:00Z';
const PLACE_ORDER = { method: 'tools/call', params: { name: 'orders.place', arguments: { sku: 'A-100', qty: 2 } } };

// ── Parties ──────────────────────────────────────────────────────────────────

/** A party with its own Ed25519 did:key and a signer for it. */
export interface Party {
  name: string;
  did: string;
  signer: ProofSigner;
}

async function party(name: string): Promise<Party> {
  const { privateKey } = await generateKeyPair('EdDSA', { extractable: true });
  const jwk = (await exportJWK(privateKey)) as Ed25519PrivateJwk;
  const did = generateDidKeyFromBytes(base64urlDecodeToBytes(jwk.x));
  const kid = `${did}#${did.slice('did:key:'.length)}`;
  return { name, did, signer: await ed25519SignerFromJwk({ did, kid, privateJwk: jwk }) };
}

// ── Acme: mint the root, publish revocation ──────────────────────────────────

function unsignedHop(opts: {
  issuer: Party;
  invoker: Party;
  id: string;
  parentCapability: string;
  allowedAction: string[];
  maxAmount: string;
  statusIndex: number;
}): UnsignedDelegationCredential {
  return {
    '@context': [DELEGATION_CONTEXT_V2, ZCAP_CONTEXT, KYA_OS_DELEGATION_CONTEXT],
    type: ['VerifiableCredential', 'DelegationCredential'],
    issuer: opts.issuer.did,
    validUntil: VALID_UNTIL,
    credentialSubject: {
      id: opts.id,
      invoker: opts.invoker.did,
      parentCapability: opts.parentCapability,
      invocationTarget: MERCHANT_DID,
      allowedAction: opts.allowedAction,
      caveats: [{ type: 'MaxAmount', limit: opts.maxAmount, currency: 'USD' }],
    },
    credentialStatus: {
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(opts.statusIndex),
      statusListCredential: ACME_STATUS_URL,
    },
  };
}

/** Acme's signed Bitstring Status List with `revoked` indices set (16 KiB, MSB-first). */
async function acmeStatusList(acme: Party, revoked: number[]): Promise<Record<string, unknown>> {
  const bits = new Uint8Array(16 * 1024);
  for (const i of revoked) bits[i >>> 3] = (bits[i >>> 3] ?? 0) | (0x80 >> (i & 7));
  return signStatusListCredential(
    {
      '@context': [DELEGATION_CONTEXT_V2],
      id: ACME_STATUS_URL,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: acme.did,
      validFrom: '2026-01-01T00:00:00Z',
      credentialSubject: {
        id: `${ACME_STATUS_URL}#list`,
        type: 'BitstringStatusList',
        statusPurpose: 'revocation',
        encodedList: `u${gzipSync(bits).toString('base64url')}`,
      },
    },
    acme.signer,
  );
}

// ── The merchant: requireProof, then requireDelegation ───────────────────────

/** What the merchant answers: the grant on success, the guard's code and first reason otherwise. */
export type MerchantAnswer =
  | { status: 200; responsibleParty: string; caller: string; source: 'carried' | 'resolved'; depth: number; fresh: boolean }
  | { status: 401 | 403; code: string; reason: string | undefined };

/** The merchant's network: Acme's public status list is reachable; Acme's registry refuses it. */
function merchantNetwork(statusList: () => Record<string, unknown>): SafeFetch {
  return async (url) => {
    if (url === ACME_STATUS_URL) return { ok: true, status: 200, json: () => Promise.resolve(statusList()) };
    return { ok: false, status: url.startsWith(ACME_REGISTRY_URL) ? 403 : 404, json: () => Promise.resolve({}) };
  };
}

/** Build the merchant's handler for `orders.place`. */
export function merchant(opts: { trustedCustomers: string[]; fetch: SafeFetch }) {
  const didResolver = createDidKeyResolver();
  const publishedKeys = async (did: string) => {
    const document = await didResolver.resolve(did);
    return (document?.verificationMethod ?? []).flatMap((method) => {
      const jwk = verificationMethodJwk(method);
      return jwk?.kty === 'OKP' && jwk.crv === 'Ed25519' ? [{ id: method.id, jwk: { kty: 'OKP' as const, crv: 'Ed25519' as const, x: jwk.x } }] : [];
    });
  };

  const proofGuard = requireProof({
    resolveKey: async (kid) => {
      const key = (await publishedKeys(kid.split('#')[0] ?? '')).find((k) => k.id === kid);
      if (!key) throw new Error(`no key ${kid}`);
      return { ...key.jwk, kid };
    },
    resolveDidKeys: async (did) => (await publishedKeys(did)).map((k) => k.jwk),
    expectedAudience: MERCHANT_DID,
    consumeNonceIfFresh: new InMemoryNonceCache().consume,
  });

  const delegationGuard = requireDelegation({
    resource: MERCHANT_DID,
    trustedRootIssuers: opts.trustedCustomers,
    verifyHopProof: createDelegationProofVerifier({ didResolver }),
    checkRevocation: createRevocationChecker({
      fetch: opts.fetch,
      verifyStatusList: createStatusListProofVerifier({ didResolver }),
    }),
    // By reference: ask the Responsible Party's registry. Used only when the request carries no chain.
    resolveDelegationChain: async ({ proofDid }) => {
      const response = await opts.fetch(`${ACME_REGISTRY_URL}?invoker=${encodeURIComponent(proofDid)}`);
      if (!response.ok) throw new Error(`registry.acme.example answered ${response.status}`);
      return (await response.json()) as DelegationChain;
    },
  });

  return async function placeOrder(request: typeof PLACE_ORDER, meta: Record<string, unknown>): Promise<MerchantAnswer> {
    const proof = await proofGuard(request, meta);
    if (!proof.ok) return { status: proof.status, code: proof.error.code, reason: proof.error.reasons[0] };
    const authority = await delegationGuard({ meta, proofDid: proof.did, action: request.params.name });
    if (!authority.ok) return { status: authority.status, code: authority.error.code, reason: authority.error.reasons[0] };
    return {
      status: 200,
      responsibleParty: authority.responsibleParty,
      caller: authority.leafInvoker,
      source: authority.source,
      depth: authority.depth,
      fresh: authority.fresh,
    };
  };
}

/** A caller's request proof for `orders.place`, bound to the merchant and a fresh nonce. */
async function proveCall(caller: Party): Promise<Record<string, unknown>> {
  return buildCardProof(PLACE_ORDER, caller.signer, { audience: MERCHANT_DID, nonce: randomBytes(16).toString('base64url') });
}

// ── The five calls ───────────────────────────────────────────────────────────

export interface DemoResult {
  parties: { acme: Party; agent: Party; worker: Party; other: Party };
  chain: [DelegationCredential, DelegationCredential];
  byReference: MerchantAnswer;
  carried: MerchantAnswer;
  tampered: MerchantAnswer;
  replayedByAnother: MerchantAnswer;
  revoked: MerchantAnswer;
}

export async function demoScenario(): Promise<DemoResult> {
  const acme = await party('Acme');
  const agent = await party('Acme procurement agent');
  const worker = await party('checkout worker');
  const other = await party('another agent');

  // Acme delegates to its agent. The agent re-delegates on its own: it signs the leaf with its
  // key and asks no one, because the root already names it as the delegate.
  const root = await signDelegationCredential(
    unsignedHop({
      issuer: acme,
      invoker: agent,
      id: 'urn:zcap:acme:procurement',
      parentCapability: MERCHANT_DID,
      allowedAction: ['orders.place', 'orders.read'],
      maxAmount: '500.00',
      statusIndex: ROOT_STATUS_INDEX,
    }),
    acme.signer,
  );
  const leaf = await signDelegationCredential(
    unsignedHop({
      issuer: agent,
      invoker: worker,
      id: 'urn:zcap:acme:procurement:checkout',
      parentCapability: root.credentialSubject.id,
      allowedAction: ['orders.place'],
      maxAmount: '100.00',
      statusIndex: LEAF_STATUS_INDEX,
    }),
    agent.signer,
  );
  const chain: [DelegationCredential, DelegationCredential] = [root, leaf];

  let published = await acmeStatusList(acme, []);
  const placeOrder = merchant({ trustedCustomers: [acme.did], fetch: merchantNetwork(() => published) });

  // 1. By reference: only the request proof travels.
  const byReference = await placeOrder(PLACE_ORDER, await proveCall(worker));

  // 2. By value: the chain travels in the same _meta as the proof.
  const carried = await placeOrder(PLACE_ORDER, { ...(await proveCall(worker)), ...toDelegationChainMeta(chain) });

  // 3. The worker edits its own hop: 100 becomes 400, still inside Acme's 500.
  const raised = {
    ...leaf,
    credentialSubject: { ...leaf.credentialSubject, caveats: [{ type: 'MaxAmount', limit: '400.00', currency: 'USD' }] },
  };
  const tampered = await placeOrder(PLACE_ORDER, { ...(await proveCall(worker)), ...toDelegationChainMeta([root, raised]) });

  // 4. Another agent presents the worker's chain with a valid proof of its own.
  const replayedByAnother = await placeOrder(PLACE_ORDER, { ...(await proveCall(other)), ...toDelegationChainMeta(chain) });

  // 5. Acme revokes the root. The worker sends exactly the chain that was accepted in step 2.
  published = await acmeStatusList(acme, [ROOT_STATUS_INDEX]);
  const revoked = await placeOrder(PLACE_ORDER, { ...(await proveCall(worker)), ...toDelegationChainMeta(chain) });

  return { parties: { acme, agent, worker, other }, chain, byReference, carried, tampered, replayedByAnother, revoked };
}

// ── Run it ───────────────────────────────────────────────────────────────────

/** `did:key:z6MkiRHC…SrPj`: enough to tell the parties apart in a terminal. */
const short = (text: string) => text.replace(/(did:key:z6Mk\w{4})\w+(\w{4})/g, '$1…$2');

function describeAnswer(answer: MerchantAnswer, parties: DemoResult['parties']): string {
  if (answer.status !== 200) return `${answer.status} ${answer.code}: ${short(answer.reason ?? '')}`;
  const name = (did: string) => Object.values(parties).find((p) => p.did === did)?.name ?? did;
  return `200 accepted: ${name(answer.caller)} acting for ${name(answer.responsibleParty)}, ${answer.depth} hops, status ${answer.fresh ? 'checked live' : 'not checked'}`;
}

async function main(): Promise<void> {
  const result = await demoScenario();
  const { parties } = result;

  console.log('\nParties');
  for (const p of Object.values(parties)) console.log(`  ${p.name.padEnd(24)} ${short(p.did)}`);
  console.log(`  ${'merchant MCP server'.padEnd(24)} ${MERCHANT_DID}`);

  console.log('\nChain (root to leaf)');
  for (const [i, hop] of result.chain.entries()) {
    const subject = hop.credentialSubject;
    const grant = `${subject.allowedAction.join(', ')}, max ${subject.caveats?.[0]?.limit ?? '-'} USD`;
    console.log(`  hop ${i}  ${subject.id.padEnd(37)} ${grant}`);
  }

  console.log('\nCalls to orders.place');
  const rows: [string, MerchantAnswer][] = [
    ['1. by reference (merchant asks Acme)', result.byReference],
    ['2. chain carried in _meta', result.carried],
    ['3. worker raised its own limit', result.tampered],
    ["4. another agent sends the worker's chain", result.replayedByAnother],
    ['5. Acme revoked the root', result.revoked],
  ];
  for (const [label, answer] of rows) console.log(`  ${label.padEnd(44)} ${describeAnswer(answer, parties)}`);
  console.log('');
}

const invokedDirectly = process.argv[1] !== undefined && process.argv[1] === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
