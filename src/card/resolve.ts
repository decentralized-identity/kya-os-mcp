/**
 * KYA-OS Entity Card — RESOLVE (discovery).
 *
 * Discover another entity's card — the conventional, UNAUTHENTICATED half. Discovery
 * precedes the proof: you need the card's DID (the proof audience) before you can mint a
 * proof against it.
 *
 * The card's canonical home is the `KyaOsEntityCard` service entry on the entity's
 * `did:web` DID document, NOT a bespoke `/.well-known` file. `resolveCard` is multi-surface:
 *   - a `did:web` (or `{ did }`) resolves in TWO steps — `did.json` → the `KyaOsEntityCard`
 *     service entry → `card.json`;
 *   - `{ cardUrl }` fetches a `card.json` directly (the lazy-fetch target of a `cardRef`);
 *   - `{ serverMeta }` reads a server.json / catalog `_meta['org.kya-os/card']` entry — a
 *     `{ 'org.kya-os/cardRef' }` and a `did:web` inline summary DEREFERENCE the entity's canonical
 *     `card.json` (the summary is a discovery INDEX, its `id` names the DID, never trusted as an
 *     authoritative card); a `did:key` summary has no web home to dereference, so it is parsed
 *     directly — fail-closed because the summary carries the `revocation` kill switch and
 *     `delegationRef` (see `resolveFromServerMeta`);
 *   - `{ a2a }` follows an A2A AgentExtension's `params.cardUrl`;
 *   - `{ agentFacts }` two-steps from a NANDA AgentFacts `id` (a `did:web`).
 *
 * EVERY outbound fetch goes through the injected `SafeFetch` seam (SSRF-hardened, https-only,
 * private-range-denied — see `src/utils/safe-fetch.ts`), because resolution now follows
 * attacker-influenced URLs across four discovery surfaces.
 */

import { isRecord } from '../utils/guards.js';
import type { SafeFetch } from '../utils/safe-fetch.js';
import { EntityCardSchema, type EntityCard } from './schema.js';

// ── Canonical discovery constants (co-located in the lowest module so `emit.ts`, which
//    builds these surfaces, can depend on `resolve.ts` one-way without an import cycle) ──

/** DID-document `service[].type` string that anchors the card (we own only this string). */
export const KYA_OS_CARD_SERVICE_TYPE = 'KyaOsEntityCard';
/** DID-document `service[].id` fragment for the card service entry. */
export const KYA_OS_CARD_SERVICE_ID = '#kya-os-card';
/** Reverse-DNS `_meta` key carrying the card (inline summary or a `cardRef`) on MCP surfaces. */
export const KYA_OS_CARD_META_KEY = 'org.kya-os/card';
/** Reverse-DNS key whose value is a lazy-fetch `card.json` URL inside `org.kya-os/card`. */
export const KYA_OS_CARD_REF_KEY = 'org.kya-os/cardRef';
/**
 * Bare-domain (org-root) card convention. A path-form `did:web:host:a:b` anchors its card at
 * `/a/b/card.json`, but a BARE `did:web:host` (an org root — e.g. the default trusted issuer
 * `did:web:example.com`) has no path segment, so its card lives at this well-known path. Defined
 * ONCE here so `didWebToCardUrl` (emit) and the summary-derive resolve path agree on one URL —
 * closing the emit/resolve asymmetry that previously locked bare org roots out of the helpers.
 */
export const KYA_OS_CARD_WELL_KNOWN_PATH = '.well-known/kya-os-card.json';

/** A non-DID reference form `resolveCard` accepts in addition to a bare `did:web` string. */
export type CardRef =
  | { did: string }
  | { cardUrl: string }
  | { serverMeta: unknown }
  | { a2a: unknown }
  | { agentFacts: unknown };

export type ResolveCardInput = string | CardRef;

export interface ResolveCardDeps {
  /** SSRF-hardened fetch seam — every outbound request is routed through it. */
  fetch: SafeFetch;
}

/**
 * Discover an entity's card from any supported reference form. A `did:web` resolves in two
 * steps (`did.json` → `KyaOsEntityCard` service → `card.json`); the reference forms short-cut
 * to the `card.json` URL (or an inline summary). `did:key` has no domain anchor, so a
 * `did:key` card must be supplied directly (e.g. via `parseCard`), never resolved.
 *
 * THROW CONTRACT (fail-closed — deliberately UNLIKE the DID-METHOD resolvers, which return
 * null so a failed method can be retried): every failure path REJECTS with a reasoned `Error`
 * (message prefixed `resolveCard:`, or a `ZodError` from `parseCard` on an invalid card body).
 * `resolveCard` NEVER resolves to `null`/`undefined`. Rationale: this is a security-relevant
 * verify surface — a silently-null card would let an integrator mistake "couldn't resolve" for
 * "no card = allow" (fail-open). Integrators MUST wrap the call and treat a throw as a hard
 * deny. See CONTRIBUTING.md → Code Style for why this surface is scoped out of the null-on-
 * failure resolver rule.
 */
export async function resolveCard(
  input: ResolveCardInput,
  deps: ResolveCardDeps,
): Promise<EntityCard> {
  const { fetch } = deps;
  if (typeof input === 'string') return resolveDidWeb(input, fetch);
  if ('did' in input) return resolveDidWeb(input.did, fetch);
  if ('cardUrl' in input) return fetchCard(input.cardUrl, fetch);
  if ('serverMeta' in input) return resolveFromServerMeta(input.serverMeta, fetch);
  if ('a2a' in input) return fetchCard(cardUrlFromA2A(input.a2a), fetch);
  if ('agentFacts' in input) return resolveDidWeb(didFromAgentFacts(input.agentFacts), fetch);
  throw new Error('resolveCard: unrecognized reference form');
}

/** Two-step `did:web` resolution: `did.json` → `KyaOsEntityCard` service → `card.json`. */
async function resolveDidWeb(did: string, fetch: SafeFetch): Promise<EntityCard> {
  if (!did.startsWith('did:web:')) {
    throw new Error(
      `resolveCard: only did:web is resolvable (got "${did}"); supply a did:key card directly`,
    );
  }
  const didDoc = await fetchJson(didWebToDidDocUrl(did), fetch);
  return fetchCard(cardEndpointFromDidDoc(didDoc, did), fetch, did);
}

/**
 * Read a server.json / catalog `_meta` block and resolve it fail-closed. An explicit
 * `org.kya-os/cardRef` is a lazy-fetch URL; an inline summary is a discovery INDEX handled by
 * `resolveInlineSummary` (dereference for `did:web`, parse-in-place for `did:key`).
 */
async function resolveFromServerMeta(serverMeta: unknown, fetch: SafeFetch): Promise<EntityCard> {
  const entry = isRecord(serverMeta) ? serverMeta[KYA_OS_CARD_META_KEY] : undefined;
  if (entry === undefined) {
    throw new Error(`resolveCard: serverMeta has no "${KYA_OS_CARD_META_KEY}" entry`);
  }
  const ref = isRecord(entry) ? entry[KYA_OS_CARD_REF_KEY] : undefined;
  if (typeof ref === 'string') return fetchCard(ref, fetch);
  return resolveInlineSummary(entry, fetch);
}

/**
 * Resolve an inline `_meta` summary fail-closed. A `did:web` summary is a discovery INDEX: its
 * `id` names the DID, so we DEREFERENCE the canonical `card.json` and never trust the (claim-
 * minimal) summary as a first-class card — landing back on the one authoritative source that
 * carries `revocation`/`delegationRef`/`attestations`, so a revoked card cannot fail open. A
 * `did:key` id has NO web home to dereference, so the summary is parsed directly; this stays
 * fail-closed because the summary now carries the `revocation` kill switch and `delegationRef`
 * (the projection is self-verifiable), so `verifyCard`'s status-list checker is still consulted
 * and a revoked `did:key` card verifies `ok:false`.
 *
 * SECURITY (§12.6): the `did:key` branch trusts the *presented* summary — a `did:key` has no
 * origin-served `card.json` to dereference, so an intermediary that strips `revocation` from an
 * unsigned `did:key` summary can hide a revocation. `did:web` is REQUIRED for revocable Entities.
 */
async function resolveInlineSummary(entry: unknown, fetch: SafeFetch): Promise<EntityCard> {
  const id = isRecord(entry) ? entry.id : undefined;
  if (typeof id !== 'string') {
    throw new Error(`resolveCard: inline "${KYA_OS_CARD_META_KEY}" summary has no string id (DID)`);
  }
  if (id.startsWith('did:web:')) return fetchCard(didWebToCardUrl(id), fetch, id);
  return parseCard(entry);
}

/** Locate the `KyaOsEntityCard` service entry's endpoint on a DID document (fail-closed). */
function cardEndpointFromDidDoc(didDoc: unknown, did: string): string {
  const services = isRecord(didDoc) && Array.isArray(didDoc.service) ? didDoc.service : [];
  for (const svc of services) {
    if (
      isRecord(svc) &&
      svc.type === KYA_OS_CARD_SERVICE_TYPE &&
      typeof svc.serviceEndpoint === 'string'
    ) {
      return svc.serviceEndpoint;
    }
  }
  throw new Error(
    `resolveCard: DID document for "${did}" has no ${KYA_OS_CARD_SERVICE_TYPE} service entry`,
  );
}

/** Pull the `card.json` URL out of an A2A AgentExtension's `params.cardUrl` (fail-closed). */
function cardUrlFromA2A(a2a: unknown): string {
  const params = isRecord(a2a) ? a2a.params : undefined;
  const cardUrl = isRecord(params) ? params.cardUrl : undefined;
  if (typeof cardUrl !== 'string') {
    throw new Error('resolveCard: A2A extension has no string params.cardUrl');
  }
  return cardUrl;
}

/** Pull the agent DID out of a NANDA AgentFacts document's `id` (fail-closed). */
function didFromAgentFacts(agentFacts: unknown): string {
  const id = isRecord(agentFacts) ? agentFacts.id : undefined;
  if (typeof id !== 'string') {
    throw new Error('resolveCard: AgentFacts has no string id (DID)');
  }
  return id;
}

/** GET a URL through the SafeFetch seam and return its parsed JSON (throws on non-2xx). */
async function fetchJson(url: string, fetch: SafeFetch): Promise<unknown> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`resolveCard: GET ${url} → ${res.status}`);
  return res.json();
}

/**
 * GET a `card.json` URL and validate it into an `EntityCard`. When `expectedDid` is supplied — every
 * DID-anchored resolve path (`did:web` two-step, inline `did:web` summary, AgentFacts) — BIND the
 * fetched card to it: its `id` MUST equal that DID (normalized), else FAIL CLOSED. This closes the
 * cross-origin confusion where a DID document's `KyaOsEntityCard` service entry points at a card for
 * a DIFFERENT DID (or a compromised third-party endpoint), which would otherwise attribute another
 * entity's claims/capabilities to the resolved DID. The `{ cardUrl }` and A2A paths carry no
 * independent DID to bind against, so they pass no `expectedDid` (the URL itself is the trust root).
 */
async function fetchCard(url: string, fetch: SafeFetch, expectedDid?: string): Promise<EntityCard> {
  const card = parseCard(await fetchJson(url, fetch));
  if (expectedDid !== undefined && normalizeDid(card.id) !== normalizeDid(expectedDid)) {
    throw new Error(
      `resolveCard: resolved card id "${card.id}" ≠ requested DID "${expectedDid}" (identity mismatch) — fail-closed`,
    );
  }
  return card;
}

/** Decompose a `did:web` into its host + slash-joined path segments. */
function parseDidWeb(did: string): { host: string; path: string } {
  const parts = did.slice('did:web:'.length).split(':').map(decodeURIComponent);
  return { host: parts[0] ?? '', path: parts.slice(1).join('/') };
}

/**
 * Canonicalize a DID for identity comparison. For `did:web` the DNS host is case-INsensitive and the
 * segments are percent-decoded (reusing {@link parseDidWeb}), so `did:web:Example.com` binds to
 * `did:web:example.com`; other DID methods (e.g. `did:key`, case-sensitive base58) compare verbatim.
 */
function normalizeDid(did: string): string {
  if (!did.startsWith('did:web:')) return did;
  const { host, path } = parseDidWeb(did);
  const base = `did:web:${host.toLowerCase()}`;
  return path ? `${base}:${path.split('/').join(':')}` : base;
}

/**
 * Map a `did:web` to its per-entity card URL:
 *   did:web:host:a:b → https://host/a/b/card.json
 *   did:web:host     → https://host/.well-known/kya-os-card.json  (the bare org-root convention)
 *
 * A bare `did:web:host` (an org root, incl. the default trusted issuer) resolves to the
 * well-known card path so the trust anchors can publish their own card via the shipped helpers,
 * and the emit projections agree with the summary-derive resolve path on this one URL. A
 * non-`did:web` DID (e.g. `did:key`) has no web home, so this throws with actionable guidance:
 * emit it onto the inline summary + AgentFacts surfaces, or supply an explicit `serviceEndpoint`.
 */
export function didWebToCardUrl(did: string): string {
  if (!did.startsWith('did:web:')) {
    throw new Error(
      `didWebToCardUrl: only a did:web has a web card URL (got "${did}"); a did:key card has no web home — emit it onto the inline summary + AgentFacts surfaces, or supply an explicit serviceEndpoint`,
    );
  }
  const { host, path } = parseDidWeb(did);
  return path ? `https://${host}/${path}/card.json` : `https://${host}/${KYA_OS_CARD_WELL_KNOWN_PATH}`;
}

/**
 * Map a `did:web` to its DID document URL (W3C did:web):
 *   did:web:host:a:b → https://host/a/b/did.json
 *   did:web:host     → https://host/.well-known/did.json
 */
export function didWebToDidDocUrl(did: string): string {
  const { host, path } = parseDidWeb(did);
  return path ? `https://${host}/${path}/did.json` : `https://${host}/.well-known/did.json`;
}

/** Validate + parse an unknown value into an EntityCard (throws a ZodError on mismatch). */
export function parseCard(value: unknown): EntityCard {
  return EntityCardSchema.parse(value);
}
