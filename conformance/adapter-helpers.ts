/**
 * Standalone helpers for the {@link ReferenceConformanceAdapter}.
 *
 * These are pure, dependency-light free functions extracted from
 * `reference-adapter.ts` to keep that module under the size guardrail. Like the
 * adapter itself, they only ever compose the package's PUBLIC primitives — no
 * verification logic is re-implemented here.
 */

import {
  createDidKeyResolver,
  createDidWebResolver,
  type DIDDocument,
} from '../src/index.js';
import type { FetchProvider } from '../src/providers/base.js';
import {
  validateDelegationChain as validateCardDelegationChain,
  type Ed25519PublicJwk,
  type AccountabilityVerifier,
  type DelegationChain,
} from '../src/card/index.js';
import type {
  Ed25519PublicJwkLike,
  EntityCardAccountabilityInput,
} from './types.js';

/**
 * Resolve a DID against the vector's supplied documents, falling back to the
 * offline method resolvers (did:key derives from the DID itself; did:web reads
 * the static fetch map). Keeps signature verification self-contained.
 */
export function makeMultiResolver(
  didDocuments: Record<string, unknown>,
  fetchProvider: FetchProvider,
): { resolve(did: string): Promise<DIDDocument | null> } {
  const didKey = createDidKeyResolver();
  const didWeb = createDidWebResolver(fetchProvider);
  return {
    resolve: async (did: string): Promise<DIDDocument | null> => {
      const supplied = didDocuments[did];
      if (supplied) {
        return supplied as DIDDocument;
      }
      if (did.startsWith('did:key:')) {
        return didKey.resolve(did);
      }
      if (did.startsWith('did:web:')) {
        return didWeb.resolve(did);
      }
      return null;
    },
  };
}

export function isUsableEd25519Document(doc: DIDDocument | null): boolean {
  const vm = doc?.verificationMethod?.[0];
  const jwk = vm?.publicKeyJwk as { kty?: string; crv?: string; x?: string } | undefined;
  return Boolean(jwk && jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && jwk.x);
}

export function didWebUrl(did: string): string | null {
  if (!did.startsWith('did:web:')) return null;
  const remainder = did.slice('did:web:'.length);
  const parts = remainder.split(':').map((p) => decodeURIComponent(p));
  const domain = parts[0];
  if (!domain) return null;
  const path = parts.slice(1);
  return path.length === 0
    ? `https://${domain}/.well-known/did.json`
    : `https://${domain}/${path.join('/')}/did.json`;
}

/** Project a vector's loosely-typed JWK into the card layer's `Ed25519PublicJwk`. */
export function toEd25519PublicJwk(k: Ed25519PublicJwkLike): Ed25519PublicJwk {
  return { kty: 'OKP', crv: 'Ed25519', x: k.x, ...(k.kid ? { kid: k.kid } : {}) };
}

/** The DID part of a `did#fragment` key id (`kid.split('#')[0]`), or `''`. */
export function didOfKid(kid: string | undefined): string {
  return kid ? (kid.split('#')[0] ?? '') : '';
}

/**
 * Resolve a signing key by exact `kid`. Fail-closed per the {@link ResolveKey}
 * contract: THROW when the `kid` is unresolvable (the verifier records
 * `key_unresolvable`), never return a prefix match.
 */
export function resolveJwksKey(keys: Ed25519PublicJwk[], kid: string): Ed25519PublicJwk {
  const key = keys.find((k) => k.kid === kid);
  if (!key) throw new Error(`no JWKS key resolves kid ${kid}`);
  return key;
}

/**
 * Wire the PUBLIC card `validateDelegationChain` into an {@link AccountabilityVerifier}:
 * the edge holds iff the chain attenuates correctly AND `card.responsibleParty ===
 * issuer(rootVC)` AND the recomputed leaf invoker equals the asserted `proofDid`
 * (the delegation/proof JOIN). `fresh` mirrors the structural validity.
 */
export function makeAccountabilityVerifier(
  acc: EntityCardAccountabilityInput,
): AccountabilityVerifier {
  return async (card) => {
    const result = validateCardDelegationChain(acc.chain as DelegationChain, {
      resourceOwner: acc.resourceOwner,
      ...(acc.resource ? { resource: acc.resource } : {}),
      ...(acc.now !== undefined ? { now: () => acc.now! } : {}),
    });
    const responsiblePartyOk = card.responsibleParty === result.responsibleParty;
    const joinOk = acc.proofDid === undefined || result.leafInvoker === acc.proofDid;
    return { verified: result.ok && responsiblePartyOk && joinOk, fresh: result.ok };
  };
}

export function asMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
