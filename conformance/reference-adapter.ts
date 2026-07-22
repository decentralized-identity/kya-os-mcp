/**
 * Reference {@link ConformanceAdapter} for `@kya-os/mcp`: every method delegates
 * to the package's PUBLIC verify primitives (signed proofs, delegation chains,
 * status lists, did:key/did:web resolution, and the Entity Card layer) and
 * re-implements no verification logic — passing the suite here proves the
 * reference implementation is conformant against the same vectors any other
 * implementation would run. Standalone helpers live in `./adapter-helpers.ts`.
 *
 * All methods are fail-closed: any thrown error or unmet property becomes
 * `{ outcome: 'fail' }`.
 */

import {
  ProofVerifier,
  DelegationCredentialVerifier,
  createDidKeyResolver,
  createDidWebResolver,
  MemoryNonceCacheProvider,
  type DIDDocument,
  type CredentialStatus,
  type DelegationCredential,
  type StatusList2021Credential,
} from '../src/index.js';
import type { Ed25519JWK } from '../src/utils/crypto-service.js';
import { NodeCryptoProvider } from '../src/providers/node-crypto.js';
import {
  validateDelegationChain,
  type DelegationCredentialVerifierPort,
} from '../src/delegation/chain-enforcement.js';
import { BitstringManager } from '../src/delegation/bitstring.js';
import { ClockProvider, FetchProvider } from '../src/providers/base.js';
// The Entity Card layer (`org.kya-os/proof@1` + the typed card) lives on the
// `@kya-os/mcp/card` subpath, NOT the package root — wire its PUBLIC verify
// primitives here exactly as the legacy ones above (no forked logic).
import {
  verifyCardProof as verifyCardProofPrimitive,
  verifyCard,
  parseCard,
  InMemoryNonceCache,
  type VerifyCardDeps,
} from '../src/card/index.js';
import type { ToolRequest } from '../src/proof/generator.js';
import type {
  AdapterResult,
  AuditIntegrityInput,
  CardProofInput,
  ConformanceAdapter,
  DelegationChainInput,
  DidResolutionInput,
  EntityCardInput,
  SignedProofInput,
  StatusListInput,
} from './types.js';
import {
  CryptoProviderAuditHasher,
  digestAuditEvent,
  parseAuditProducerEvent,
  Rfc9162MerkleTree,
  type Digest,
} from '../src/audit/index.js';
import { canonicalizeJson } from '../src/utils/canonical-json.js';
import {
  conformanceCompressor,
  conformanceDecompressor,
  ed25519SignatureVerifier,
} from './crypto-kit.js';
import {
  asMessage,
  didOfKid,
  didWebUrl,
  isUsableEd25519Document,
  makeAccountabilityVerifier,
  makeMultiResolver,
  resolveJwksKey,
  toEd25519PublicJwk,
} from './adapter-helpers.js';

const PASS: AdapterResult = { outcome: 'pass' };
function fail(detail: string): AdapterResult {
  return { outcome: 'fail', detail };
}

/**
 * `ClockProvider` pinned to a fixed epoch-ms "now" so timestamp-skew vectors are
 * deterministic regardless of wall-clock time.
 */
class PinnedClock extends ClockProvider {
  constructor(private readonly nowMs: number) {
    super();
  }
  now(): number {
    return this.nowMs;
  }
  isWithinSkew(timestampMs: number, skewSeconds: number): boolean {
    return Math.abs(this.nowMs - timestampMs) <= skewSeconds * 1000;
  }
  hasExpired(expiresAt: number): boolean {
    return this.nowMs > expiresAt;
  }
  calculateExpiry(ttlSeconds: number): number {
    return this.nowMs + ttlSeconds * 1000;
  }
  format(timestamp: number): string {
    return new Date(timestamp).toISOString();
  }
}

/**
 * Offline `FetchProvider` serving DID documents and status lists from in-memory
 * maps the vector supplies — the harness does no network I/O, so vectors stay
 * hermetic and reproducible.
 */
class StaticFetchProvider extends FetchProvider {
  constructor(
    private readonly didDocuments: Record<string, unknown> = {},
    private readonly urlBodies: Record<string, unknown> = {},
  ) {
    super();
  }
  async resolveDID(did: string): Promise<DIDDocument | null> {
    return (this.didDocuments[did] as DIDDocument) ?? null;
  }
  async fetchStatusList(): Promise<StatusList2021Credential | null> {
    return null;
  }
  async fetchDelegationChain(): Promise<never[]> {
    return [];
  }
  async fetch(url: string): Promise<Response> {
    const body = this.urlBodies[url];
    if (body === undefined) {
      return new Response('not found', { status: 404 });
    }
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }
}

export class ReferenceConformanceAdapter implements ConformanceAdapter {
  readonly name = '@kya-os/mcp (reference)';
  private readonly crypto = new NodeCryptoProvider();

  async verifySignedProof(input: SignedProofInput): Promise<AdapterResult> {
    try {
      const verifier = new ProofVerifier({
        cryptoProvider: this.crypto,
        clockProvider: new PinnedClock(input.now * 1000),
        nonceCacheProvider: new MemoryNonceCacheProvider(),
        fetchProvider: new StaticFetchProvider(),
        timestampSkewSeconds: input.skewSeconds,
      });
      const result = await verifier.verifyProof(
        input.proof as Parameters<ProofVerifier['verifyProof']>[0],
        input.publicKeyJwk as Ed25519JWK,
      );
      return result.valid ? PASS : fail(result.reason ?? 'proof rejected');
    } catch (error) {
      return fail(`verifySignedProof threw: ${asMessage(error)}`);
    }
  }

  async verifyDelegationChain(input: DelegationChainInput): Promise<AdapterResult> {
    try {
      const fetchProvider = new StaticFetchProvider(input.didDocuments);
      const didResolver = makeMultiResolver(input.didDocuments, fetchProvider);

      const credentialVerifier = new DelegationCredentialVerifier({
        didResolver,
        signatureVerifier: ed25519SignatureVerifier(this.crypto),
      });
      const verifierPort: DelegationCredentialVerifierPort = {
        verifyDelegationCredential: (credential, options) =>
          credentialVerifier.verifyDelegationCredential(credential, {
            skipStatus: true, // status handled by the dedicated status-list vectors
            ...(options?.skipSignature ? { skipSignature: true } : {}),
          }),
      };

      const ancestors = (input.ancestors ?? []) as DelegationCredential[];
      const result = await validateDelegationChain(
        input.leaf as DelegationCredential,
        {
          serverDid: input.serverDid,
          verifier: verifierPort,
          statusListConfigured: false,
          resolveDelegationChain:
            ancestors.length > 0
              ? async () => [...ancestors, input.leaf as DelegationCredential]
              : undefined,
        },
      );
      return result.valid ? PASS : fail(result.reason ?? 'chain rejected');
    } catch (error) {
      return fail(`verifyDelegationChain threw: ${asMessage(error)}`);
    }
  }

  async verifyStatusList(input: StatusListInput): Promise<AdapterResult> {
    try {
      const credential = input.credential as DelegationCredential;
      const status = credential.credentialStatus;
      if (!status) {
        return fail('credential has no credentialStatus to verify');
      }

      // Status resolver backed by the supplied StatusList2021Credentials, decoded
      // with the SAME bitstring primitive the manager uses (DRY).
      const statusListResolver = {
        checkStatus: async (s: CredentialStatus): Promise<boolean> => {
          const list = input.statusLists[s.statusListCredential] as
            | StatusList2021Credential
            | undefined;
          if (!list) {
            throw new Error(`status list not found: ${s.statusListCredential}`);
          }
          const manager = await BitstringManager.decode(
            list.credentialSubject.encodedList,
            conformanceCompressor,
            conformanceDecompressor,
          );
          return manager.getBit(parseInt(s.statusListIndex, 10));
        },
      };

      const fetchProvider = new StaticFetchProvider(input.didDocuments);
      const didResolver = makeMultiResolver(input.didDocuments, fetchProvider);
      const verifier = new DelegationCredentialVerifier({
        didResolver,
        statusListResolver,
        signatureVerifier: ed25519SignatureVerifier(this.crypto),
      });

      const result = await verifier.verifyDelegationCredential(credential, {
        skipCache: true,
      });
      return result.valid ? PASS : fail(result.reason ?? 'credential rejected');
    } catch (error) {
      return fail(`verifyStatusList threw: ${asMessage(error)}`);
    }
  }

  async resolveDidKey(input: DidResolutionInput): Promise<AdapterResult> {
    try {
      const resolver = createDidKeyResolver();
      const doc = await resolver.resolve(input.did);
      return isUsableEd25519Document(doc)
        ? PASS
        : fail(`did:key resolution produced no usable verification method for ${input.did}`);
    } catch (error) {
      return fail(`resolveDidKey threw: ${asMessage(error)}`);
    }
  }

  async resolveDidWeb(input: DidResolutionInput): Promise<AdapterResult> {
    try {
      // did:web is fetched from its well-known URL; serve the vector's document
      // there (or nothing, for the not-found negative case).
      const url = didWebUrl(input.did);
      const urlBodies = url && input.didDocument !== undefined
        ? { [url]: input.didDocument }
        : {};
      const resolver = createDidWebResolver(new StaticFetchProvider({}, urlBodies));
      const doc = await resolver.resolve(input.did);
      return isUsableEd25519Document(doc)
        ? PASS
        : fail(`did:web resolution produced no usable verification method for ${input.did}`);
    } catch (error) {
      return fail(`resolveDidWeb threw: ${asMessage(error)}`);
    }
  }

  async verifyCardProof(input: CardProofInput): Promise<AdapterResult> {
    try {
      const keys = input.jwks.keys.map(toEd25519PublicJwk);
      // A fresh single-use nonce cache per vector: race-free consume, pinned clock.
      const nonceCache = new InMemoryNonceCache({ now: () => input.nowMs });
      const result = await verifyCardProofPrimitive(input.proof, input.request as ToolRequest, {
        resolveKey: (kid) => resolveJwksKey(keys, kid),
        resolveDidKeys: (did) => keys.filter((k) => didOfKid(k.kid) === did),
        expectedAudience: input.expectedAudience,
        // Omit the seam for the nonce-seam-missing vector; the verifier MUST fail closed without it.
        ...(input.omitNonceSeam ? {} : { consumeNonceIfFresh: nonceCache.consume }),
        now: () => input.nowMs,
        skewSec: input.skewSeconds,
        ...(input.tokenCnfJkt !== undefined ? { tokenCnfJkt: input.tokenCnfJkt } : {}),
      });
      return result.ok ? PASS : fail(result.reasons.join(', '));
    } catch (error) {
      return fail(`verifyCardProof threw: ${asMessage(error)}`);
    }
  }

  async verifyEntityCard(input: EntityCardInput): Promise<AdapterResult> {
    try {
      const card = parseCard(input.card); // throws on a malformed card → fail-closed
      const deps: VerifyCardDeps = {
        ...(input.trustedIssuers ? { trustedIssuers: input.trustedIssuers } : {}),
        ...(input.cimdKeyProven !== undefined ? { cimdKeyProven: input.cimdKeyProven } : {}),
        ...(input.accountability
          ? { accountabilityVerifier: makeAccountabilityVerifier(input.accountability) }
          : {}),
      };
      const result = await verifyCard(card, deps);
      return result.ok
        ? PASS
        : fail(`card rejected (level ${result.conformanceLevel})`);
    } catch (error) {
      return fail(`verifyEntityCard rejected: ${asMessage(error)}`);
    }
  }

  async verifyAuditIntegrity(input: AuditIntegrityInput): Promise<AdapterResult> {
    try {
      const hasher = new CryptoProviderAuditHasher(this.crypto);
      const tree = new Rfc9162MerkleTree(hasher);
      const event = parseAuditProducerEvent(input.event);
      const eventValid = canonicalizeJson(event) === input.eventCanonical &&
        await digestAuditEvent(hasher, event) === input.eventDigest;
      const leaves = input.leaves as Digest[];
      const root = await tree.root(leaves);
      const inclusion = await tree.verifyInclusion({
        leaf: leaves[input.inclusion.leafIndex]!,
        leafIndex: input.inclusion.leafIndex,
        treeSize: leaves.length,
        root: input.root as Digest,
        auditPath: input.inclusion.auditPath as Digest[],
      });
      const consistency = await tree.verifyConsistency({
        oldSize: input.consistency.oldSize,
        newSize: leaves.length,
        oldRoot: input.consistency.oldRoot as Digest,
        newRoot: input.root as Digest,
        auditPath: input.consistency.auditPath as Digest[],
      });
      return eventValid && root === input.root && inclusion && consistency
        ? PASS
        : fail('audit event canonicalization/digest, Merkle root, or proof rejected');
    } catch (error) {
      return fail(`verifyAuditIntegrity threw: ${asMessage(error)}`);
    }
  }
}
