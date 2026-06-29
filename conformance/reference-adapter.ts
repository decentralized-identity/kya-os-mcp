/**
 * Reference {@link ConformanceAdapter} for `@kya-os/mcp`.
 *
 * DRY: every method delegates to the package's PUBLIC verify primitives — it does
 * NOT re-implement any verification logic. This is exactly the surface a third
 * party would wire their own implementation into, so passing the suite here
 * proves the reference implementation is conformant against the same vectors any
 * other implementation would run.
 *
 *   - signed proofs        → {@link ProofVerifier.verifyProof}
 *   - delegation chains    → {@link validateDelegationChain} + {@link DelegationCredentialVerifier}
 *   - status-list checks   → {@link StatusList2021Manager.checkStatus} via the chain's status resolver
 *   - did:key resolution   → {@link createDidKeyResolver}
 *   - did:web resolution   → {@link createDidWebResolver}
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
import type {
  AdapterResult,
  ConformanceAdapter,
  DelegationChainInput,
  DidResolutionInput,
  SignedProofInput,
  StatusListInput,
} from './types.js';
import {
  conformanceCompressor,
  conformanceDecompressor,
  ed25519SignatureVerifier,
} from './crypto-kit.js';

const PASS: AdapterResult = { outcome: 'pass' };
function fail(detail: string): AdapterResult {
  return { outcome: 'fail', detail };
}

/**
 * Clock pinned to a fixed epoch-seconds "now" so timestamp-skew vectors are
 * deterministic regardless of wall-clock time. Implements the package's
 * `ClockProvider` port with a fixed time source.
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
 * Offline FetchProvider serving DID documents and status lists from in-memory
 * maps the vector supplies. The harness MUST do no network I/O so vectors are
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
}

/**
 * Resolve a DID against the vector's supplied documents, falling back to the
 * offline method resolvers (did:key derives from the DID itself; did:web reads
 * the static fetch map). Keeps signature verification self-contained.
 */
function makeMultiResolver(
  didDocuments: Record<string, unknown>,
  fetchProvider: StaticFetchProvider,
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

function isUsableEd25519Document(doc: DIDDocument | null): boolean {
  const vm = doc?.verificationMethod?.[0];
  const jwk = vm?.publicKeyJwk as { kty?: string; crv?: string; x?: string } | undefined;
  return Boolean(jwk && jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && jwk.x);
}

function didWebUrl(did: string): string | null {
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

function asMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
