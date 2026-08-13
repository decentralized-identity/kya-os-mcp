/**
 * CheqdStatusListResolver — StatusList2021 revocation checks against a cheqd
 * DID-Linked Resource (the on-chain status list the DEF CON 34 "REVOKED" demo
 * ran, upstreamed as a thin consumer of the shared primitives).
 *
 * Implements the delegation `StatusListResolver` seam: `checkStatus` returns
 * TRUE when the credential's bit is set (revoked) and THROWS on anything
 * unprovable — `DelegationCredentialVerifier` then denies fail-closed
 * (`status_unresolvable`). Unlike the package's other status-list readers,
 * this one also verifies the LIST itself: issuer pinned to
 * `expectedIssuerDid`, and the Ed25519Signature2020 proof checked against the
 * issuer's (on-chain) DID document. The chain provides availability and
 * append-only history; the cryptographic root stays the issuer's signature —
 * "the resolver returned it" is never sufficient on its own.
 *
 * Fail-closed matrix (all throw → verifier denies as `status_unresolvable`):
 * non-https URL, malformed index, network error / non-200, malformed VC,
 * unsigned VC, wrong issuer, purpose mismatch, missing proofValue,
 * unresolvable issuer DID, no usable verification method, bad signature,
 * out-of-range index.
 *
 * Freshness: an internal {@link TtlCache} holds the VERIFIED document
 * (default 10 s — one fetch amortizes across every credential on a list;
 * `cacheTtlMs: 0` disables). Compose `withStatusCache` on top for a
 * declared per-bit staleness SLA. `invalidateCache()` drops the document and
 * defeats upstream HTTP caches on the next fetch.
 */
import type { FetchProvider, CryptoProvider } from '../../providers/base.js';
import type {
  DIDResolver,
  StatusListResolver,
} from '../../delegation/vc-verifier.types.js';
import type { DecompressionFunction } from '../../delegation/bitstring.js';
import type {
  CredentialStatus,
  StatusList2021Credential,
} from '../../types/protocol.js';
import { verificationMethodJwk } from '../../delegation/verification-method-key.js';
import { canonicalizeJSON } from '../../delegation/utils.js';
import {
  decodeStatusListPayload,
  parseStatusListIndex,
  readStatusBit,
} from '../../utils/statuslist-bits.js';
import { assertStatusPurpose } from '../../utils/statuslist-purpose.js';
import { base64urlDecodeToBytes, bytesToBase64 } from '../../utils/base64.js';
import { TtlCache } from '../../utils/ttl-cache.js';

export interface CheqdStatusListResolverOptions {
  /**
   * Transport for fetching the status-list resource. The resolver enforces
   * `https://` on the URL; SSRF guarding beyond the scheme (private-range
   * blocking, redirects) is the injected provider's duty —
   * `RuntimeFetchProvider` provides it.
   */
  fetchProvider: FetchProvider;
  /** Resolves the status list ISSUER's DID document (did:cheqd, on-chain). */
  didResolver: DIDResolver;
  /** Verifies the list's Ed25519 signature (raw bytes + base64 public key). */
  cryptoProvider: CryptoProvider;
  /** Only status lists issued (and signed) by this DID are trusted. */
  expectedIssuerDid: string;
  /** Inflates the gzip `encodedList` (same seam as `BitstringManager`). */
  decompressor: DecompressionFunction;
  /** In-memory TTL for the fetched VERIFIED list; 0 disables. Default 10s. */
  cacheTtlMs?: number;
}

export class CheqdStatusListResolver implements StatusListResolver {
  private readonly opts: CheqdStatusListResolverOptions;
  private readonly cacheTtlMs: number;
  private cache: TtlCache<StatusList2021Credential>;
  private bustNextFetch = false;

  constructor(options: CheqdStatusListResolverOptions) {
    this.opts = options;
    this.cacheTtlMs = options.cacheTtlMs ?? 10_000;
    // A single issuer realistically publishes a handful of lists; 16 entries
    // is generous without being unbounded.
    this.cache = new TtlCache<StatusList2021Credential>({
      ttlMs: this.cacheTtlMs,
      maxEntries: 16,
    });
  }

  /** Drop the cached list and defeat upstream HTTP caches on the next fetch. */
  invalidateCache(): void {
    this.cache.clear();
    this.bustNextFetch = true;
  }

  /** TRUE = revoked. Throws on anything unprovable — the verifier fails closed. */
  async checkStatus(status: CredentialStatus): Promise<boolean> {
    const url = status.statusListCredential;
    if (typeof url !== 'string' || !/^https:\/\//.test(url)) {
      throw new Error('credentialStatus.statusListCredential must be an https URL');
    }

    const index = parseStatusListIndex(status.statusListIndex);
    const credential = await this.fetchAndVerifyList(url);

    // Purpose parity, fail-closed (shared validator): a clear bit on the WRONG
    // KIND of list would report "not revoked" from a list that never tracked
    // revocation.
    assertStatusPurpose(
      credential.credentialSubject.statusPurpose,
      status.statusPurpose,
    );

    const bits = await decodeStatusListPayload(
      credential.credentialSubject.encodedList,
      (bytes) => this.opts.decompressor.decompress(bytes),
    );
    return readStatusBit(bits, index);
  }

  private async fetchAndVerifyList(url: string): Promise<StatusList2021Credential> {
    const cached = this.cache.get(url);
    if (cached) {
      return cached;
    }

    // NEVER append query params here: the cheqd resolver parses the query as
    // DID URL dereferencing input and 400s (invalidDidUrl) on unknown params
    // (verified live). The endpoint is served cf-cache-status DYNAMIC, so
    // post-revocation freshness only needs a no-cache header.
    const response = await this.opts.fetchProvider.fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        ...(this.bustNextFetch
          ? { 'Cache-Control': 'no-cache', Pragma: 'no-cache' }
          : {}),
      },
    });
    if (!response.ok) {
      throw new Error(`Status list fetch failed: HTTP ${response.status} for ${url}`);
    }

    const body = (await response.json()) as StatusList2021Credential;
    this.assertShape(body);
    this.assertIssuer(body);
    await this.assertSignature(body);

    this.bustNextFetch = false;
    this.cache.set(url, body);
    return body;
  }

  private assertShape(vc: StatusList2021Credential): void {
    const types = Array.isArray(vc?.type) ? vc.type : [];
    if (!types.includes('StatusList2021Credential')) {
      throw new Error('Fetched resource is not a StatusList2021Credential');
    }
    const subject = vc.credentialSubject;
    if (
      subject?.type !== 'StatusList2021' ||
      typeof subject.encodedList !== 'string' ||
      subject.encodedList.length === 0
    ) {
      throw new Error(
        'Status list credentialSubject is malformed (missing StatusList2021 encodedList)',
      );
    }
    if (!vc.proof || typeof vc.proof !== 'object') {
      throw new Error('Status list credential is unsigned');
    }
  }

  private assertIssuer(vc: StatusList2021Credential): void {
    const issuer = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer?.id;
    if (issuer !== this.opts.expectedIssuerDid) {
      throw new Error(
        `Status list issuer "${issuer}" is not the expected issuer "${this.opts.expectedIssuerDid}"`,
      );
    }
  }

  /**
   * Verify the Ed25519Signature2020 proof over the JCS-canonicalized VC
   * (minus `proof`) against the issuer's on-chain DID document. Key material
   * arrives however the DID method publishes it — `verificationMethodJwk`
   * accepts `publicKeyJwk`, `publicKeyMultibase` (cheqd's format), or legacy
   * `publicKeyBase58`.
   */
  private async assertSignature(vc: StatusList2021Credential): Promise<void> {
    const proof = vc.proof as Record<string, unknown>;
    const proofValue = proof['proofValue'];
    if (typeof proofValue !== 'string' || proofValue.length === 0) {
      throw new Error('Status list proof is missing proofValue');
    }

    const unsigned: Record<string, unknown> = { ...vc };
    delete unsigned['proof'];
    const data = new TextEncoder().encode(canonicalizeJSON(unsigned));
    const signature = base64urlDecodeToBytes(proofValue);

    const didDoc = await this.opts.didResolver.resolve(this.opts.expectedIssuerDid);
    if (!didDoc) {
      throw new Error(`Could not resolve issuer DID ${this.opts.expectedIssuerDid}`);
    }

    const verificationMethodId =
      typeof proof['verificationMethod'] === 'string'
        ? proof['verificationMethod']
        : undefined;
    const methods = didDoc.verificationMethod ?? [];
    const candidates = verificationMethodId
      ? methods.filter((m) => m.id === verificationMethodId)
      : methods;
    if (candidates.length === 0) {
      throw new Error(
        `Issuer DID document has no verification method matching "${verificationMethodId ?? '(any)'}"`,
      );
    }

    for (const method of candidates) {
      const jwk = verificationMethodJwk(method);
      if (!jwk) continue;
      const publicKeyBase64 = bytesToBase64(base64urlDecodeToBytes(jwk.x));
      if (await this.opts.cryptoProvider.verify(data, signature, publicKeyBase64)) {
        return;
      }
    }
    throw new Error(
      'Status list signature verification FAILED against the issuer DID document',
    );
  }
}

export function createCheqdStatusListResolver(
  options: CheqdStatusListResolverOptions,
): CheqdStatusListResolver {
  return new CheqdStatusListResolver(options);
}
