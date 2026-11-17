/**
 * CheqdStatusListResolver — StatusList2021 revocation checks against a cheqd
 * DID-Linked Resource (the on-chain status list the DEF CON 34 "REVOKED" demo
 * ran, upstreamed as a thin consumer of the shared primitives).
 *
 * Implements the delegation `StatusListResolver` seam: `checkStatus` returns
 * TRUE when the credential's bit is set (revoked) and THROWS on anything
 * unprovable — `DelegationCredentialVerifier` then denies fail-closed
 * (`status_unresolvable`). Like the card revocation checker given
 * `verifyStatusList`, it verifies the LIST itself: issuer pinned to
 * `expectedIssuerDid`, and the Ed25519Signature2020 proof checked against the
 * issuer's (on-chain) DID document. The chain provides availability and
 * append-only history; the cryptographic root stays the issuer's signature —
 * "the resolver returned it" is never sufficient on its own.
 *
 * The pin is the verifier's whole trust decision for status: a list the
 * pinned DID issued is read for any credential, whoever issued it, and no
 * other list is read, so the `context` a caller passes is not consulted. The
 * acceptance rule the proof-verifying status-list readers share
 * (`acceptStatusList`) holds the list to the pin and to the entry's purpose,
 * and, with `requireId`, to state as its `id` the URL it was fetched from,
 * byte for byte: the pinned DID may sign lists for many issuers' credentials,
 * and only the `id` binds a list to the URL it is served at. A DID URL naming
 * the same resource is another `id`. `StatusList2021Manager` states the `id`
 * of every list it writes. This resolver checks no validity window, so an
 * earlier version of a list the pinned DID signed is read as it stands.
 *
 * Fail-closed matrix (all throw → verifier denies as `status_unresolvable`):
 * non-https URL, malformed index, network error / non-200, malformed VC,
 * unsigned VC, wrong issuer, purpose mismatch, no `id` or an `id` other than
 * the fetched URL, missing proofValue, a verification method named by
 * anything but a non-empty string, unresolvable issuer DID, no usable
 * verification method, bad signature, out-of-range index. The refusal carries
 * its code: `host_refused` for a URL that is not https, `delegation_malformed`
 * for an entry it does not read, one that names its list by no string included, `status_signer_untrusted` for a list that may
 * not answer or whose proof does not verify, the resolution's code for an
 * issuer DID that could not be resolved, and `status_unavailable` otherwise.
 *
 * Freshness: an internal {@link TtlCache} holds the VERIFIED document
 * (default 10 s — one fetch amortizes across every credential on a list;
 * `cacheTtlMs: 0` disables). Compose `withStatusCache` on top for a
 * declared per-bit staleness SLA. `invalidateCache()` drops the document and
 * defeats upstream HTTP caches on the next fetch.
 */
import { resolveExplained } from '../../delegation/did-resolution-failure.js';
import { fetchStatusListJson } from '../../delegation/status-list-fetch.js';
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
import {
  ASSERTION_METHOD,
  assertionMethodRefusal,
  proofPurposeMismatch,
  selectAssertionMethod,
} from '../../delegation/verification-relationship.js';
import { credentialWithoutProof } from '../../delegation/signed-form.js';
import {
  decodeStatusListPayload,
  parseStatusListIndex,
  readStatusBit,
} from '../../utils/statuslist-bits.js';
import { acceptEntrySize, acceptStatusList } from '../../utils/statuslist-acceptance.js';
import { bytesToBase64 } from '../../utils/base64.js';
import { base64EitherBytes } from '../../utils/base64-reading.js';
import { canonicalizeJsonBytes } from '../../utils/canonical-json.js';
import { dependencyTimeout } from '../../utils/deadline.js';
import { developmentMode } from '../../utils/development-mode.js';
import { admittingPrivateHosts, type PrivateNetworkTransport } from '../../utils/private-network-rule.js';
import { ed25519KeyBytes } from '../../utils/ed25519-public-key.js';
import { RefusalError } from '../../utils/refusal.js';
import { TtlCache } from '../../utils/ttl-cache.js';

export interface CheqdStatusListResolverOptions {
  /**
   * Transport for fetching the status-list resource. The resolver enforces
   * `https://` on the URL and reads through the private-network rule
   * (`utils/private-network-rule.ts`), whatever the provider: a non-public
   * IP-literal host and a local name are refused, and each redirect is followed
   * by hand and held to the same rule. A provider with
   * `allowPrivateNetworkHosts: true`, such as
   * `new RuntimeFetchProvider({ allowPrivateNetworkHosts: true })`, turns the
   * host check off.
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
  /**
   * How long, in milliseconds, the list read may take, and the resolution of the issuer DID after it: a number greater than 0 and at most
   * 2,147,483,647. Default 5,000. Any other value throws a `TypeError` naming the option.
   */
  dependencyTimeoutMs?: number;
  /**
   * Read status lists on private and local hosts, such as a `*.localhost` name in a local demo, as
   * a provider with `allowPrivateNetworkHosts: true` does, whatever the provider. Nothing else
   * changes: the https rule, checked redirects, byte caps and deadlines all hold. For development
   * only: while `NODE_ENV` is `production` it throws when the resolver is built, and it warns once
   * per process. Any value but a boolean throws a `TypeError`.
   */
  development?: boolean;
}

export class CheqdStatusListResolver implements StatusListResolver {
  private readonly opts: CheqdStatusListResolverOptions;
  /** What the list is read through: the provider, admitting private hosts under `development`. */
  private readonly transport: PrivateNetworkTransport;
  private readonly cacheTtlMs: number;
  private cache: TtlCache<StatusList2021Credential>;
  private bustNextFetch = false;
  private readonly timeoutMs: number;

  constructor(options: CheqdStatusListResolverOptions) {
    const development = developmentMode(options.development, 'CheqdStatusListResolverOptions.development');
    this.opts = options;
    this.transport = development ? admittingPrivateHosts(options.fetchProvider) : options.fetchProvider;
    this.timeoutMs = dependencyTimeout(options.dependencyTimeoutMs);
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
    if (typeof url !== 'string') {
      throw new RefusalError('delegation_malformed', 'credentialStatus.statusListCredential must be an https URL');
    }
    if (!/^https:\/\//.test(url)) {
      throw new RefusalError('host_refused', 'credentialStatus.statusListCredential must be an https URL');
    }
    // One bit is read per entry, so an entry of another size is refused before any fetch.
    const size = acceptEntrySize(status.statusSize);
    if (!size.valid) {
      throw new RefusalError('delegation_malformed', size.reason);
    }

    const index = parseStatusListIndex(status.statusListIndex);
    const credential = await this.fetchAndVerifyList(url, status.statusPurpose);

    const bits = await decodeStatusListPayload(
      credential.credentialSubject.encodedList,
      (bytes) => this.opts.decompressor.decompress(bytes),
    );
    return readStatusBit(bits, index);
  }

  /**
   * The list at `url`, held to the acceptance rule for an entry of
   * `statusPurpose`, fail-closed: issued by the pinned DID, of the entry's
   * purpose (a clear bit on the WRONG KIND of list would report "not revoked"
   * from a list that never tracked revocation), and stating `url` as its `id`.
   * The rule runs before the signature check on a fetch, and again for every
   * entry read from a cached list, since entries on one list may state other
   * purposes.
   */
  private async fetchAndVerifyList(
    url: string,
    statusPurpose: string,
  ): Promise<StatusList2021Credential> {
    const cached = this.cache.get(url);
    const credential = cached ?? (await this.fetchList(url));
    const verdict = acceptStatusList(credential, {
      statusListCredential: url,
      statusPurpose,
      keeper: { did: this.opts.expectedIssuerDid, why: 'resolver-issuer' },
      requireId: true,
    });
    if (!verdict.valid) {
      throw new RefusalError('status_signer_untrusted', verdict.reason);
    }
    if (!cached) {
      await this.assertSignature(credential);
      this.bustNextFetch = false;
      this.cache.set(url, credential);
    }
    return credential;
  }

  private async fetchList(url: string): Promise<StatusList2021Credential> {
    // NEVER append query params here: the cheqd resolver parses the query as
    // DID URL dereferencing input and 400s (invalidDidUrl) on unknown params
    // (verified live). The endpoint is served cf-cache-status DYNAMIC, so
    // post-revocation freshness only needs a no-cache header.
    const body = (await fetchStatusListJson(this.transport, url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        ...(this.bustNextFetch
          ? { 'Cache-Control': 'no-cache', Pragma: 'no-cache' }
          : {}),
      },
    }, this.timeoutMs)) as StatusList2021Credential;
    this.assertShape(body);
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

  /**
   * Verify the Ed25519Signature2020 proof over the JCS-canonicalized VC
   * (minus `proof`) against the issuer's on-chain DID document. Key material
   * arrives however the DID method publishes it — `verificationMethodJwk`
   * accepts `publicKeyJwk`, `publicKeyMultibase` (cheqd's format), or legacy
   * `publicKeyBase58`. A status list is an assertion by its issuer, so only a
   * key the issuer's DID document lists under `assertionMethod` is tried
   * ({@link selectAssertionMethod}): the one `proof.verificationMethod` names,
   * or, when it names none, the first listed there, so a list costs one
   * signature check. A proof that states another `proofPurpose` is refused
   * before the issuer's DID is resolved, and one that names its verification
   * method by anything but a non-empty string is refused (SPEC.md §6.2): an
   * empty name names no key, and is not read as no name.
   */
  private async assertSignature(vc: StatusList2021Credential): Promise<void> {
    const proof = vc.proof as Record<string, unknown>;
    const proofValue = proof['proofValue'];
    if (typeof proofValue !== 'string' || proofValue.length === 0) {
      throw new RefusalError('status_signer_untrusted', 'Status list proof is missing proofValue');
    }
    const purposeMismatch = proofPurposeMismatch(proof, ASSERTION_METHOD);
    if (purposeMismatch) {
      throw new RefusalError('status_signer_untrusted', purposeMismatch);
    }

    // What the signature covers is what an embedded proof covers on any credential (SPEC.md
    // §6.2): the object without `proof`, in its RFC 8785 form.
    const data = canonicalizeJsonBytes(credentialWithoutProof(vc));
    // Read as a credential's proofValue is (SPEC.md §7.8), so one string is one signature on
    // every runtime; a string that carries none fails the check below. The list is not read
    // through `signedCredential`, whose refusals are a delegation credential's: it refuses such
    // a string, and a signature of no bytes, in its own words and before the issuer's DID is
    // resolved, and it bounds nesting as SPEC.md §7.8 does. A list is refused below, once its
    // issuer's key is selected, as a signature that failed.
    const signature = base64EitherBytes(proofValue);

    const named: unknown = proof['verificationMethod'];
    const keyId = typeof named === 'string' ? named : undefined;
    const resolved = await resolveExplained(this.opts.didResolver, this.opts.expectedIssuerDid, keyId, this.timeoutMs);
    if (resolved.document === null) {
      throw new RefusalError(resolved.code, `Could not resolve issuer DID ${this.opts.expectedIssuerDid}${resolved.why}`);
    }
    const didDoc = resolved.document;

    const selection = selectAssertionMethod(didDoc, this.opts.expectedIssuerDid, named);
    if (!('method' in selection)) {
      throw new RefusalError(
        'status_signer_untrusted',
        assertionMethodRefusal(selection, 'Status list proof verificationMethod', named, this.opts.expectedIssuerDid),
      );
    }

    const jwk = verificationMethodJwk(selection.method);
    const publicKeyBase64 = jwk ? ed25519KeyBase64(jwk) : undefined;
    // The crypto provider is the host's: the signature holds only on the literal `true`.
    if (!signature || !publicKeyBase64 || (await this.opts.cryptoProvider.verify(data, signature, publicKeyBase64)) !== true) {
      throw new RefusalError(
        'status_signer_untrusted',
        'Status list signature verification FAILED against the issuer DID document',
      );
    }
  }
}

/**
 * The base64 of the Ed25519 key a JWK carries in `x`, read as every proof's key is (SPEC.md §7.4):
 * base64url as RFC 7515 §2 writes it, of 32 bytes. Undefined for an `x` not so written.
 */
function ed25519KeyBase64(jwk: { x?: unknown }): string | undefined {
  try {
    return bytesToBase64(ed25519KeyBytes(jwk));
  } catch {
    return undefined;
  }
}

export function createCheqdStatusListResolver(
  options: CheqdStatusListResolverOptions,
): CheqdStatusListResolver {
  return new CheqdStatusListResolver(options);
}
