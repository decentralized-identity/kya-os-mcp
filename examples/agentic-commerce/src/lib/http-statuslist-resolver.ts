/**
 * HttpStatusListResolver — StatusList2021 revocation checks against a list the
 * Responsible Party hosts at a plain URL, modelled on the shipped
 * `CheqdStatusListResolver` (the on-chain variant from the REVOKED demo).
 *
 * Implements the delegation `StatusListResolver` seam: `checkStatus` returns
 * TRUE when the credential's bit is set (revoked) and THROWS on anything
 * unprovable — `DelegationCredentialVerifier` then denies fail-closed
 * (`status_unresolvable`). The LIST itself is verified, not just fetched:
 * issuer pinned to `expectedIssuerDid`, Ed25519Signature2020 proof checked
 * over the JCS-canonicalized credential against the issuer's resolved DID
 * document. "The server returned it" is never sufficient on its own.
 *
 * Fail-closed matrix (all throw → verifier denies): non-https URL (except
 * loopback when allowed), malformed index, network error / non-200, malformed
 * VC, unsigned VC, wrong issuer, purpose mismatch, missing proofValue,
 * unresolvable issuer DID, no usable verification method, bad signature,
 * out-of-range index.
 *
 * Freshness: the default cache TTL is 0 — every call fetches the list. That is
 * the demo's point ("checked at the moment of action") and costs sub-millisecond
 * on a loopback hub. Set `cacheTtlMs` for a real deployment's SLA.
 */
import {
  BitstringManager,
  base64urlDecodeToBytes,
  bytesToBase64,
  canonicalizeJSON,
  type CredentialStatus,
  type CryptoProvider,
  type DIDResolver,
  type FetchProvider,
  type StatusList2021Credential,
  type StatusListResolver,
  type CompressionFunction,
  type DecompressionFunction,
  type VerificationMethod,
} from '@kya-os/mcp';

export interface HttpStatusListResolverOptions {
  fetchProvider: FetchProvider;
  didResolver: DIDResolver;
  cryptoProvider: CryptoProvider;
  expectedIssuerDid: string;
  compressor: CompressionFunction;
  decompressor: DecompressionFunction;
  /** In-memory TTL for the fetched VERIFIED list; 0 (default) fetches every call. */
  cacheTtlMs?: number;
  /** Accept http:// for localhost / 127.0.0.1 (rehearsal). Default false. */
  allowInsecureLocalhost?: boolean;
}

export interface StatusListObservation {
  url: string;
  fetchedAt: string;
  elapsedMs: number;
  issuer: string;
  verificationMethod: string;
  issuanceDate: string;
  cached: boolean;
}

export class HttpStatusListResolver implements StatusListResolver {
  private readonly opts: HttpStatusListResolverOptions;
  private readonly cacheTtlMs: number;
  private cached: { url: string; credential: StatusList2021Credential; at: number } | null = null;
  /** The last successful fetch+verify, for the console. */
  lastObservation: StatusListObservation | null = null;

  constructor(options: HttpStatusListResolverOptions) {
    this.opts = options;
    this.cacheTtlMs = options.cacheTtlMs ?? 0;
  }

  invalidateCache(): void {
    this.cached = null;
  }

  /** TRUE = revoked. Throws on anything unprovable — the verifier fails closed. */
  async checkStatus(status: CredentialStatus): Promise<boolean> {
    const url = status.statusListCredential;
    if (typeof url !== 'string' || !this.isAcceptableUrl(url)) {
      throw new Error('credentialStatus.statusListCredential must be an https URL');
    }
    const index = parseIndex(status.statusListIndex);
    const credential = await this.fetchAndVerifyList(url);

    // Purpose parity, fail-closed: a clear bit on the WRONG KIND of list would
    // report "not revoked" from a list that never tracked revocation.
    if (credential.credentialSubject.statusPurpose !== status.statusPurpose) {
      throw new Error(
        `Status list purpose "${credential.credentialSubject.statusPurpose}" does not match credential purpose "${status.statusPurpose}"`,
      );
    }

    const bits = await BitstringManager.decode(
      credential.credentialSubject.encodedList,
      this.opts.compressor,
      this.opts.decompressor,
    );
    if (index >= bits.getSize()) {
      throw new Error(`Status list index ${index} is out of range (list size ${bits.getSize()})`);
    }
    return bits.getBit(index);
  }

  private isAcceptableUrl(url: string): boolean {
    let u: URL;
    try { u = new URL(url); } catch { return false; }
    if (u.protocol === 'https:') return true;
    if (u.protocol === 'http:' && this.opts.allowInsecureLocalhost) {
      return u.hostname === 'localhost' || u.hostname === '127.0.0.1';
    }
    return false;
  }

  private async fetchAndVerifyList(url: string): Promise<StatusList2021Credential> {
    if (this.cached && this.cached.url === url && Date.now() - this.cached.at < this.cacheTtlMs) {
      if (this.lastObservation) this.lastObservation = { ...this.lastObservation, cached: true };
      return this.cached.credential;
    }

    const started = Date.now();
    const response = await this.opts.fetchProvider.fetch(url, {
      method: 'GET',
      headers: { Accept: 'application/json', 'Cache-Control': 'no-cache', Pragma: 'no-cache' },
    });
    if (!response.ok) {
      throw new Error(`Status list fetch failed: HTTP ${response.status} for ${url}`);
    }
    const body = (await response.json()) as StatusList2021Credential;
    this.assertShape(body);
    this.assertIssuer(body);
    const verificationMethod = await this.assertSignature(body);

    this.cached = { url, credential: body, at: Date.now() };
    this.lastObservation = {
      url,
      fetchedAt: new Date().toISOString(),
      elapsedMs: Date.now() - started,
      issuer: typeof body.issuer === 'string' ? body.issuer : body.issuer.id,
      verificationMethod,
      issuanceDate: body.issuanceDate,
      cached: false,
    };
    return body;
  }

  private assertShape(vc: StatusList2021Credential): void {
    const types = Array.isArray(vc?.type) ? vc.type : [];
    if (!types.includes('StatusList2021Credential')) {
      throw new Error('Fetched resource is not a StatusList2021Credential');
    }
    const subject = vc.credentialSubject;
    if (subject?.type !== 'StatusList2021' || typeof subject.encodedList !== 'string' || subject.encodedList.length === 0) {
      throw new Error('Status list credentialSubject is malformed (missing StatusList2021 encodedList)');
    }
    if (!vc.proof || typeof vc.proof !== 'object') {
      throw new Error('Status list credential is unsigned');
    }
  }

  private assertIssuer(vc: StatusList2021Credential): void {
    const issuer = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer?.id;
    if (issuer !== this.opts.expectedIssuerDid) {
      throw new Error(`Status list issuer "${issuer}" is not the expected issuer "${this.opts.expectedIssuerDid}"`);
    }
  }

  /**
   * Verify the Ed25519Signature2020 proof over the JCS-canonicalized VC (minus
   * `proof`) against the issuer's DID document. Returns the verification
   * method id that verified.
   */
  private async assertSignature(vc: StatusList2021Credential): Promise<string> {
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
    const wanted = typeof proof['verificationMethod'] === 'string' ? proof['verificationMethod'] : undefined;
    const methods = didDoc.verificationMethod ?? [];
    const candidates = wanted ? methods.filter((m) => m.id === wanted) : methods;
    if (candidates.length === 0) {
      throw new Error(`Issuer DID document has no verification method matching "${wanted ?? '(any)'}"`);
    }
    for (const method of candidates) {
      const publicKeyBase64 = ed25519PublicKeyBase64(method);
      if (!publicKeyBase64) continue;
      if (await this.opts.cryptoProvider.verify(data, signature, publicKeyBase64)) {
        return method.id;
      }
    }
    throw new Error('Status list signature verification FAILED against the issuer DID document');
  }
}

/** Strict canonical-decimal parse, fail-closed (a lenient parse could read a different bit). */
export function parseIndex(raw: string): number {
  if (typeof raw !== 'string' || !/^(0|[1-9][0-9]*)$/.test(raw)) {
    throw new Error(`statusListIndex must be a canonical non-negative decimal, got "${raw}"`);
  }
  const n = Number(raw);
  if (!Number.isSafeInteger(n)) throw new Error(`statusListIndex ${raw} is not a safe integer`);
  return n;
}

/** Ed25519 public key (standard base64) from a verification method's JWK or multibase form. */
export function ed25519PublicKeyBase64(method: VerificationMethod): string | null {
  const jwk = method.publicKeyJwk as { kty?: string; crv?: string; x?: string } | undefined;
  if (jwk && jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && typeof jwk.x === 'string') {
    return bytesToBase64(base64urlDecodeToBytes(jwk.x));
  }
  if (typeof method.publicKeyMultibase === 'string' && method.publicKeyMultibase.startsWith('z')) {
    const bytes = base58Decode(method.publicKeyMultibase.slice(1));
    // multicodec ed25519-pub prefix 0xed 0x01
    if (bytes.length === 34 && bytes[0] === 0xed && bytes[1] === 0x01) {
      return bytesToBase64(bytes.slice(2));
    }
  }
  return null;
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Decode(s: string): Uint8Array {
  const bytes: number[] = [];
  for (const ch of s) {
    let carry = B58.indexOf(ch);
    if (carry < 0) throw new Error('invalid base58');
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i]! * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  for (const ch of s) { if (ch === '1') bytes.push(0); else break; }
  return Uint8Array.from(bytes.reverse());
}
