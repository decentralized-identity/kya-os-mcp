/**
 * Status-list operations shared by the operator scripts and the demo server:
 * build, re-sign, fetch, publish-as-new-DLR-version, and wait-for-visibility.
 *
 * The publish path is the on-chain analog of what StatusList2021Manager's
 * storage provider does off-chain: every mutation is a NEW resource version
 * under the same name/type — cheqd DLRs are append-only, so the issuer can
 * never quietly rewrite history. DLR preparation (canonicalize → hash →
 * registrar body) is the shipped `prepareCheqdDlrResource` with the
 * `StatusListCredential` artifact type.
 */
import {
  BitstringManager,
  canonicalizeJSON,
  type StatusList2021Credential,
  type VCSigningFunction,
} from '@kya-os/mcp';
import {
  prepareCheqdDlrResource,
  type CheqdDidRegistrarClient,
  type CheqdRegistrarSigner,
} from '@kya-os/mcp/cheqd';
import {
  cryptoProvider,
  gzipCompressor,
  gzipDecompressor,
  STATUSLIST_NAME,
  STATUSLIST_RESOURCE_TYPE,
  type IssuerIdentity,
} from './lib/wiring.js';

export const STATUS_LIST_SIZE = 131072; // W3C minimum-recommended herd size

// ---------------------------------------------------------------------------
// Build & re-sign
// ---------------------------------------------------------------------------

export async function buildInitialStatusListCredential(options: {
  identity: IssuerIdentity;
  signingFunction: VCSigningFunction;
  /** The version-independent resolver URL — doubles as the credential id. */
  url: string;
  purpose?: 'revocation' | 'suspension';
  size?: number;
}): Promise<StatusList2021Credential> {
  const { identity, signingFunction, url } = options;
  const purpose = options.purpose ?? 'revocation';
  const manager = new BitstringManager(options.size ?? STATUS_LIST_SIZE, gzipCompressor, gzipDecompressor);
  const encodedList = await manager.encode();

  const unsigned = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://w3id.org/vc/status-list/2021/v1',
    ] as (string | Record<string, unknown>)[],
    id: url,
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    issuer: identity.did,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: `${url}#list`,
      type: 'StatusList2021' as const,
      statusPurpose: purpose,
      encodedList,
    },
  };

  const proof = await signingFunction(canonicalizeJSON(unsigned), identity.did, identity.kid);
  return { ...unsigned, proof: proof as Record<string, unknown> };
}

/** Flip one bit and re-sign — the entire content of a revocation. */
export async function resignWithBit(options: {
  credential: StatusList2021Credential;
  index: number;
  revoked: boolean;
  identity: IssuerIdentity;
  signingFunction: VCSigningFunction;
}): Promise<StatusList2021Credential> {
  const { credential, index, revoked, identity, signingFunction } = options;

  const bits = await BitstringManager.decode(
    credential.credentialSubject.encodedList,
    gzipCompressor,
    gzipDecompressor,
  );
  bits.setBit(index, revoked);
  const encodedList = await bits.encode();

  const unsigned: Record<string, unknown> = {
    ...credential,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      ...credential.credentialSubject,
      encodedList,
    },
  };
  delete unsigned['proof'];

  const proof = await signingFunction(canonicalizeJSON(unsigned), identity.did, identity.kid);
  return { ...(unsigned as unknown as StatusList2021Credential), proof: proof as Record<string, unknown> };
}

// ---------------------------------------------------------------------------
// Fetch & publish
// ---------------------------------------------------------------------------

interface FetchLike {
  fetch(url: string, init?: Record<string, unknown>): Promise<{
    ok: boolean;
    status: number;
    json(): Promise<unknown>;
  }>;
}

export async function fetchLatestStatusList(
  fetchProvider: FetchLike,
  url: string,
  options?: { bust?: boolean },
): Promise<StatusList2021Credential> {
  // NOTE: never append extra query params — the cheqd resolver treats the query
  // string as DID URL dereferencing input and 400s (invalidDidUrl) on unknown
  // params. Verified live: the query is cf-cache-status DYNAMIC (uncached), so
  // a no-cache header is all "busting" can or needs to be.
  const response = await fetchProvider.fetch(url, {
    method: 'GET',
    headers: {
      Accept: 'application/json',
      ...(options?.bust ? { 'Cache-Control': 'no-cache', Pragma: 'no-cache' } : {}),
    },
  });
  if (!response.ok) {
    throw new Error(`Status list fetch failed: HTTP ${response.status} for ${url}`);
  }
  const vc = (await response.json()) as StatusList2021Credential;
  if (!vc?.credentialSubject?.encodedList) {
    throw new Error(`Resolver response for ${url} is not a status list credential`);
  }
  return vc;
}

export async function publishStatusListVersion(options: {
  registrar: CheqdDidRegistrarClient;
  signer: CheqdRegistrarSigner;
  identity: IssuerIdentity;
  credential: StatusList2021Credential;
  version: string;
  name?: string;
}): Promise<{ resourceId: string | undefined; contentHash: string; response: unknown }> {
  const { registrar, signer, identity, credential, version } = options;

  // The artifact's content is the WHOLE SIGNED VC — hash-what-you-publish: the
  // canonical bytes anchored on-chain are exactly what a verifier fetches.
  const prepared = await prepareCheqdDlrResource(
    {
      type: 'StatusListCredential',
      subjectDid: identity.did,
      name: options.name ?? STATUSLIST_NAME,
      resourceType: STATUSLIST_RESOURCE_TYPE,
      version,
      content: credential,
    },
    cryptoProvider,
  );

  const result = await registrar.createResource({
    did: identity.did,
    resource: prepared.resource,
    signer,
    verificationMethodId: identity.kid,
  });

  if (!result.success) {
    throw new Error(
      `Status list publish failed at stage "${result.stage}": ${result.reason ?? 'unknown'}\n` +
      JSON.stringify(result.response ?? {}, null, 2).slice(0, 2000),
    );
  }

  return {
    resourceId: findStringByKey(result.response, 'resourceId'),
    contentHash: prepared.contentHash,
    response: result.response,
  };
}

/** Poll the version-independent URL until `predicate` matches. Returns elapsed ms. */
export async function waitForStatusListVisible(options: {
  fetchProvider: FetchLike;
  url: string;
  predicate: (vc: StatusList2021Credential) => boolean;
  timeoutMs?: number;
  intervalMs?: number;
}): Promise<{ elapsedMs: number; credential: StatusList2021Credential }> {
  const timeoutMs = options.timeoutMs ?? 120_000;
  const intervalMs = options.intervalMs ?? 2_000;
  const started = Date.now();
  let lastError: unknown;

  for (;;) {
    try {
      const vc = await fetchLatestStatusList(options.fetchProvider, options.url, { bust: true });
      if (options.predicate(vc)) {
        return { elapsedMs: Date.now() - started, credential: vc };
      }
      lastError = new Error('fetched a list, but the predicate did not match yet');
    } catch (err) {
      // transient resolver errors during propagation are expected; keep polling
      lastError = err;
    }
    if (Date.now() - started > timeoutMs) {
      const detail = lastError instanceof Error ? lastError.message : String(lastError);
      throw new Error(`Status list not visible at ${options.url} within ${timeoutMs}ms (last error: ${detail})`);
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

export function findStringByKey(value: unknown, key: string): string | undefined {
  if (Array.isArray(value)) {
    for (const entry of value) {
      const found = findStringByKey(entry, key);
      if (found) return found;
    }
    return undefined;
  }
  if (typeof value !== 'object' || value === null) return undefined;
  const record = value as Record<string, unknown>;
  if (typeof record[key] === 'string') return record[key] as string;
  for (const nested of Object.values(record)) {
    const found = findStringByKey(nested, key);
    if (found) return found;
  }
  return undefined;
}
