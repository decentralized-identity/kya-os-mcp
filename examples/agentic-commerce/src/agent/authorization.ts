/** Verify merchant challenges and order receipts before reporting their contents. */
import {
  MemoryNonceCacheProvider,
  NoopFetchProvider,
  ProofVerifier,
  RESPONSE_PROOF_PROFILE_ENVELOPE,
  SystemClockProvider,
  base64urlEncodeFromBytes,
  extractProofFromMeta,
  extractPublicKeyFromDidKey,
  toHolderBindingRequest,
  type NeedsAuthorizationError,
} from '@kya-os/mcp';
import { cryptoProvider } from '../lib/wiring.js';

export interface MerchantToolResult {
  content?: Array<{ type: string; text?: string }>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
  structuredContent?: Record<string, unknown>;
}

export interface AuthorizationExpectation {
  args: Record<string, unknown>;
  merchantDid: string;
  agentDid: string;
  consentOrigin: string;
  scope: string;
}

export function responseBody(result: MerchantToolResult): Record<string, unknown> {
  const text = result.content?.find((part) => part.type === 'text')?.text;
  if (!text) return {};
  try {
    const body: unknown = JSON.parse(text);
    return body !== null && typeof body === 'object' && !Array.isArray(body) ? body as Record<string, unknown> : {};
  } catch {
    return { raw: text };
  }
}

function createResponseVerifier(verifyReceipts: boolean) {
  const verifier = new ProofVerifier({
    cryptoProvider,
    clockProvider: new SystemClockProvider(),
    nonceCacheProvider: new MemoryNonceCacheProvider(),
    fetchProvider: new NoopFetchProvider(),
  });

  return async (result: MerchantToolResult, expected: AuthorizationExpectation): Promise<NeedsAuthorizationError | null> => {
    const body = responseBody(result);
    const challenge = body['error'] === 'needs_authorization';
    // x402 uses an MCP error-shaped tool result for its signed payment quote.
    // Its presence is not permission to skip authenticating the merchant.
    const payment = body['x402Version'] === 2 && Array.isArray(body['accepts']);
    const settlementPending = body['error'] === 'SETTLEMENT_PENDING';
    if (!challenge && (!verifyReceipts || (!payment && !settlementPending && (result.isError || body['error'])))) return null;

    const extracted = extractProofFromMeta(result._meta ?? {});
    if (!extracted.success) throw new Error(`Untrusted merchant response proof: ${extracted.reason}`);
    const { proof } = extracted;
    // This local demo pins an Ed25519 did:key merchant and its canonical key
    // fragment. A did:web merchant needs an explicit resolver/key policy here.
    const expectedKid = `${expected.merchantDid}#${expected.merchantDid.slice('did:key:'.length)}`;
    if (proof.meta.did !== expected.merchantDid || proof.meta.kid !== expectedKid || proof.meta.audience !== expected.merchantDid) {
      throw new Error('Untrusted merchant response proof: merchant identity or audience mismatch');
    }
    if (!proof.meta.responseHash || (challenge
      ? proof.meta.outcome !== 'needs_authorization'
      : proof.meta.outcome !== undefined && proof.meta.outcome !== 'allowed')) {
      throw new Error('Untrusted merchant response proof: invalid outcome or missing responseHash');
    }
    const publicKey = extractPublicKeyFromDidKey(expected.merchantDid);
    if (!publicKey) throw new Error('Untrusted merchant response proof: merchant DID cannot be resolved');
    // The published challenge proof excludes the delegation while retaining
    // the holder proof. Success receipts bind the clean handler arguments.
    const { _kyaos_delegation: ignoredCredential, ...params } = expected.args;
    const verified = await verifier.verifyProof(proof, {
      kty: 'OKP', crv: 'Ed25519', x: base64urlEncodeFromBytes(publicKey), kid: expectedKid,
    }, {
      request: challenge ? { method: 'place_order', params } : toHolderBindingRequest('place_order', expected.args),
      response: { data: proof.meta.prf === RESPONSE_PROOF_PROFILE_ENVELOPE ? result : result.content },
    });
    if (!verified.valid) throw new Error(`Untrusted merchant response proof: ${verified.errorCode ?? verified.reason ?? 'verification failed'}`);
    if (!challenge) return null;

    if (typeof body['message'] !== 'string' || !body['message'] ||
        typeof body['resumeToken'] !== 'string' || !body['resumeToken'] ||
        typeof body['authorizationUrl'] !== 'string' ||
        !Number.isSafeInteger(body['expiresAt']) || Number(body['expiresAt']) <= Math.floor(Date.now() / 1000) ||
        !Array.isArray(body['scopes']) || body['scopes'].length !== 1 || body['scopes'][0] !== expected.scope) {
      throw new Error('Unsafe authorization challenge: expired or invalid grant parameters');
    }
    let url: URL;
    try { url = new URL(body['authorizationUrl']); } catch { throw new Error('Unsafe authorization URL'); }
    const allowed = new URL(expected.consentOrigin);
    // Passkeys registered on localhost require that RP name; ordinary click
    // consent uses 127.0.0.1. Only these two signed loopback names may alias,
    // and only on the exact configured protocol and port.
    const loopback = new Set(['127.0.0.1', 'localhost']);
    const sameLocalEndpoint = loopback.has(url.hostname) && loopback.has(allowed.hostname)
      && url.protocol === allowed.protocol && url.port === allowed.port;
    if ((url.origin !== allowed.origin && !sameLocalEndpoint) || url.pathname !== '/consent' || url.username || url.password || url.hash) {
      throw new Error('Unsafe authorization URL: unexpected RP origin or consent path');
    }
    const exactQuery = (key: string, value: string): boolean => url.searchParams.getAll(key).length === 1 && url.searchParams.get(key) === value;
    if (!exactQuery('resume_token', body['resumeToken']) || !exactQuery('agent_did', expected.agentDid) || !exactQuery('tool', 'place_order')) {
      throw new Error('Unsafe authorization URL: token, agent, or tool binding mismatch');
    }
    const encodedScopes = url.searchParams.get('scopes');
    let scopes: unknown = encodedScopes === expected.scope ? [encodedScopes] : null;
    if (scopes === null) {
      try { scopes = JSON.parse(encodedScopes ?? 'null'); } catch { scopes = null; }
    }
    if (url.searchParams.getAll('scopes').length !== 1 || !Array.isArray(scopes) || scopes.length !== 1 || scopes[0] !== expected.scope) {
      throw new Error('Unsafe authorization URL: scope binding mismatch');
    }
    return body as NeedsAuthorizationError;
  };
}

export const createAuthorizationVerifier = () => createResponseVerifier(false);
export const createOrderResponseVerifier = () => createResponseVerifier(true);

/** Shared live verifier retains nonce replay protection between gateway calls. */
export const verifyMerchantOrderResponse = createOrderResponseVerifier();
