import {
  generateRequestProof, toHolderBindingRequest, ProofVerifier, MemoryNonceCacheProvider,
  NoopFetchProvider, SystemClockProvider, resolveDidKeySync,
  type DetachedProof,
} from '@kya-os/mcp';
import { cryptoProvider, RP_DID, rpOrigin, type KeyedIdentity } from './wiring.js';
import { ed25519PublicKeyBase64 } from './http-statuslist-resolver.js';

export interface SignedMessage { body: Record<string, unknown>; proof: DetachedProof }
const signer = (identity: KeyedIdentity) => ({ did: identity.did, kid: identity.kid, privateKey: identity.privateKeyBase64, publicKey: identity.publicKeyBase64 });
export async function signMessage(method: string, body: Record<string, unknown>, identity: KeyedIdentity, audience: string): Promise<SignedMessage> {
  return { body, proof: await generateRequestProof({ identity: signer(identity), crypto: cryptoProvider, toolName: method, args: body, audience }) };
}

/** This example's HTTP binding uses the same published request-proof primitives.
 * Requests and replies have distinct method names; replies bind the request nonce.
 */
export class ConsentProtocol {
  private readonly verifier = new ProofVerifier({ cryptoProvider, clockProvider: new SystemClockProvider(), nonceCacheProvider: new MemoryNonceCacheProvider(), fetchProvider: new NoopFetchProvider() });
  constructor(private readonly rpDid = RP_DID, private readonly origin = rpOrigin()) {}

  async verify(method: string, message: SignedMessage, expectedDid: string, audience: string): Promise<Record<string, unknown>> {
    if (!message?.body || typeof message.body !== 'object' || Array.isArray(message.body)
      || message.proof?.meta?.did !== expectedDid || message.proof.meta.audience !== audience) throw new Error('CONSENT_PROTOCOL_INVALID: signer or audience mismatch');
    const proof = message.proof;
    let doc;
    if (expectedDid.startsWith('did:key:')) doc = resolveDidKeySync(expectedDid);
    else {
      if (expectedDid !== this.rpDid) throw new Error('CONSENT_PROTOCOL_INVALID: untrusted issuer');
      const response = await fetch(new URL('/.well-known/did.json', this.origin), { signal: AbortSignal.timeout(5000), redirect: 'error' });
      if (!response.ok) throw new Error('CONSENT_PROTOCOL_UNAVAILABLE: issuer DID document');
      doc = await response.json();
    }
    if (doc?.id !== expectedDid) throw new Error('CONSENT_PROTOCOL_INVALID: DID document binding');
    const methodKey = doc.verificationMethod?.find((m: { id: string }) => m.id === proof.meta.kid);
    const key = methodKey && ed25519PublicKeyBase64(methodKey);
    if (!key) throw new Error('CONSENT_PROTOCOL_INVALID: signer key');
    const verified = await this.verifier.verifyProof(proof, {
      kty: 'OKP', crv: 'Ed25519', kid: proof.meta.kid, x: Buffer.from(key, 'base64').toString('base64url'),
    }, { request: toHolderBindingRequest(method, message.body) });
    if (!verified.valid) throw new Error(`CONSENT_PROTOCOL_INVALID: ${verified.errorCode ?? 'proof verification failed'}`);
    return message.body;
  }

  async request(path: string, method: string, body: Record<string, unknown>, identity: KeyedIdentity): Promise<Record<string, unknown>> {
    const message = await signMessage(method, body, identity, this.rpDid);
    const response = await fetch(new URL(path, this.origin), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(message),
      signal: AbortSignal.timeout(5000), redirect: 'error',
    });
    if (!response.ok) throw new Error(`CONSENT_PROTOCOL_UNAVAILABLE: RP returned HTTP ${response.status}`);
    const reply = await response.json() as SignedMessage;
    const result = await this.verify(`${method}.result`, reply, this.rpDid, identity.did);
    if (result['requestNonce'] !== message.proof.meta.nonce) throw new Error('CONSENT_PROTOCOL_INVALID: response request binding');
    return result;
  }
}
