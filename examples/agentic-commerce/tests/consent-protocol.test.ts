import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';
import { ConsentProtocol, signMessage } from '../src/lib/consent-protocol.js';
import type { KeyedIdentity } from '../src/lib/wiring.js';

let rp: KeyedIdentity, agent: KeyedIdentity, other: KeyedIdentity;
beforeAll(async () => {
  const identities = await Promise.all(Array.from({ length: 3 }, async () => {
    const key = await new NodeCryptoProvider().generateKeyPair();
    const did = generateDidKeyFromBase64(key.publicKey);
    return { did, kid: `${did}#${did.slice(8)}`, publicKeyBase64: key.publicKey, privateKeyBase64: key.privateKey };
  }));
  rp = identities[0]!; agent = identities[1]!; other = identities[2]!;
});
afterEach(() => vi.unstubAllGlobals());

describe('authenticated RP protocol replies', () => {
  it.each(['signer', 'audience', 'body', 'method', 'nonce'] as const)('rejects a reply with the wrong %s', async attack => {
    vi.stubGlobal('fetch', vi.fn(async (_url, init) => {
      const request = JSON.parse(init.body);
      const message = await signMessage(attack === 'method' ? 'consent.create.result' : 'consent.pickup.result', {
        requestNonce: attack === 'nonce' ? 'an-earlier-request' : request.proof.meta.nonce,
        state: 'pending',
      }, attack === 'signer' ? other : rp, attack === 'audience' ? other.did : agent.did);
      if (attack === 'body') message.body['state'] = 'approved';
      return Response.json(message);
    }));
    await expect(new ConsentProtocol(rp.did, 'http://rp.test').request('/consent/pickup', 'consent.pickup', {
      resumeToken: 'request-token', audience: other.did,
    }, agent)).rejects.toThrow('CONSENT_PROTOCOL_INVALID');
  });
  it('accepts a correctly signed reply bound to this exact request', async () => {
    vi.stubGlobal('fetch', vi.fn(async (_url, init) => {
      const request = JSON.parse(init.body);
      await new ConsentProtocol().verify('consent.pickup', request, agent.did, rp.did);
      return Response.json(await signMessage('consent.pickup.result', { requestNonce: request.proof.meta.nonce, state: 'pending' }, rp, agent.did));
    }));
    await expect(new ConsentProtocol(rp.did, 'http://rp.test').request('/consent/pickup', 'consent.pickup', { resumeToken: 'token' }, agent)).resolves.toMatchObject({ state: 'pending' });
  });
  it('rejects proof replay and a substituted request body', async () => {
    const message = await signMessage('consent.pickup', { resumeToken: 'first' }, agent, rp.did);
    const verifier = new ConsentProtocol();
    await expect(verifier.verify('consent.pickup', message, agent.did, rp.did)).resolves.toEqual(message.body);
    await expect(verifier.verify('consent.pickup', message, agent.did, rp.did)).rejects.toThrow('CONSENT_PROTOCOL_INVALID');
    await expect(new ConsentProtocol().verify('consent.pickup', { ...message, body: { resumeToken: 'second' } }, agent.did, rp.did)).rejects.toThrow('CONSENT_PROTOCOL_INVALID');
  });
});
