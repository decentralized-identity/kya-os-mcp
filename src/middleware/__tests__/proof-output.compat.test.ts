/**
 * Byte-for-byte pins of what the middleware emits today.
 *
 * Signing is deterministic (Ed25519), so with a fixed key, seeded random bytes
 * and a frozen clock every result below, proofs included, is reproducible. The
 * expected results in `__fixtures__/proof-output-golden.json` were captured from
 * the 1.18.0 behavior; they are compared as serialized, so key order counts. A
 * change that alters any of them alters the wire for existing callers.
 */
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createKyaOsMiddleware, type KyaOsMiddleware } from '../with-kya-os.js';
import { createKyaOsTransport, type JSONRPCMessage, type Transport } from '../kya-os-transport.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { generateDidKeyFromBase64, didKeyFragment } from '../../utils/did-helpers.js';
import {
  RESPONSE_PROOF_PROFILE_ENVELOPE,
  type ResponseProofProfile,
} from '../../proof/generator.js';
import type { PolicyEngine } from '../../policy/engine.js';

/** Random bytes from a counter-seeded SHA-256 stream: reproducible across runs. */
class SeededCryptoProvider extends NodeCryptoProvider {
  private counter = 0;

  override async randomBytes(length: number): Promise<Uint8Array> {
    const out = new Uint8Array(length);
    let filled = 0;
    while (filled < length) {
      const block = createHash('sha256').update(`seed-${this.counter++}`).digest();
      const take = Math.min(block.length, length - filled);
      out.set(block.subarray(0, take), filled);
      filled += take;
    }
    return out;
  }
}

const SEED = Buffer.alloc(32, 7);
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function fixedIdentity() {
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, SEED]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = (createPublicKey(privateKey).export({ type: 'spki', format: 'der' }) as Buffer)
    .subarray(12)
    .toString('base64');
  const did = generateDidKeyFromBase64(publicKey);
  return { did, kid: `${did}#${didKeyFragment(did)}`, privateKey: SEED.toString('base64'), publicKey };
}

const GOLDEN = JSON.parse(
  readFileSync(new URL('./__fixtures__/proof-output-golden.json', import.meta.url), 'utf8'),
) as Record<string, unknown>;

function expectGolden(name: string, actual: unknown): void {
  expect(GOLDEN[name]).toBeDefined();
  expect(JSON.stringify(actual)).toBe(JSON.stringify(GOLDEN[name]));
}

const NOW = Date.UTC(2026, 9, 1, 12, 0, 0);
const CONSENT = { scopeId: 'cart:write', consentUrl: 'https://consent.example/authorize' };

async function setup(responseProofProfile?: ResponseProofProfile): Promise<{
  kyaos: KyaOsMiddleware;
  sessionId: string;
}> {
  const identity = fixedIdentity();
  const kyaos = createKyaOsMiddleware(
    {
      identity,
      session: { sessionTtlMinutes: 60 },
      ...(responseProofProfile === undefined ? {} : { responseProofProfile }),
    },
    new SeededCryptoProvider(),
  );
  const handshake = await kyaos.handleHandshake({
    nonce: 'compat-nonce',
    audience: identity.did,
    timestamp: Math.floor(NOW / 1000),
  });
  return { kyaos, sessionId: JSON.parse(handshake.content[0]!.text).sessionId };
}

const engine = (decision: Awaited<ReturnType<PolicyEngine['evaluate']>>): PolicyEngine => ({
  evaluate: async () => decision,
});

const ran = async () => ({ content: [{ type: 'text', text: 'ran' }] });

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'], now: NOW });
});
afterEach(() => {
  vi.useRealTimers();
});

describe('proof output stays byte-identical', () => {
  it('default needs_authorization challenge, body profile', async () => {
    const { kyaos, sessionId } = await setup();
    const result = await kyaos.wrapWithDelegation('checkout', CONSENT, ran)({ item: 'x' }, sessionId);
    expectGolden('challengeBody', result);
  });

  it('default needs_authorization challenge, envelope profile', async () => {
    const { kyaos, sessionId } = await setup(RESPONSE_PROOF_PROFILE_ENVELOPE);
    const result = await kyaos.wrapWithDelegation('checkout', CONSENT, ran)({ item: 'x' }, sessionId);
    expectGolden('challengeEnvelope', result);
  });

  it('delegation gate denial of a malformed delegation', async () => {
    const { kyaos, sessionId } = await setup();
    const result = await kyaos.wrapWithDelegation('checkout', CONSENT, ran)(
      { item: 'x', _kyaos_delegation: { bogus: true } },
      sessionId,
    );
    expectGolden('delegationDenied', result);
  });

  it('policy gate denial', async () => {
    const { kyaos, sessionId } = await setup();
    const result = await kyaos.withPolicyGate!('wipe', ran, {
      engine: engine({ decision: 'deny', reason: 'blocked' }),
    })({ id: 1 }, sessionId);
    expectGolden('policyDenied', result);
  });

  it('policy gate step-up', async () => {
    const { kyaos, sessionId } = await setup();
    const result = await kyaos.withPolicyGate!('wipe', ran, {
      engine: engine({ decision: 'step_up', quorum: { n: 1, approvers: [] }, reason: 'destructive' }),
    })({ id: 1 }, sessionId);
    expectGolden('policyStepUp', result);
  });

  it('success proof, body profile', async () => {
    const { kyaos, sessionId } = await setup();
    const result = await kyaos.wrapWithProof('greet', ran)({ name: 'DIF' }, sessionId);
    expectGolden('successBody', result);
  });

  it('success proof, envelope profile', async () => {
    const { kyaos, sessionId } = await setup(RESPONSE_PROOF_PROFILE_ENVELOPE);
    const result = await kyaos.wrapWithProof('greet', async () => ({
      content: [{ type: 'text', text: 'ran' }],
      structuredContent: { ok: true },
    }))({ name: 'DIF' }, sessionId);
    expectGolden('successEnvelope', result);
  });

  describe('through the withKyaOs transport', () => {
    async function send(result: Record<string, unknown>): Promise<JSONRPCMessage> {
      const { kyaos } = await setup();
      const sent: JSONRPCMessage[] = [];
      const inner: Transport = {
        start: async () => {},
        close: async () => {},
        send: async (message) => {
          sent.push(message);
        },
      };
      const wrapper = createKyaOsTransport(inner, kyaos);
      await wrapper.start();
      inner.onmessage!({
        jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'pay', arguments: { amount: 5 } },
      });
      await wrapper.send({ jsonrpc: '2.0', id: 1, result: structuredClone(result) });
      return sent[0]!;
    }

    it('an unstamped error result goes out unproven, exactly as the handler returned it', async () => {
      const sent = await send({ content: [{ type: 'text', text: 'declined' }], isError: true });
      expectGolden('transportError', sent);
    });

    it('an unstamped error result loses an outcome proof it forged', async () => {
      const sent = await send({
        content: [{ type: 'text', text: 'declined' }],
        isError: true,
        _meta: { traceparent: '00-abc-01', 'org.kya-os/response-proof': { jws: 'forged' } },
      });
      expectGolden('transportForgedError', sent);
    });

    it('an unstamped success result is proven', async () => {
      const sent = await send({ content: [{ type: 'text', text: 'paid' }] });
      expectGolden('transportSuccess', sent);
    });
  });
});
