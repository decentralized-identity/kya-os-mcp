/**
 * The cases a response proof is held to beyond the vectors (SPEC.md §7.3,
 * §7.4 and §7.8), the ones `conformance/proof_cases.py` holds the Python
 * verifier to, under the same names and in the same order.
 *
 * Each alters one thing of a vector whose proof binds: something the verifier
 * holds (its clock, its skew, the key, the request, the response, the outcome
 * it asks for, the chain), the JWS as received, or a claim of the proof, which
 * is signed again with the test key of RFC 8032 §7.1 (TEST 1) and checked with
 * that key. A case the Python verifier finds `bound`, or `no-chain`, passes
 * here; every other fails, and fails where the Python verifier does: on the
 * request, on the response, on the chain, or before any of them is compared.
 */

import { createHash } from 'node:crypto';
import { canonicalize } from 'json-canonicalize';
import { describe, expect, it } from 'vitest';
import { signProofMeta } from '../crypto-kit.js';
import { BASE_POINT_ORDER, ORDER_TWO } from '../small-order.js';
import { buildProofJwsPayload } from '../../src/index.js';
import { bindingFailure } from '../../src/proof/binding.js';
import type { AdapterResult, SignedProofInput } from '../types.js';
import { inputOf, verify } from './helpers/delegation-vectors.js';

type Members = Record<string, unknown>;
/** A vector's input, as JSON gives it: any member may hold anything. */
type Input = Members & { proof: { jws: string; meta: Members }; publicKeyJwk: Members; expected: Members };
type Verdict = 'bound' | 'no-chain' | 'invalid' | 'request' | 'response' | 'no-signed-form';

// RFC 8032 §7.1, TEST 1: a key pair any implementation can sign the cases with.
const TEST_SECRET_KEY = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex');
const TEST_PUBLIC_KEY = Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex');
const LEFT_OUT = Symbol('left out');

const b64url = (data: string | Uint8Array): string => Buffer.from(data).toString('base64url');
const fromLittleEndian = (bytes: Uint8Array): bigint => BigInt(`0x${Buffer.from(bytes).reverse().toString('hex')}`);
const toLittleEndian = (value: bigint, length: number): Buffer =>
  Buffer.from(value.toString(16).padStart(length * 2, '0'), 'hex').reverse();
const sha256Of = (value: unknown): string => `sha256:${createHash('sha256').update(canonicalize(value)).digest('hex')}`;

/** A copy of `members` with each of `changes` set, or left out where it is LEFT_OUT. */
function set<T extends Members>(members: T, changes: Members): T {
  const altered: Members = structuredClone(members);
  for (const [name, value] of Object.entries(changes)) {
    if (value === LEFT_OUT) delete altered[name];
    else altered[name] = value;
  }
  return altered as T;
}

const key = (vector: Input, changes: Members): Input => ({ ...vector, publicKeyJwk: set(vector.publicKeyJwk, changes) });
const held = (vector: Input, changes: Members): Input => ({ ...vector, expected: set(vector.expected, changes) });
const withJws = (vector: Input, jws: string): Input => ({ ...vector, proof: { ...vector.proof, jws } });
const withMeta = (vector: Input, changes: Members): Input => ({
  ...vector,
  proof: { ...vector.proof, meta: set(vector.proof.meta, changes) },
});

/**
 * The vector's proof with `changes` made to its meta and signed again with the
 * test key, which the verifier is given for the proof's `kid`.
 */
async function signed(vector: Input, changes: Members = {}): Promise<Input> {
  const meta = set(vector.proof.meta, changes);
  const kid = meta['kid'] as string;
  const party = { kid, privateKey: TEST_SECRET_KEY.toString('base64') };
  const { jws } = await signProofMeta(party, meta as never);
  return { ...vector, proof: { jws, meta }, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: b64url(TEST_PUBLIC_KEY), kid } };
}

/** Each case: its name, the vector it is, and the verdict proof_cases.py gives it. */
async function proofCases(bound: Input, bare: Input): Promise<Array<[string, Input, Verdict]>> {
  const { meta } = bound.proof;
  const ts = meta['ts'] as number;
  const [header, payload, signature] = bound.proof.jws.split('.') as [string, string, string];
  const x = bound.publicKeyJwk['x'] as string;
  const request = bound.expected['request'] as Members;
  const params = request['params'] as { name: string; arguments: Members };
  const anotherPayload = b64url(canonicalize(buildProofJwsPayload({ ...meta, nonce: 'nonce-other' } as never)));
  const [identityKey, forged] = [b64url(Buffer.from([1, ...Array(31).fill(0)])), b64url(Buffer.from([1, ...Array(63).fill(0)]))];
  // R = the key and S = 0, which satisfy the verification equation under the
  // key of order two over what `chain-binding` signs (`../small-order.ts`).
  const [orderTwoKey, forgedUnderIt] = [b64url(ORDER_TWO), b64url(Buffer.concat([ORDER_TWO, Buffer.alloc(32)]))];
  const noPoint = b64url(Buffer.from([2, ...Array<number>(31).fill(0)]));
  const signatureBytes = Buffer.from(signature, 'base64url');
  const [r, s] = [signatureBytes.subarray(0, 32), fromLittleEndian(signatureBytes.subarray(32))];
  const with65thByte = b64url(Buffer.concat([r, toLittleEndian(s, 33)]));
  // S + L satisfies the verification equation as S does, so only the refusal
  // of an S that is not below L (RFC 8032 §5.1.7) refuses it.
  const malleated = b64url(Buffer.concat([r, toLittleEndian(s + BASE_POINT_ORDER, 32)]));
  const digestInCapitals = `sha256:${(meta['requestHash'] as string).slice('sha256:'.length).toUpperCase()}`;
  const dataWithMeta = { content: (bound.expected['response'] as Members)['data'], _meta: { note: 'kept' } };
  return [
    // The verifier's clock and skew.
    ['now as far after ts as the skew allows', { ...bound, now: ts + 300 }, 'bound'],
    ['now a second later than the skew allows', { ...bound, now: ts + 301 }, 'invalid'],
    ['now a quarter of a second later than the skew allows', { ...bound, now: ts + 300.25 }, 'invalid'],
    ['now a second earlier than the skew allows', { ...bound, now: ts - 301 }, 'invalid'],
    ['now given as a string', { ...bound, now: String(ts) }, 'invalid'],
    ['skew zero, now at ts', { ...bound, now: ts, skewSeconds: 0 }, 'bound'],
    ['skew negative', { ...bound, now: ts, skewSeconds: -1 }, 'invalid'],
    ['skew that is no finite number', { ...bound, skewSeconds: Infinity }, 'invalid'],
    ['skew left out', set(bound, { skewSeconds: LEFT_OUT }), 'invalid'],
    // The key the proof is checked with.
    ['key x padded to complete its last group', key(bound, { x: `${x}=` }), 'invalid'],
    ['key x with a space inside it', key(bound, { x: `${x.slice(0, 5)} ${x.slice(5)}` }), 'invalid'],
    ['key x with a character outside base64url', key(bound, { x: `${x}*` }), 'invalid'],
    ['key x of 31 bytes', key(bound, { x: b64url(Buffer.from(x, 'base64url').subarray(0, 31)) }), 'invalid'],
    ['key x of 32 bytes that encode no point, no x having y = 2', key(bound, { x: noPoint }), 'invalid'],
    ['key x given as a number', key(bound, { x: 7 }), 'invalid'],
    ['key with no x', key(bound, { x: LEFT_OUT }), 'invalid'],
    ['key named by another kid', key(bound, { kid: `${meta['kid'] as string}-other` }), 'invalid'],
    ['key on another curve', key(bound, { crv: 'X25519' }), 'invalid'],
    ['key of another type', key(bound, { kty: 'EC' }), 'invalid'],
    ['no key', set(bound, { publicKeyJwk: LEFT_OUT }), 'invalid'],
    [
      'key of small order, under which R = identity and S = 0 verify every payload',
      withJws(key(bound, { x: identityKey }), `${header}.${payload}.${forged}`),
      'invalid',
    ],
    [
      'key of order two, under which R = the key and S = 0 verify this payload',
      withJws(key(bound, { x: orderTwoKey }), `${header}.${payload}.${forgedUnderIt}`),
      'invalid',
    ],
    // The JWS as received.
    ['JWS with no payload segment, detached', withJws(bound, `${header}..${signature}`), 'bound'],
    ["JWS whose payload segment is another proof's", withJws(bound, `${header}.${anotherPayload}.${signature}`), 'invalid'],
    ['JWS whose payload segment is not JSON', withJws(bound, `${header}.${b64url('not json')}.${signature}`), 'invalid'],
    ['JWS whose header is a JSON array', withJws(bound, `${b64url('[]')}.${payload}.${signature}`), 'invalid'],
    ['JWS with an empty signature segment', withJws(bound, `${header}.${payload}.`), 'invalid'],
    ['JWS whose signature segment is padded to complete its last group',
      withJws(bound, `${header}.${payload}.${signature}==`), 'invalid'],
    ['JWS whose signature segment holds a line break',
      withJws(bound, `${header}.${payload}.${signature.slice(0, 43)}\n${signature.slice(43)}`), 'invalid'],
    [
      'JWS whose signature has a 65th byte, zero, which leaves S as it is',
      withJws(bound, `${header}.${payload}.${with65thByte}`),
      'invalid',
    ],
    [
      'JWS whose signature has S + L for S, which satisfies the equation as S does',
      withJws(bound, `${header}.${payload}.${malleated}`),
      'invalid',
    ],
    ['JWS given as a number', withJws(bound, 7 as never), 'invalid'],
    ['proof whose meta is null', { ...bound, proof: { ...bound.proof, meta: null as never } }, 'invalid'],
    // JSON.parse reads an integer of 401 digits as Infinity, as Python's float reads 10 ** 400.
    ['proof whose ts is an integer past the largest double', withMeta(bound, { ts: JSON.parse(`1${'0'.repeat(400)}`) }), 'invalid'],
    // The request the verifier sent.
    [
      'request in the legacy shape, the tool its method and the arguments its params',
      held(bound, { request: { method: params.name, params: params.arguments } }),
      'bound',
    ],
    [
      'request with params._meta and a control argument, which the hash leaves out',
      held(bound, {
        request: {
          method: 'tools/call',
          params: { ...params, _meta: { progressToken: 1 }, arguments: { ...params.arguments, _kyaos_delegation: 'a credential' } },
        },
      }),
      'bound',
    ],
    [
      'request with another argument',
      held(bound, { request: { ...request, params: { ...params, arguments: { recordId: 'r-2' } } } }),
      'request',
    ],
    [
      'request whose arguments are an array',
      held(bound, { request: { ...request, params: { ...params, arguments: ['r-1'] } } }),
      'request',
    ],
    ['request that is no object', held(bound, { request: 'tools/call' }), 'invalid'],
    ['request left out', held(bound, { request: LEFT_OUT }), 'invalid'],
    ...([['null', null], ['0', 0], ['an empty string', ''], ['false', false]] as const).map(
      ([written, value]): [string, Input, Verdict] => [
        `request without params, given as ${written}`,
        held(bare, { request: { method: 'tools/call', params: value } }),
        'bound',
      ],
    ),
    [
      'request without params, given as an empty object',
      held(bare, { request: { method: 'tools/call', params: {} } }),
      'request',
    ],
    ['request whose params is a number', held(bare, { request: { method: 'tools/call', params: 7 } }), 'request'],
    // The response the verifier received, and what it asks.
    ['response left out', held(bound, { response: LEFT_OUT }), 'response'],
    ['response held, of a proof that binds none', await signed(bound, { responseHash: LEFT_OUT }), 'response'],
    [
      'response with other data',
      held(bound, { response: { data: [{ type: 'text', text: 'released r-2' }] } }),
      'response',
    ],
    [
      'response data an object with _meta, which the body profile hashes as it is',
      held(await signed(bound, { responseHash: sha256Of(dataWithMeta) }), { response: { data: dataWithMeta } }),
      'bound',
    ],
    ['response given as null', held(bound, { response: null }), 'invalid'],
    ['response with no data', held(bound, { response: {} }), 'invalid'],
    ['outcome asked for, allowed, as the proof records', held(bound, { outcome: 'allowed' }), 'bound'],
    ['nothing held of the call, so nothing is compared', set(bound, { expected: LEFT_OUT }), 'no-chain'],
    ['what is held of the call given as null', { ...bound, expected: null as never }, 'invalid'],
    // The chain the verifier holds.
    ['chain held as an empty array, which no proof binds', held(bound, { delegationChain: [] }), 'no-signed-form'],
    ['chain held as a number, which no proof binds', held(bound, { delegationChain: 7 }), 'no-signed-form'],
    // The claims, each signed again with the test key.
    ['signed again with the test key, and checked with it', await signed(bound), 'bound'],
    ['kid relative to meta.did', await signed(bound, { kid: '#key-1' }), 'bound'],
    ['kid empty', await signed(bound, { kid: '' }), 'invalid'],
    ['ts with a fraction', await signed(bound, { ts: ts + 0.5 }), 'invalid'],
    ['ts zero, checked at time zero', { ...(await signed(bound, { ts: 0 })), now: 0 }, 'invalid'],
    ['ts one, checked at time one', { ...(await signed(bound, { ts: 1 })), now: 1 }, 'bound'],
    ['ts given as true, checked at time one', { ...(await signed(bound, { ts: true })), now: 1 }, 'invalid'],
    ['ts given as a string', await signed(bound, { ts: String(ts) }), 'invalid'],
    ['did empty, with a relative kid', await signed(bound, { did: '', kid: '#key-1' }), 'invalid'],
    ['nonce empty', await signed(bound, { nonce: '' }), 'invalid'],
    ['audience empty', await signed(bound, { audience: '' }), 'invalid'],
    ['sessionId empty', await signed(bound, { sessionId: '' }), 'invalid'],
    ['requestHash in capitals', await signed(bound, { requestHash: digestInCapitals }), 'invalid'],
    ['responseHash one digit short', await signed(bound, { responseHash: `sha256:${'0'.repeat(63)}` }), 'invalid'],
    [
      'delegationChainDigest with a capital',
      await signed(bound, { delegationChainDigest: `sha256:${'0'.repeat(63)}A` }),
      'invalid',
    ],
    ['delegationRef given as a number', await signed(bound, { delegationRef: 7 }), 'invalid'],
    ['scopeId empty, which is not signed', await signed(bound, { scopeId: '' }), 'bound'],
    ['scopeId given, which is signed', await signed(bound, { scopeId: 'scope-1' }), 'bound'],
    ['scopeId given as null', await signed(bound, { scopeId: null }), 'invalid'],
    ['clientDid given, which is signed', await signed(bound, { clientDid: 'did:web:client.example' }), 'bound'],
    ['clientDid given as a number', await signed(bound, { clientDid: 7 }), 'invalid'],
    ['reason given, which is signed', await signed(bound, { reason: 'within the delegated slice' }), 'bound'],
    ['reason given as a number', await signed(bound, { reason: 7 }), 'invalid'],
    ['outcome given, allowed, which is signed', await signed(bound, { outcome: 'allowed' }), 'bound'],
    ['outcome given as null', await signed(bound, { outcome: null }), 'invalid'],
    ['outcome that is none of the four', await signed(bound, { outcome: 'Allowed' }), 'invalid'],
    [
      'prf of the envelope profile, which is signed',
      await signed(bound, { prf: 'org.kya-os/response-proof.envelope' }),
      'bound',
    ],
    ['prf of a profile no verifier knows', await signed(bound, { prf: 'org.example/unknown-profile' }), 'invalid'],
    ['member the proof schema does not name', await signed(bound, { note: 'x' }), 'bound'],
  ];
}

/**
 * What the reference adapter reports a verification that fails on the
 * request, on the response, or on a chain that has no digest, which it
 * reports as any chain the proof does not bind.
 */
const BINDING_REASONS: Record<'request' | 'response' | 'no-signed-form', readonly string[]> = {
  request: [bindingFailure({ binding: 'request' }).reason],
  response: (['response', 'response-missing', 'response-unexpected'] as const).map(
    (binding) => bindingFailure({ binding }).reason,
  ),
  'no-signed-form': [bindingFailure({ binding: 'delegation-chain' }).reason],
};

/** Whether the adapter's result is `verdict`: a pass, a failure on what the verdict names, or a failure before any. */
function hasVerdict(result: AdapterResult, verdict: Verdict): boolean {
  if (verdict === 'bound' || verdict === 'no-chain') return result.outcome === 'pass' && result.detail === undefined;
  if (result.outcome !== 'fail') return false;
  if (verdict !== 'invalid') return BINDING_REASONS[verdict].includes(result.detail!);
  return !Object.values(BINDING_REASONS).flat().includes(result.detail!);
}

describe('the cases conformance/proof_cases.py holds the Python verifier to', () => {
  const bound = inputOf('chain-binding') as unknown as Input;
  const bare = inputOf('proof-request-without-params') as unknown as Input;

  it('start from a vector that binds, and one whose request has no params', async () => {
    expect(await verify(bound as unknown as SignedProofInput)).toEqual({ outcome: 'pass' });
    expect(await verify(bare as unknown as SignedProofInput)).toEqual({ outcome: 'pass' });
    expect(bare.expected['request']).toEqual({ method: 'tools/call' });
  });

  it('each have the verdict the Python verifier reaches', async () => {
    const cases = await proofCases(bound, bare);
    const missed: string[] = [];
    for (const [name, input, verdict] of cases) {
      const result = await verify(input as unknown as SignedProofInput);
      if (!hasVerdict(result, verdict)) missed.push(`${name}: ${result.outcome} (${result.detail ?? 'no detail'}), not ${verdict}`);
    }
    expect(missed).toEqual([]);
    expect(cases).toHaveLength(86);
  });

  it('refuse a clock or a skew given as anything but a number, and the reference says so', async () => {
    for (const changes of [{ now: String(bound['now']) }, { skewSeconds: String(bound['skewSeconds']) }]) {
      expect(await verify({ ...bound, ...changes } as unknown as SignedProofInput)).toEqual({
        outcome: 'fail',
        detail: 'a signed-proof vector gives now and skewSeconds as numbers',
      });
    }
  });
});
