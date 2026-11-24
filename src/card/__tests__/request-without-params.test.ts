/**
 * The covered request of a call that has no params (SPEC-ENTITY-CARD §8.3).
 *
 * The proof rides `params._meta`, so the call a verifier holds always has `params`, and with `_meta`
 * removed that is an empty object. The covered request is read from that form alone: `params` that
 * are absent, `null`, or empty once `_meta` is removed are left out, and the call is `{ method }`.
 * For the 1.x line a verifier also accepts a proof over `{ method, params: {} }`, which a 1.x client
 * signs for a call given `params: {}`, as 1.26.0 did, so that 1.26.0 verifiers keep accepting it.
 */
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { statementParameters } from '../../delegation/stated-delegation.js';
import { webCryptoSha256 } from '../../utils/domain-digest.js';
import {
  buildCardProof,
  computeRequestHash,
  requireProof,
  verifyCardProof,
  type CardProofMeta,
  type ProofSigner,
} from '../index.js';
import { canonicalPayloadBytes } from '../proof/canonical.js';
import { AUD, DID, KID, NONCE, PROOF_KEY, T0, clock, deps, keypair } from './proof-helpers.js';

const LIST = { method: 'tools/list' };

/** A proof whose `requestHash` is over `{ method, params: {} }`, as 1.26.0 minted it for a call given `params: {}`. */
async function mintedOverEmptyParams(method: string, signer: ProofSigner): Promise<CardProofMeta> {
  const digest = createHash('sha256').update(JSON.stringify({ method, params: {} })).digest('base64');
  const created = Math.floor(T0 / 1000);
  const unsigned: CardProofMeta = {
    prf: 'org.kya-os/proof.v1',
    alg: 'EdDSA',
    did: DID,
    kid: KID,
    audience: AUD,
    nonce: NONCE,
    created,
    expires: created + 30,
    requestHash: `sha-256=:${digest}:`,
    ...(signer.jkt !== undefined ? { cnf: { jkt: signer.jkt } } : {}),
    jws: '',
  };
  const stated = await statementParameters(undefined, undefined, webCryptoSha256);
  return { ...unsigned, jws: await signer.sign(canonicalPayloadBytes(unsigned), stated) };
}

/** The Content-Digest form of SHA-256 over `request`, whose keys are already in JCS order. */
const digestOf = (request: object): string =>
  `sha-256=:${createHash('sha256').update(JSON.stringify(request)).digest('base64')}:`;

describe('what a 1.x client signs for a call with no params', () => {
  it('signs the method alone when params is absent or null, as 1.26.0 did', async () => {
    expect(await computeRequestHash(LIST)).toBe(digestOf(LIST));
    expect(await computeRequestHash({ ...LIST, params: null })).toBe(digestOf(LIST));
  });

  it('signs { method, params: {} } when given params with no member but _meta, as 1.26.0 did, so its verifiers keep accepting it', async () => {
    for (const params of [{}, { _meta: { progressToken: 7 } }]) {
      expect(await computeRequestHash({ ...LIST, params })).toBe(digestOf({ ...LIST, params: {} }));
    }
  });
});

describe('the covered request of a call with no params', () => {
  it('keeps params that hold a member beside _meta, even an empty one', async () => {
    const withCursor = await computeRequestHash({ ...LIST, params: { cursor: '', _meta: { progressToken: 7 } } });
    expect(withCursor).not.toBe(await computeRequestHash(LIST));
  });

  it('verifies a proof minted for the call against the call as it travels, with the proof in params._meta', async () => {
    const { signer, publicJwk } = await keypair();
    const carried = await buildCardProof(LIST, signer, { audience: AUD, nonce: NONCE, now: clock });
    const wire = { ...LIST, params: { _meta: { ...carried } } };
    const result = await verifyCardProof(carried[PROOF_KEY], wire, deps(publicJwk));
    expect(result.reasons).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it('passes the proof alike whether the host hands the guard the call as it travels, empty params, or none', async () => {
    const { signer, publicJwk } = await keypair();
    const carried = await buildCardProof({ ...LIST, params: {} }, signer, { audience: AUD, nonce: NONCE, now: clock });
    const guard = requireProof(deps(publicJwk));
    expect((await guard({ ...LIST, params: { _meta: { ...carried } } }, carried)).ok).toBe(true);
    expect((await guard({ ...LIST, params: {} }, carried)).ok).toBe(true);
    expect((await guard(LIST, carried)).ok).toBe(true);
  });
});

describe('for the 1.x line, a proof over { method, params: {} }', () => {
  it('verifies against the call as it travels and against the call with no params', async () => {
    const { signer, publicJwk } = await keypair();
    const proof = await mintedOverEmptyParams(LIST.method, signer);
    const wire = { ...LIST, params: { _meta: { [PROOF_KEY]: proof } } };
    expect((await verifyCardProof(proof, wire, deps(publicJwk))).reasons).toEqual([]);
    expect((await verifyCardProof(proof, LIST, deps(publicJwk))).reasons).toEqual([]);
  });

  it('is refused for a call whose params hold a member', async () => {
    const { signer, publicJwk } = await keypair();
    const proof = await mintedOverEmptyParams(LIST.method, signer);
    const result = await verifyCardProof(proof, { ...LIST, params: { cursor: 'c-2' } }, deps(publicJwk));
    expect(result.reasons).toEqual(['request_hash_mismatch']);
  });

  it('is refused for a call to another method', async () => {
    const { signer, publicJwk } = await keypair();
    const proof = await mintedOverEmptyParams('prompts/list', signer);
    const result = await verifyCardProof(proof, LIST, deps(publicJwk));
    expect(result.reasons).toEqual(['request_hash_mismatch']);
  });
});
