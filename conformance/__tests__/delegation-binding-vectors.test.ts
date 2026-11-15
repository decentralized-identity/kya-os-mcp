/**
 * The `signed-proof/delegation-*` vectors (suite 1.5.0) each have to turn on
 * one rule of SPEC.md §7.8 and nothing else: a negative one that failed for a
 * broken signature or a stale timestamp would pass an implementation that
 * never looks at the chain, the outcome or the reference, and a chain of
 * credentials nobody signed would say nothing about signed forms.
 */

import { decodeJwt } from 'jose';
import { describe, it, expect } from 'vitest';
import { delegationCredentialId, delegationRefOf } from '../../src/delegation/delegation-ref.js';
import { NoSignedFormError, signedForm } from '../../src/delegation/signed-form.js';
import {
  type Credential,
  byId,
  chainOf,
  crypto,
  digestOf,
  hash,
  inputOf,
  issuerSigned,
  proofOf,
  verify,
} from './helpers/delegation-vectors.js';

describe('signed-proof/delegation-chain-* vectors', () => {
  it('bind a chain of two credential objects and a VC-JWT leaf, each signed by its issuer', async () => {
    const chain = chainOf('chain-binding');
    expect(chain.map((credential) => typeof credential)).toEqual(['object', 'object', 'string']);
    for (const credential of chain) expect(await issuerSigned(credential)).toBe(true);
    expect(proofOf('chain-binding').meta.delegationChainDigest).toBe(await digestOf(chain));
    expect(byId('chain-binding').expected).toBe('pass');
  });

  it('reserialized: another copy of the same signed credentials, accepted', async () => {
    expect(proofOf('chain-reserialized')).toEqual(proofOf('chain-binding'));
    const bound = chainOf('chain-binding');
    const copy = chainOf('chain-reserialized');
    // No credential is written as its counterpart is...
    copy.forEach((credential, hop) => expect(credential).not.toEqual(bound[hop]));
    // ...and each has the same signed form: the same signed content and the
    // same signature bytes, under other proof metadata and other encodings.
    copy.forEach((credential, hop) => expect(signedForm(credential)).toEqual(signedForm(bound[hop]!)));
    const [root, middle, leaf] = copy as [Exclude<Credential, string>, Exclude<Credential, string>, string];
    const [boundRoot, boundMiddle, boundLeaf] = bound as [Exclude<Credential, string>, Exclude<Credential, string>, string];
    expect(root.proof.created).not.toBe(boundRoot.proof.created);
    expect(root.proof).toHaveProperty('note');
    expect(String(root.proof.proofValue)).toMatch(/==$/);
    expect(String(middle.proof.proofValue)).toContain('\n');
    expect(String(middle.proof.proofValue).replace('\n', '')).not.toBe(boundMiddle.proof.proofValue);
    expect(leaf.slice(0, leaf.lastIndexOf('.'))).toBe(boundLeaf.slice(0, boundLeaf.lastIndexOf('.')));
    expect(leaf).not.toBe(boundLeaf);

    expect(await digestOf(copy)).toBe(await digestOf(bound));
    expect((await verify(inputOf('chain-reserialized'))).outcome).toBe('pass');
  });

  it('refused: a denial binds the chain it refused and no response, and verifies for a verifier that asks for a refusal', async () => {
    const { meta } = proofOf('chain-refused');
    expect(meta.outcome).toBe('denied');
    expect(meta.responseHash).toBeUndefined();
    expect(inputOf('chain-refused').expected!.response).toBeUndefined();
    expect(inputOf('chain-refused').expected!.outcome).toBe('denied');
    expect(meta.delegationChainDigest).toBe(await digestOf(chainOf('chain-refused')));
    expect(byId('chain-refused').expected).toBe('pass');
    expect((await verify(inputOf('chain-refused'))).outcome).toBe('pass');
  });

  it('refused-outcome-unstated: the same refusal and chain, rejected only because no outcome was asked for', async () => {
    expect(proofOf('chain-refused-outcome-unstated')).toEqual(proofOf('chain-refused'));
    const { outcome, ...unstated } = inputOf('chain-refused').expected!;
    expect(outcome).toBe('denied');
    expect(inputOf('chain-refused-outcome-unstated').expected).toEqual(unstated);
    expect(byId('chain-refused-outcome-unstated').expected).toBe('fail');

    const result = await verify(inputOf('chain-refused-outcome-unstated'));
    expect(result.outcome).toBe('fail');
    expect(result.detail).toMatch(/Outcome mismatch/);
    // Without the chain nothing is asked of the outcome.
    const { delegationChain: _chain, ...content } = unstated;
    expect((await verify({ ...inputOf('chain-refused-outcome-unstated'), expected: content })).outcome).toBe('pass');
  });

  it('substituted: the same proof and ids, one credential really re-issued, rejected on the digest alone', async () => {
    expect(proofOf('chain-substituted')).toEqual(proofOf('chain-binding'));
    const bound = chainOf('chain-binding');
    const substituted = chainOf('chain-substituted');
    const idOf = (credential: Credential) =>
      typeof credential === 'string' ? credential : `${credential.id} ${credential.credentialSubject.delegation.id}`;
    expect(substituted.map(idOf)).toEqual(bound.map(idOf));
    expect(substituted[1]).not.toEqual(bound[1]);
    // The replacement is a genuine credential from the same issuer.
    expect(await issuerSigned(substituted[1]!)).toBe(true);

    const result = await verify(inputOf('chain-substituted'));
    expect(result.outcome).toBe('fail');
    expect(result.detail).toMatch(/Delegation chain digest mismatch/);
    // Without the chain the same proof verifies: nothing else is wrong with it.
    const { delegationChain: _chain, ...rest } = inputOf('chain-substituted').expected!;
    expect((await verify({ ...inputOf('chain-substituted'), expected: rest })).outcome).toBe('pass');
  });

  it('digest-stripped: differs from the bound proof only by the missing claim, rejected on the signature', async () => {
    const { delegationChainDigest, ...rest } = proofOf('chain-binding').meta;
    expect(delegationChainDigest).toBeDefined();
    expect(proofOf('chain-digest-stripped')).toEqual({ jws: proofOf('chain-binding').jws, meta: rest });

    const result = await verify(inputOf('chain-digest-stripped'));
    expect(result.outcome).toBe('fail');
    expect(result.detail).toMatch(/Invalid JWS signature/);
  });

  it('unbound: an authentic proof that only names its credential, rejected because a chain was asked for', async () => {
    const { meta } = proofOf('chain-unbound');
    expect(meta.delegationRef).toBe(proofOf('chain-binding').meta.delegationRef);
    expect(meta.delegationChainDigest).toBeUndefined();

    const result = await verify(inputOf('chain-unbound'));
    expect(result.outcome).toBe('fail');
    expect(result.detail).toMatch(/binds none/);
    const { delegationChain: _chain, ...rest } = inputOf('chain-unbound').expected!;
    expect((await verify({ ...inputOf('chain-unbound'), expected: rest })).outcome).toBe('pass');
  });

  it('no-signed-form: the bound chain with its VC-JWT signature in the other base64 alphabet, which is no JWS and has no digest', async () => {
    expect(proofOf('chain-no-signed-form')).toEqual(proofOf('chain-binding'));
    const bound = chainOf('chain-binding');
    const rewritten = chainOf('chain-no-signed-form');
    expect(rewritten.slice(0, 2)).toEqual(bound.slice(0, 2));
    const [boundLeaf, leaf] = [bound[2] as string, rewritten[2] as string];
    // The same three segments, the last spelled with + and / where base64url has - and _.
    const signature = leaf.slice(leaf.lastIndexOf('.') + 1);
    expect(leaf.slice(0, leaf.lastIndexOf('.'))).toBe(boundLeaf.slice(0, boundLeaf.lastIndexOf('.')));
    expect(signature).toMatch(/[+/]/);
    expect(signature.replace(/\+/g, '-').replace(/\//g, '_')).toBe(boundLeaf.slice(boundLeaf.lastIndexOf('.') + 1));
    expect(() => signedForm(leaf)).toThrow(NoSignedFormError);
    expect(await issuerSigned(leaf)).toBe(false);

    const result = await verify(inputOf('chain-no-signed-form'));
    expect(byId('chain-no-signed-form').expected).toBe('fail');
    expect(result.outcome).toBe('fail');
    expect(result.detail).toMatch(/Delegation chain digest mismatch/);
  });

  it('name the leaf credential of the chain they bind', async () => {
    const leaf = chainOf('chain-binding')[2] as string;
    const claims = decodeJwt<{ vc: { id: string } }>(leaf);
    expect(proofOf('chain-binding').meta.delegationRef).toBe(claims.vc.id);
    expect(proofOf('chain-binding').meta.delegationRef).toBe(await delegationRefOf(leaf, hash));
  });
});

describe('signed-proof/delegation-ref-* vectors', () => {
  it('substituted: an authentic proof of the bound chain that names its root, rejected on the reference alone', async () => {
    const { meta } = proofOf('ref-substituted');
    const chain = chainOf('ref-substituted');
    expect(chain).toEqual(chainOf('chain-binding'));
    // The digest is the chain's, so only the name is wrong.
    expect(meta.delegationChainDigest).toBe(await digestOf(chain));
    expect(meta.delegationRef).toBe(delegationCredentialId(chain[0]));
    expect(meta.delegationRef).not.toBe(await delegationRefOf(chain[2], hash));
    expect(byId('ref-substituted').expected).toBe('fail');

    const result = await verify(inputOf('ref-substituted'));
    expect(result.outcome).toBe('fail');
    expect(result.detail).toMatch(/Delegation reference mismatch/);
    // Without the chain the same proof verifies: it is signed as it stands.
    const { delegationChain: _chain, ...rest } = inputOf('ref-substituted').expected!;
    expect((await verify({ ...inputOf('ref-substituted'), expected: rest })).outcome).toBe('pass');
  });

  it('digest-form: a credential whose id is too long to record is named by the digest of the id', async () => {
    const { meta } = proofOf('ref-digest-form');
    const chain = chainOf('ref-digest-form');
    expect(chain).toHaveLength(1);
    const [credential] = chain as [Exclude<Credential, string>];
    expect(await issuerSigned(credential)).toBe(true);
    const id = delegationCredentialId(credential)!;
    expect(id).toBe(credential.id);
    expect(id.length).toBeGreaterThan(256);
    expect(meta.delegationRef).toBe(await crypto.hash(new TextEncoder().encode(id)));
    expect(meta.delegationRef).toBe(await delegationRefOf(credential, hash));
    expect(meta.delegationChainDigest).toBe(await digestOf(chain));
    expect(byId('ref-digest-form').expected).toBe('pass');
    expect((await verify(inputOf('ref-digest-form'))).outcome).toBe('pass');
  });

  /** The one credential object a vector binds, checked as its issuer signed it and bound by the proof. */
  async function boundAlone(id: string): Promise<Exclude<Credential, string>> {
    const chain = chainOf(id);
    expect(chain).toHaveLength(1);
    const [credential] = chain as [Exclude<Credential, string>];
    expect(await issuerSigned(credential)).toBe(true);
    expect(proofOf(id).meta.delegationChainDigest).toBe(await digestOf(chain));
    expect(byId(id).expected).toBe('pass');
    expect((await verify(inputOf(id))).outcome).toBe('pass');
    return credential;
  }

  it('control-at-bound: a credential whose id is U+001F alone, the last C0 control, is named by the digest of the id', async () => {
    const credential = await boundAlone('ref-control-at-bound');
    expect(credential.id).toBe('\u001f');
    const { meta } = proofOf('ref-control-at-bound');
    expect(meta.delegationRef).toBe(await crypto.hash(new TextEncoder().encode('\u001f')));
    expect(meta.delegationRef).toBe(await delegationRefOf(credential, hash));
  });

  it('control-past-bound: a credential whose id is U+0020 alone, the first character past C0, is named by the id', async () => {
    const credential = await boundAlone('ref-control-past-bound');
    expect(credential.id).toBe(' ');
    expect(proofOf('ref-control-past-bound').meta.delegationRef).toBe(' ');
    expect(await delegationRefOf(credential, hash)).toBe(' ');
  });

  it.each([
    ['ref-bidi-override', 'a right-to-left override', 'urn:uuid:del-\u202egnp.exe'],
    ['ref-zero-width', 'a zero-width space', 'urn:uuid:del-\u200b1'],
    // Code points that are in the table only as rendering as nothing by default, one of each run.
    ['ref-grapheme-joiner', 'a combining grapheme joiner', 'urn:uuid:del-\u034f1'],
    ['ref-hangul-filler', 'a Hangul filler', 'urn:uuid:del-\u31641'],
    ['ref-variation-selector', 'a variation selector', 'urn:uuid:del-\ufe0f1'],
    ['ref-variation-selector-supplement', 'a variation selector outside the basic plane', 'urn:uuid:del-\u{e0100}1'],
  ])('%s: a credential whose id holds %s, which does not print as itself, is named by the digest of the id', async (name, _what, id) => {
    const credential = await boundAlone(name);
    expect(credential.id).toBe(id);
    expect(proofOf(name).meta.delegationRef).toBe(await crypto.hash(new TextEncoder().encode(id)));
    expect(await delegationRefOf(credential, hash)).toBe(proofOf(name).meta.delegationRef);
  });

  it('unknown: a credential whose id is the word an audit record names a credential with no id by is named by its digest', async () => {
    const credential = await boundAlone('ref-unknown');
    expect(credential.id).toBe('unknown');
    expect(proofOf('ref-unknown').meta.delegationRef).toBe(await crypto.hash(new TextEncoder().encode('unknown')));
    expect(await delegationRefOf(credential, hash)).toBe(proofOf('ref-unknown').meta.delegationRef);
  });

  it('digest-form-suffixed: an id one character longer than the digest form is named by the id itself', async () => {
    const credential = await boundAlone('ref-digest-form-suffixed');
    expect(credential.id).toMatch(/^sha256:[0-9a-f]{64}.$/);
    expect(proofOf('ref-digest-form-suffixed').meta.delegationRef).toBe(credential.id);
    expect(await delegationRefOf(credential, hash)).toBe(credential.id);
    // Without its last character the id is of the digest form, and is named by a digest.
    expect(await delegationRefOf({ ...credential, id: credential.id!.slice(0, -1) }, hash)).not.toBe(credential.id!.slice(0, -1));
  });

  it('jwt-long-number: a refusal binds a VC-JWT whose payload holds an integer of 4301 digits, named by its id', async () => {
    const chain = chainOf('ref-jwt-long-number');
    expect(chain).toHaveLength(1);
    const [jwt] = chain as [string];
    const payload = Buffer.from(jwt.split('.')[1]!, 'base64url').toString('utf8');
    expect(payload).toMatch(/"n":1{4301}\}$/);
    const claims = JSON.parse(payload) as { vc: { id: string }; n: number };
    expect(claims.n).toBe(Infinity);
    // Its payload was changed after it was signed, which is why the server refused it.
    expect(await issuerSigned(jwt)).toBe(false);

    const { meta } = proofOf('ref-jwt-long-number');
    expect(meta.outcome).toBe('denied');
    expect(meta.responseHash).toBeUndefined();
    expect(meta.delegationRef).toBe(claims.vc.id);
    expect(meta.delegationRef).toBe(await delegationRefOf(jwt, hash));
    expect(meta.delegationChainDigest).toBe(await digestOf(chain));
    expect(inputOf('ref-jwt-long-number').expected!.outcome).toBe('denied');
    expect(byId('ref-jwt-long-number').expected).toBe('pass');
    expect((await verify(inputOf('ref-jwt-long-number'))).outcome).toBe('pass');
  });

  it('jwt-duplicate-id: a refusal binds a VC-JWT whose payload holds the credential id twice, named by the last', async () => {
    const chain = chainOf('ref-jwt-duplicate-id');
    expect(chain).toHaveLength(1);
    const [jwt] = chain as [string];
    const [header, payload, signature] = jwt.split('.') as [string, string, string];
    const claims = Buffer.from(payload, 'base64url').toString('utf8');
    // Another id written ahead of the issuer's, and nothing else: without it
    // this is the VC-JWT its issuer signed.
    const written = '"vc":{"id":"urn:uuid:del-jwt-duplicate-id-first",';
    expect(claims.split(written)).toHaveLength(2);
    expect(claims.split('"id":"urn:uuid:del-jwt-duplicate-id"')).toHaveLength(2);
    const issued = `${header}.${Buffer.from(claims.replace(written, '"vc":{'), 'utf8').toString('base64url')}.${signature}`;
    expect(await issuerSigned(issued)).toBe(true);
    expect(await issuerSigned(jwt)).toBe(false);

    const { meta } = proofOf('ref-jwt-duplicate-id');
    expect(meta.outcome).toBe('denied');
    expect(meta.responseHash).toBeUndefined();
    expect(meta.delegationRef).toBe('urn:uuid:del-jwt-duplicate-id');
    expect(meta.delegationRef).toBe(await delegationRefOf(jwt, hash));
    expect(meta.delegationRef).toBe(await delegationRefOf(issued, hash));
    expect(meta.delegationChainDigest).toBe(await digestOf(chain));
    expect(inputOf('ref-jwt-duplicate-id').expected!.outcome).toBe('denied');
    expect(byId('ref-jwt-duplicate-id').expected).toBe('pass');
    expect((await verify(inputOf('ref-jwt-duplicate-id'))).outcome).toBe('pass');
  });
});
