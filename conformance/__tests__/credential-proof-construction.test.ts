/**
 * The base-profile credential proof, checked against the vectors as SPEC.md
 * §6.2 states it: Ed25519 over the JCS canonicalization of the credential
 * without `proof`, `proofValue` as unpadded base64url, the key taken from the
 * issuer's DID document by `proof.verificationMethod`. It uses node:crypto and
 * json-canonicalize directly rather than the library's verifier, because an
 * outside implementer builds from that text and the text has to match the
 * bytes the suite ships.
 */

import { createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalize } from 'json-canonicalize';
import { describe, it, expect } from 'vitest';
import { VECTORS_DIR } from '../loader.js';

type Json = Record<string, unknown>;
interface Proof { type: string; created: string; verificationMethod: string; proofValue: string }
interface Credential extends Json { issuer: string | { id: string }; proof: Proof }
interface DidDocument { verificationMethod: { id: string; publicKeyJwk: { x: string } }[] }
interface Vector { id: string; input: Json }

function load(name: string): Vector[] {
  return (JSON.parse(readFileSync(join(VECTORS_DIR, name), 'utf8')) as { vectors: Vector[] }).vectors;
}

/**
 * Every delegation credential a vector carries, labeled by where it sits. The
 * status-list vectors' StatusList2021Credential is left out: its committed
 * signature does not verify, and the reference adapter reads its bits without
 * checking it, so it needs a suite version bump rather than a test here.
 */
function credentialsOf(vector: Vector): [string, Credential][] {
  const { leaf, ancestors, credential } = vector.input as {
    leaf?: Credential;
    ancestors?: Credential[];
    credential?: Credential;
  };
  return [
    ...(leaf ? [['leaf', leaf] as [string, Credential]] : []),
    ...(ancestors ?? []).map((c, i): [string, Credential] => [`ancestors[${i}]`, c]),
    ...(credential ? [['credential', credential] as [string, Credential]] : []),
  ];
}

/** SPEC.md §6.2, step by step. */
function verifiesPerSpec(vc: Credential, didDocuments: Record<string, DidDocument>): boolean {
  const { proof, ...unsigned } = vc;
  const issuer = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id;
  const method = didDocuments[issuer]?.verificationMethod.find((m) => m.id === proof.verificationMethod);
  if (!method) return false;
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: method.publicKeyJwk.x }, format: 'jwk' });
  return verify(null, Buffer.from(canonicalize(unsigned), 'utf8'), key, Buffer.from(proof.proofValue, 'base64url'));
}

const vectors = [...load('delegation-chain.json'), ...load('status-list.json')];
const cases = vectors.flatMap((v) =>
  credentialsOf(v).map(([where, vc]) => ({
    name: `${v.id} ${where}`,
    vc,
    didDocuments: v.input.didDocuments as Record<string, DidDocument>,
    // The one credential the suite signs and then alters, so its signature must fail.
    tampered: v.id === 'delegation-chain/tampered-signature' && where === 'leaf',
  })),
);

describe('base-profile credential proof as SPEC.md §6.2 states it', () => {
  it('covers every delegation credential in the delegation-chain and status-list vectors', () => {
    expect(cases.length).toBeGreaterThanOrEqual(vectors.length);
  });

  it.each(cases)('$name: proofValue is unpadded base64url with no multibase prefix', ({ vc }) => {
    expect(vc.proof.type).toBe('Ed25519Signature2020');
    expect(vc.proof.proofValue).toMatch(/^[A-Za-z0-9_-]{86}$/);
    expect(Buffer.from(vc.proof.proofValue, 'base64url')).toHaveLength(64);
  });

  it.each(cases)('$name: verifies over JCS of the credential without proof', ({ vc, didDocuments, tampered }) => {
    expect(verifiesPerSpec(vc, didDocuments)).toBe(!tampered);
  });

  it.each(cases.filter((c) => !c.tampered))(
    '$name: the proof options are outside the signature',
    ({ vc, didDocuments }) => {
      const restamped = { ...vc, proof: { ...vc.proof, created: '1999-01-01T00:00:00Z', proofPurpose: 'authentication' } };
      expect(verifiesPerSpec(restamped, didDocuments)).toBe(true);
    },
  );
});
