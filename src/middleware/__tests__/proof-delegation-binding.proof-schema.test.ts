/**
 * The published proof schema admits the claims a proof may make of its
 * delegation (SPEC.md §7.8): `delegationRef`, and `delegationChainDigest` in
 * the `sha256:<hex>` form and no other.
 */
import { readFileSync } from 'node:fs';
import { Ajv2020, type AnySchema } from 'ajv/dist/2020.js';
import { describe, it, expect } from 'vitest';
import { makeServer } from './helpers/delegation-gate-server.js';
import { ARGS, CONSENT, SCOPE, TOOL, released } from './helpers/delegated-call.js';
import { chainDigestOf, threeHops } from './helpers/delegation-chains.js';
import { proofOf } from './helpers/received-proof.js';

describe('the published proof schema', () => {
  const schema = JSON.parse(
    readFileSync(new URL('../../../schemas/detached-proof.json', import.meta.url), 'utf8'),
  ) as AnySchema;
  const conforms = new Ajv2020({ strict: false }).compile(schema);

  /** An allowed and a refused proof of a delegated call, as the server signs them. */
  async function proofs() {
    const { kyaos, server, ancestors } = await makeServer();
    const { root, middle, leaf, chain } = await threeHops(server.did);
    const widened = await threeHops(server.did, [SCOPE, 'records:delete']);
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));
    ancestors.push(root, middle);
    const allowed = proofOf(await handler({ ...ARGS, _kyaos_delegation: leaf }))!;
    ancestors.splice(0, ancestors.length, widened.root, widened.middle);
    const refused = proofOf(await handler({ ...ARGS, _kyaos_delegation: widened.leaf }))!;
    return { allowed, refused, reference: leaf.id, digest: await chainDigestOf(chain) };
  }

  it('admits the proofs the server signs, allowed and refused, and the same proofs with both delegation claims', async () => {
    const { allowed, refused, reference, digest } = await proofs();

    for (const proof of [allowed, refused]) {
      expect(conforms(proof), JSON.stringify(conforms.errors)).toBe(true);
      const claimed = { ...proof, meta: { ...proof.meta, delegationRef: reference, delegationChainDigest: digest } };
      expect(conforms(claimed), JSON.stringify(conforms.errors)).toBe(true);
    }
  });

  it('rejects a chain digest that is not a sha256 digest', async () => {
    const { allowed, digest } = await proofs();

    for (const written of ['urn:uuid:leaf', digest.toUpperCase(), digest.slice(0, -1), `sha512:${digest.slice(7)}`]) {
      expect(conforms({ ...allowed, meta: { ...allowed.meta, delegationChainDigest: written } })).toBe(false);
    }
  });
});
