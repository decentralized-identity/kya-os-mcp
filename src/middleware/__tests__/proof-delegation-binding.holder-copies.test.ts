/**
 * The gate decides on the credential its issuer signed: whatever a holder
 * does to its copy of a credential, and however a VC-JWT's signature segment
 * is written, a copy is allowed or refused as the issuer's own copy is, and
 * the audit trail records it under the issuer's reference (SPEC.md §7.8).
 */
import { afterEach, describe, it, expect, vi } from 'vitest';
import { DelegationCredentialVerifier } from '../../delegation/vc-verifier.js';
import type { DelegationCredential } from '../../types/protocol.js';
import { UNENCODABLE_DELEGATION_REASON } from '../with-kya-os.delegation-encoding.js';
import { makeServer } from './helpers/delegation-gate-server.js';
import { ARGS, CONSENT, SCOPE, TOOL, released } from './helpers/delegated-call.js';
import { jwtParty, threeHops } from './helpers/delegation-chains.js';
import { proofOf, verifyReceived } from './helpers/received-proof.js';
import { delegationClaims, recordedReferences, refusal } from './helpers/server-answers.js';

describe('an allowed call', () => {
  it('allows the credential the issuer signed, whatever else the copy presented carries', async () => {
    const { kyaos, server, ancestors, recorded } = await makeServer();
    const { root, middle, leaf } = await threeHops(server.did);
    // Proof metadata is outside the §6.2 signature. A store that keeps a
    // fetch time there, or a holder that edits it, changes nothing signed.
    ancestors.push(
      { ...root, proof: { ...root.proof!, fetchedAt: new Date(0), cache: undefined } } as never,
      { ...middle, proof: { ...middle.proof!, created: '2031-01-01T00:00:00.000Z' } },
    );
    const redressed = { ...leaf, proof: { ...leaf.proof!, note: 'added by the holder' } };
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: redressed });

    expect(result.isError).toBeUndefined();
    expect(recordedReferences(recorded, 'delegation.verified')).toEqual([leaf.id]);
    const verified = await verifyReceived(result, { signer: server.did, toolName: TOOL, params: ARGS, binds: 'content' });
    expect(verified).toEqual({ valid: true });
  });

  describe('whatever a holder does to its copy of a credential', () => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const reparsed = (credential: DelegationCredential, edit: (json: string) => string) =>
      JSON.parse(edit(JSON.stringify(credential))) as DelegationCredential;
    const withProof = (credential: DelegationCredential, proof: Record<string, unknown>) =>
      ({ ...credential, proof: { ...credential.proof!, ...proof } }) as DelegationCredential;
    const signature = (credential: DelegationCredential) => String(credential.proof!.proofValue);

    /** Edits that touch nothing the issuer signed: the copy must verify, and bind as the issuer's does. */
    const unsignedEdits: Array<[string, (credential: DelegationCredential) => DelegationCredential]> = [
      ['changes proof.created', (c) => withProof(c, { created: '2031-01-01T00:00:00.000Z' })],
      ['adds a proof member', (c) => withProof(c, { note: 'mine' })],
      ['sets a spare bit of the signature', (c) => withProof(c, {
        proofValue: signature(c).slice(0, -1) + alphabet[alphabet.indexOf(signature(c).at(-1)!) | 1],
      })],
      ['pads the signature', (c) => withProof(c, { proofValue: `${signature(c)}==` })],
      ['writes the signature in the base64 alphabet', (c) => withProof(c, {
        proofValue: signature(c).replaceAll('-', '+').replaceAll('_', '/'),
      })],
      ['breaks the signature across lines', (c) => withProof(c, {
        proofValue: `${signature(c).slice(0, 40)}\n${signature(c).slice(40)}`,
      })],
    ];

    /** Edits to what the issuer signed, or to the signature: the copy must not verify. */
    const signedEdits: Array<[string, (credential: DelegationCredential) => DelegationCredential]> = [
      ['adds a member', (c) => ({ ...c, note: 'mine' }) as DelegationCredential],
      ['adds a member named __proto__', (c) => reparsed(c, (json) => json.replace('{', '{"__proto__":{"scope":"all"},'))],
      ['adds a scalar member named __proto__', (c) => reparsed(c, (json) => json.replace('{', '{"__proto__":1,'))],
      ['widens a scope', (c) => reparsed(c, (json) => json.replaceAll(`"${SCOPE}"`, `"${SCOPE}","records:delete"`))],
      ['replaces the signature', (c) => withProof(c, { proofValue: signature(c).split('').reverse().join('') })],
      ['puts a character that is not base64 in the signature', (c) => withProof(c, {
        proofValue: `${signature(c).slice(0, 10)}!${signature(c).slice(10)}`,
      })],
      // Padding ends a signature; decoders disagree about one anywhere else.
      ['puts padding inside the signature', (c) => withProof(c, {
        proofValue: `${signature(c).slice(0, 40)}=${signature(c).slice(40)}`,
      })],
    ];

    /** Present each edit once as the leaf, once as an ancestor the server resolves. */
    async function presentEdited(edit: (credential: DelegationCredential) => DelegationCredential) {
      const { kyaos, server, ancestors } = await makeServer();
      const { root, middle, leaf } = await threeHops(server.did);
      const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));
      const results = [];
      for (const [resolved, presented] of [
        [[root, middle], edit(leaf)],
        [[root, edit(middle)], leaf],
      ] as const) {
        ancestors.splice(0, ancestors.length, ...resolved);
        results.push(await handler({ ...ARGS, _kyaos_delegation: presented }));
      }
      return results;
    }

    it.each(unsignedEdits)('a copy that %s verifies', async (_name, edit) => {
      for (const result of await presentEdited(edit)) expect(result.isError).toBeUndefined();
    });

    it.each(signedEdits)('a copy that %s does not verify', async (_name, edit) => {
      for (const result of await presentEdited(edit)) {
        expect(result.isError).toBe(true);
        expect(refusal(result).error).toBe('delegation_invalid');
      }
    });

    it('a copy that puts values with no JSON form in proof verifies resolved, and is refused presented, as one the gate cannot encode', async () => {
      const [presented, resolved] = await presentEdited((c) => withProof(c, { cache: undefined, at: new Date(0) }));
      // The gate hands on the credential presented, and the grant it binds holds all of it, so all
      // of it must encode (./with-kya-os.delegation-encoding.ts). An ancestor is verified and recorded.
      expect(refusal(presented!)).toEqual({ error: 'delegation_invalid', reason: UNENCODABLE_DELEGATION_REASON });
      expect(resolved!.isError).toBeUndefined();
    });

    it.each([
      [
        'that is not base64',
        (c: DelegationCredential) => withProof(c, { proofValue: `${signature(c).slice(0, 10)}!${signature(c).slice(10)}` }),
        'Unreadable proofValue: A credential signature is base64url',
      ],
      [
        'of no bytes',
        (c: DelegationCredential) => withProof(c, { proofValue: '==' }),
        'Unreadable proofValue: A credential signature is base64url of at least one byte',
      ],
      [
        'that is empty',
        (c: DelegationCredential) => withProof(c, { proofValue: '' }),
        'Missing proofValue in proof',
      ],
    ])('a copy with a signature %s is refused for that', async (_name, edit, said) => {
      const { kyaos, server, ancestors } = await makeServer();
      const { root, middle, leaf } = await threeHops(server.did);
      ancestors.push(root, middle);
      const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

      const result = await handler({ ...ARGS, _kyaos_delegation: edit(leaf) });

      expect(refusal(result)).toEqual({
        error: 'delegation_invalid',
        reason: `Delegation ${leaf.credentialSubject.delegation.id} invalid: ${said}`,
      });
    });

    it('a copy whose signed content has no canonical form is refused as unreadable', async () => {
      const { kyaos, server, ancestors } = await makeServer();
      const { root, middle, leaf } = await threeHops(server.did);
      ancestors.push(root, middle);
      const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

      // A lone surrogate has no UTF-8 form, so no RFC 8785 form covers it.
      const result = await handler({ ...ARGS, _kyaos_delegation: { ...leaf, note: '\uD800' } });

      expect(refusal(result).reason).toMatch(new RegExp(
        `^Delegation ${leaf.credentialSubject.delegation.id} invalid: Unreadable credential content: ` +
          "What a credential's signature covers has no canonical JSON form: Cannot canonicalize",
      ));
    });

    it('is read once: a value that could answer differently each time is no credential', async () => {
      const { kyaos, server, ancestors, recorded } = await makeServer();
      const { root, middle, leaf } = await threeHops(server.did);
      const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

      // A Proxy is refused outright, presented or resolved, whatever it would
      // have answered.
      ancestors.splice(0, ancestors.length, root, middle);
      const proxied = await handler({ ...ARGS, _kyaos_delegation: new Proxy(leaf, {}) });
      expect(refusal(proxied)).toEqual({
        error: 'delegation_invalid',
        reason: 'Malformed delegation credential: it is not plain data',
      });
      ancestors.splice(0, ancestors.length, root, new Proxy(middle, {}));
      const resolved = await handler({ ...ARGS, _kyaos_delegation: leaf });
      expect(refusal(resolved)).toEqual({
        error: 'delegation_invalid',
        reason: `Resolved delegation chain for ${leaf.credentialSubject.delegation.id} holds a value that could not be copied`,
      });

      // A getter is never run. A copy would keep what it answered, and the
      // credential would then verify on that answer: so it is refused unread,
      // and the trail names nothing, since nothing was read of it.
      ancestors.splice(0, ancestors.length, root, middle);
      let reads = 0;
      const shifting = { ...leaf };
      Object.defineProperty(shifting, 'issuer', {
        enumerable: true,
        get: () => (reads++ === 0 ? leaf.issuer : 'did:web:someone.else'),
      });
      const result = await handler({ ...ARGS, _kyaos_delegation: shifting });
      expect(refusal(result)).toEqual({
        error: 'delegation_invalid',
        reason: 'Malformed delegation credential: it is not plain data',
      });
      expect(reads).toBe(0);
      expect(proofOf(result)!.meta.outcome).toBe('denied');
      expect(delegationClaims(result)).toEqual({});
      expect(recordedReferences(recorded, 'delegation.rejected').at(-1)).toBeUndefined();

      // As an ancestor it refuses the chain before any of it is verified. The
      // trail names the credential presented.
      ancestors.splice(0, ancestors.length, root, { ...middle, get note() { reads += 1; return 'mine'; } });
      const walked = await handler({ ...ARGS, _kyaos_delegation: leaf });
      expect(refusal(walked).reason).toBe(
        `Resolved delegation chain for ${leaf.credentialSubject.delegation.id} holds a value that could not be copied`,
      );
      expect(reads).toBe(0);
      expect(delegationClaims(walked)).toEqual({});
      expect(recordedReferences(recorded, 'delegation.rejected').at(-1)).toBe(leaf.id);
    });

    it('is refused when it adds a __proto__ member, which no issuer signed', async () => {
      const { kyaos, server, ancestors } = await makeServer();
      const { root, middle, leaf } = await threeHops(server.did);
      ancestors.push(root, middle);
      const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));
      const smuggled = reparsed(leaf, (json) => json.replace('{', '{"__proto__":{"scope":"all"},'));

      const result = await handler({ ...ARGS, _kyaos_delegation: smuggled });

      expect(result.isError).toBe(true);
      expect(refusal(result).error).toBe('delegation_invalid');
    });

    it('is allowed when only the writing of its signature differs', async () => {
      const { kyaos, server, ancestors } = await makeServer();
      const { root, middle, leaf } = await threeHops(server.did);
      ancestors.push(root, middle);
      const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));
      const padded = withProof(leaf, { proofValue: `${signature(leaf)}==` });

      const result = await handler({ ...ARGS, _kyaos_delegation: padded });

      expect(result.isError).toBeUndefined();
    });
  });

  describe('a VC-JWT, however its signature segment is written', () => {
    const base64url = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    /**
     * A VC-JWT and the gate it is presented to. Its signature holds a
     * character the base64 alphabet writes otherwise, so it can be rewritten
     * in that alphabet.
     */
    async function minting() {
      const { kyaos, recorded } = await makeServer();
      const issuer = await jwtParty();
      const mint = (attempt: number) =>
        issuer.issue({ id: 'urn:uuid:jwt-recoded', delegationId: 'del-jwt-recoded', claims: { attempt } });
      let minted = await mint(0);
      for (let attempt = 1; !/[-_]/.test(minted.slice(minted.lastIndexOf('.'))); attempt += 1) {
        minted = await mint(attempt);
      }
      const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));
      return {
        minted,
        /** `header.payload.`, and the signature segment after it. */
        signed: minted.slice(0, minted.lastIndexOf('.') + 1),
        signature: minted.slice(minted.lastIndexOf('.') + 1),
        present: (written: string) => handler({ ...ARGS, _kyaos_delegation: written }),
        envelope: vi.spyOn(DelegationCredentialVerifier.prototype, 'verifyDelegationJwt'),
        recorded,
      };
    }

    it('verifies one a JWS library reads, as the JWT its issuer minted', async () => {
      const { minted, signature, present, envelope, recorded } = await minting();
      // 64 signature bytes are 86 characters: a last group of two, which two
      // `=` complete, and four spare bits in the last character.
      expect(signature).toHaveLength(86);
      const last = minted.at(-1)!;
      const writings = [
        minted,
        minted.slice(0, -1) + base64url[base64url.indexOf(last) ^ 1],
        `${minted}==`,
        `${minted.slice(0, -20)} ${minted.slice(-20)}`,
        `${minted}\n`,
      ];
      expect(new Set(writings).size).toBe(writings.length);

      for (const written of writings) {
        const result = await present(written);
        expect(result.isError).toBeUndefined();
      }
      expect(recordedReferences(recorded, 'delegation.verified')).toEqual(writings.map(() => 'urn:uuid:jwt-recoded'));
      // Whatever was presented, the JWS library is handed the one canonical writing.
      expect(envelope.mock.calls.map(([jwt]) => jwt)).toEqual(writings.map(() => minted));
    });

    it.each([
      ['a single = where two would complete its last group', (signature: string) => `${signature}=`],
      ['a = inside it', (signature: string) => `${signature.slice(0, -20)}=${signature.slice(-20)}`],
      ['the base64 alphabet, + and / for - and _', (signature: string) =>
        signature.replaceAll('-', '+').replaceAll('_', '/')],
      ['a last group of one character', (signature: string) => `${signature}AAA`],
    ])('refuses one written with %s: no JWS library reads it', async (_name, rewrite) => {
      const { signed, signature, present, envelope, recorded } = await minting();
      const written = signed + rewrite(signature);

      const result = await present(written);

      // The refusal is the JWS library's own, of the string as it came.
      expect(refusal(result)).toEqual({
        error: 'delegation_invalid',
        reason: 'JWT envelope signature is not valid: Failed to base64url decode the signature',
      });
      expect(envelope.mock.calls.map(([jwt]) => jwt)).toEqual([written]);
      // The trail records the credential the string claimed to be.
      expect(recordedReferences(recorded, 'delegation.rejected')).toEqual(['urn:uuid:jwt-recoded']);
      expect(proofOf(result)!.meta.outcome).toBe('denied');
      expect(delegationClaims(result)).toEqual({});
    });

    it('takes no verdict on a signature it cannot read itself, whatever a JWS library makes of it', async () => {
      const { signed, signature, present, envelope } = await minting();
      // A decoder that reads the base64 alphabet as base64url, as some have:
      // the JWS library uses the platform's where there is one.
      const platform = Object.getOwnPropertyDescriptor(Uint8Array, 'fromBase64');
      Object.defineProperty(Uint8Array, 'fromBase64', {
        configurable: true,
        writable: true,
        value: (encoded: string) => new Uint8Array(Buffer.from(encoded, 'base64')),
      });
      try {
        const result = await present(signed + signature.replaceAll('-', '+').replaceAll('_', '/'));

        // The library verified the envelope. Nothing that verified so could
        // be digested, so the call is refused all the same.
        await expect(envelope.mock.results[0]!.value).resolves.toMatchObject({ valid: true });
        expect(refusal(result)).toEqual({
          error: 'delegation_invalid',
          reason: 'JWT envelope signature is not valid: its signature is not base64url',
        });
        expect(delegationClaims(result)).toEqual({});
      } finally {
        if (platform === undefined) delete (Uint8Array as { fromBase64?: unknown }).fromBase64;
        else Object.defineProperty(Uint8Array, 'fromBase64', platform);
      }
    });
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});
