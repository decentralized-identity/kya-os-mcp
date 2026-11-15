/**
 * Readings two implementations could make differently (SPEC.md §7.8).
 *
 * Each vector holds a credential that a plausible implementation reads
 * otherwise than the spec does, and so derives another reference or another
 * digest: a payload with a number its parser refuses or an id written twice,
 * an id at either edge of the control characters, one that holds a format
 * character, one that holds a code point that only renders as nothing, one
 * that reads as a digest with a character after it, and one that is the word
 * `unknown`, a member named `__proto__`, and a number that is an integer above
 * 2^53 - 1 only once it is read.
 */

import { canonicalize } from 'json-canonicalize';
import {
  digestDelegationChain,
  NoSignedFormError,
  type DelegationCredential,
  type DetachedProof,
} from '../src/index.js';
import { isDigest } from '../src/delegation/digest-form.js';
import { payloadText, type BindingKit } from './delegation-binding-kit.js';
import { READ_AS_LARGE_INTEGER } from './numbers-as-written.js';
import type { ConformanceVector } from './types.js';

/**
 * Code points that are no control, format or separator character and render
 * as nothing by default (Default_Ignorable_Code_Point), one of each of four
 * runs of `./unseen-code-points.json`: the vector's name, what the code point
 * is, and the code point.
 */
const RENDERED_AS_NOTHING = [
  ['grapheme-joiner', 'a combining grapheme joiner', 0x034f],
  ['hangul-filler', 'a Hangul filler', 0x3164],
  ['variation-selector', 'a variation selector', 0xfe0f],
  ['variation-selector-supplement', 'a variation selector outside the basic plane', 0xe0100],
] as const;

/** The vectors of the readings of a credential that two implementations could make differently. */
export async function readingVectors<P extends { did: string }>(kit: BindingKit<P>): Promise<ConformanceVector[]> {
  const { mint, request, response } = kit;

  // A VC-JWT whose payload holds an integer of 4301 digits, more than some
  // JSON parsers convert unless told to. JSON sets no limit on a number, and
  // a number plays no part in the id. A caller wrote the number into an
  // issuer's VC-JWT, so its signature no longer verifies: the server refuses
  // it, names the id it shows, and binds it by its segments as received.
  const longNumber = await rewrittenVcJwt(kit, 'del-jwt-long-number', (issued) =>
    `${issued.slice(0, -1)},"n":${'1'.repeat(4301)}}`,
  );
  if (
    !longNumber.issued.endsWith('}') ||
    JSON.parse(longNumber.claims).n !== Number.POSITIVE_INFINITY ||
    (await kit.reference(longNumber.jwt)) !== 'urn:uuid:del-jwt-long-number'
  ) {
    throw new Error('expected a VC-JWT whose payload holds a number of 4301 digits and shows its id');
  }
  const longNumberProof = await refusedUnverified(kit, longNumber.jwt);

  // A VC-JWT whose payload holds the credential's id twice: a caller wrote
  // another id into an issuer's VC-JWT, ahead of the issuer's own. Of the
  // members of one object that share a name the last is read, as JSON.parse
  // reads them, so the credential shows the issuer's id. Its signature no
  // longer verifies: the server refuses it, names that id, and binds it by its
  // segments as received.
  const duplicateId = await rewrittenVcJwt(kit, 'del-jwt-duplicate-id', (issued) =>
    issued.replace('"vc":{', '"vc":{"id":"urn:uuid:del-jwt-duplicate-id-first",'),
  );
  if (
    duplicateId.issued.split('"vc":{').length !== 2 ||
    !duplicateId.issued.includes('"id":"urn:uuid:del-jwt-duplicate-id"') ||
    JSON.parse(duplicateId.claims).vc.id !== 'urn:uuid:del-jwt-duplicate-id' ||
    (await kit.reference(duplicateId.jwt)) !== 'urn:uuid:del-jwt-duplicate-id'
  ) {
    throw new Error('expected a VC-JWT whose payload holds the credential id twice and shows the last');
  }
  const duplicateIdProof = await refusedUnverified(kit, duplicateId.jwt);

  // Ids on either side of the last C0 control character: U+001F is referred
  // to by its digest, and U+0020, the first character past it, is kept.
  const lastControlCredential = await kit.credential('del-id-unit-separator', { vcId: '\u001f' });
  const pastControlCredential = await kit.credential('del-id-space', { vcId: ' ' });
  // An id that reads as a digest with one more character after it does not
  // read as a digest, and is kept.
  const suffixedDigestId = `sha256:${'0123456789abcdef'.repeat(4)}0`;
  const suffixedDigestCredential = await kit.credential('del-id-digest-suffixed', { vcId: suffixedDigestId });
  if (
    !isDigest(await kit.reference(lastControlCredential)) ||
    (await kit.reference(pastControlCredential)) !== ' ' ||
    (await kit.reference(suffixedDigestCredential)) !== suffixedDigestId
  ) {
    throw new Error('expected U+001F referred to by its digest, and U+0020 and the suffixed digest kept');
  }
  const lastControlProof = await kit.boundAlone(lastControlCredential);
  const pastControlProof = await kit.boundAlone(pastControlCredential);
  const suffixedDigestProof = await kit.boundAlone(suffixedDigestCredential);

  // Ids that print as something other than they hold: a right-to-left
  // override, which shows the characters after it reversed ("exe.png" here),
  // and a zero-width space, which shows as nothing. Each is referred to by its
  // digest. So is an id that is the word an audit record names a credential
  // that shows no id by.
  const bidiCredential = await kit.credential('del-id-bidi-override', { vcId: 'urn:uuid:del-\u202egnp.exe' });
  const zeroWidthCredential = await kit.credential('del-id-zero-width', { vcId: 'urn:uuid:del-\u200b1' });
  const unknownCredential = await kit.credential('del-id-unknown', { vcId: 'unknown' });
  for (const credential of [bidiCredential, zeroWidthCredential, unknownCredential]) {
    if (!isDigest(await kit.reference(credential))) {
      throw new Error(`expected the id ${JSON.stringify(credential.id)} referred to by its digest`);
    }
  }
  const bidiProof = await kit.boundAlone(bidiCredential);
  const zeroWidthProof = await kit.boundAlone(zeroWidthCredential);
  const unknownProof = await kit.boundAlone(unknownCredential);

  // Ids that hold a code point Unicode gives no control or format category
  // and that renders as nothing by default, so each prints as the id without
  // it does. Each is referred to by its digest.
  const renderedAsNothingVectors: ConformanceVector[] = [];
  for (const [name, what, codePoint] of RENDERED_AS_NOTHING) {
    const written = `U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}`;
    const credential = await kit.credential(`del-id-${name}`, {
      vcId: `urn:uuid:del-${String.fromCodePoint(codePoint)}1`,
    });
    if (!isDigest(await kit.reference(credential))) {
      throw new Error(`expected the id holding ${written} referred to by its digest`);
    }
    renderedAsNothingVectors.push({
      id: `signed-proof/delegation-ref-${name}`,
      category: 'signed-proof',
      description: `Proof binding a single credential whose id holds ${written}, ${what}, with delegationRef the SHA-256 of the id`,
      expected: 'pass',
      reason:
        'An id that holds a code point that renders as nothing by default, whatever its general category, is referred to by sha256 of its UTF-8 bytes: an implementation that hashes only ids with a control or format character names the credential by the id itself',
      input: kit.inputOf(await kit.boundAlone(credential), { request, response, delegationChain: [credential] }),
    });
  }

  // A credential object whose issuer signed a member named `__proto__`: it is
  // a member like any other, so it is in the signed form and the digest.
  const protoMemberCredential = await kit.credential('del-proto-member', {
    members: [['__proto__', 'signed by the issuer']],
  });
  const withoutProtoMember = Object.fromEntries(
    Object.entries(protoMemberCredential).filter(([key]) => key !== '__proto__'),
  ) as DelegationCredential;
  if (
    !Object.hasOwn(protoMemberCredential, '__proto__') ||
    !JSON.stringify(protoMemberCredential).includes('"__proto__":"signed by the issuer"') ||
    (await kit.chainDigest([protoMemberCredential])) === (await kit.chainDigest([withoutProtoMember]))
  ) {
    throw new Error('expected a credential with an own __proto__ member that its digest covers');
  }
  const protoMemberProof = await kit.boundAlone(protoMemberCredential);

  // A credential object holding a number the file writes as 9007199254740993.5
  // (READ_AS_LARGE_INTEGER). Read as a binary64 value it is an integer of
  // magnitude above 2^53 - 1, so the credential has no RFC 8785 form, though
  // the number is no integer as written. Its issuer signed it as a
  // canonicalizer that holds numbers to no such rule writes it, and the proof
  // carries the digest such a canonicalizer gives.
  const largeIntegerCredential = await kit.credential('del-number-read-as-binary64', {
    metadata: { [READ_AS_LARGE_INTEGER.member]: READ_AS_LARGE_INTEGER.value },
    canonicalize: (unsigned) => canonicalize(unsigned as never),
  });
  const largeIntegerRefused = await digestDelegationChain([largeIntegerCredential], mint.hash).then(
    () => false,
    (error: unknown) => error instanceof NoSignedFormError,
  );
  if (
    !/^\d+\.\d*[1-9]$/.test(READ_AS_LARGE_INTEGER.text) ||
    JSON.parse(READ_AS_LARGE_INTEGER.text) !== READ_AS_LARGE_INTEGER.value ||
    !Number.isInteger(READ_AS_LARGE_INTEGER.value) ||
    Number.isSafeInteger(READ_AS_LARGE_INTEGER.value) ||
    !largeIntegerRefused
  ) {
    throw new Error('expected a credential holding a number that reads as an integer above 2^53 - 1');
  }
  const largeIntegerProof = await kit.lenientProof(largeIntegerCredential);

  return [
    {
      id: 'signed-proof/delegation-ref-jwt-long-number',
      category: 'signed-proof',
      description:
        'Denial proof binding a single VC-JWT whose payload holds an integer of 4301 digits, naming the credential by the id that payload shows, verified against that VC-JWT as a refusal (expected.outcome: denied)',
      expected: 'pass',
      reason:
        'JSON sets no limit on the length of a number, so the payload is read whatever its numbers hold, and a number plays no part in the id: an implementation whose parser refuses a long number derives no id, and rejects a proof it must accept',
      input: kit.inputOf(longNumberProof, { request, delegationChain: [longNumber.jwt], outcome: 'denied' }),
    },
    {
      id: 'signed-proof/delegation-ref-control-at-bound',
      category: 'signed-proof',
      description:
        'Proof binding a single credential whose id is U+001F alone, the last C0 control character, with delegationRef the SHA-256 of the id',
      expected: 'pass',
      reason:
        'An id that holds a control character, U+0000 to U+001F among them, is referred to by sha256 of its UTF-8 bytes: an implementation that stops the range short of U+001F names the credential by the id itself',
      input: kit.inputOf(lastControlProof, { request, response, delegationChain: [lastControlCredential] }),
    },
    {
      id: 'signed-proof/delegation-ref-control-past-bound',
      category: 'signed-proof',
      description:
        'Proof binding a single credential whose id is U+0020 alone, the first character past the C0 controls, with delegationRef the id itself',
      expected: 'pass',
      reason:
        'U+0020 is no control character, so an id of it alone is referred to as it is: an implementation that runs the range past U+001F names the credential by a digest',
      input: kit.inputOf(pastControlProof, { request, response, delegationChain: [pastControlCredential] }),
    },
    {
      id: 'signed-proof/delegation-ref-digest-form-suffixed',
      category: 'signed-proof',
      description:
        'Proof binding a single credential whose id is sha256: followed by 64 lowercase hexadecimal digits and one more character, with delegationRef the id itself',
      expected: 'pass',
      reason:
        'Only an id that reads as such a digest and nothing more is replaced by its own digest. One with a character after the 64 digits is kept: an implementation that matches the digest form at the start of the id alone names the credential by a digest',
      input: kit.inputOf(suffixedDigestProof, { request, response, delegationChain: [suffixedDigestCredential] }),
    },
    {
      id: 'signed-proof/delegation-ref-bidi-override',
      category: 'signed-proof',
      description:
        'Proof binding a single credential whose id holds U+202E, a right-to-left override, with delegationRef the SHA-256 of the id',
      expected: 'pass',
      reason:
        'An id that holds a format character, which prints as something other than it holds, is referred to by sha256 of its UTF-8 bytes: an implementation that hashes only ids with a control character names the credential by the id itself',
      input: kit.inputOf(bidiProof, { request, response, delegationChain: [bidiCredential] }),
    },
    {
      id: 'signed-proof/delegation-ref-zero-width',
      category: 'signed-proof',
      description:
        'Proof binding a single credential whose id holds U+200B, a zero-width space, with delegationRef the SHA-256 of the id',
      expected: 'pass',
      reason:
        'An id that holds a format character, one that prints as nothing among them, is referred to by sha256 of its UTF-8 bytes: an implementation that hashes only ids with a control character names the credential by the id itself',
      input: kit.inputOf(zeroWidthProof, { request, response, delegationChain: [zeroWidthCredential] }),
    },
    ...renderedAsNothingVectors,
    {
      id: 'signed-proof/delegation-ref-unknown',
      category: 'signed-proof',
      description:
        'Proof binding a single credential whose id is the word unknown, with delegationRef the SHA-256 of the id',
      expected: 'pass',
      reason:
        'An audit record names a credential that shows no id unknown, so an id written so is referred to by sha256 of its UTF-8 bytes and the word never stands for a credential: an implementation that keeps it names the credential by the id itself',
      input: kit.inputOf(unknownProof, { request, response, delegationChain: [unknownCredential] }),
    },
    {
      id: 'signed-proof/delegation-chain-proto-member',
      category: 'signed-proof',
      description:
        'Proof binding a single credential object whose issuer signed a member named __proto__, verified against that credential',
      expected: 'pass',
      reason:
        'A member named __proto__ is a member like any other: it is part of the signed form, so of the digest. An implementation that drops it, or reads it as a prototype, computes another digest and rejects a proof it must accept',
      input: kit.inputOf(protoMemberProof, { request, response, delegationChain: [protoMemberCredential] }),
    },
    {
      id: 'signed-proof/delegation-ref-jwt-duplicate-id',
      category: 'signed-proof',
      description:
        "Denial proof binding a single VC-JWT whose payload holds the credential id twice, another id written ahead of the issuer's, naming the credential by the last of them, verified against that VC-JWT as a refusal (expected.outcome: denied)",
      expected: 'pass',
      reason:
        'Of the members of one object that share a name the last is read, as JSON.parse reads them, so the credential shows the id written last: an implementation whose parser keeps the first, or refuses the payload, names another credential or none, and rejects a proof it must accept',
      input: kit.inputOf(duplicateIdProof, { request, delegationChain: [duplicateId.jwt], outcome: 'denied' }),
    },
    {
      id: 'signed-proof/delegation-chain-number-read-as-binary64',
      category: 'signed-proof',
      description:
        'Authentic proof carrying the chain digest an implementation that holds a number to RFC 8785 as it is written takes of a credential object holding 9007199254740993.5, verified against that credential',
      expected: 'fail',
      reason:
        'A number is read as an IEEE 754 binary64 value before it is held to RFC 8785: 9007199254740993.5 reads as 9007199254740994, an integer of magnitude above 2^53 - 1, so the credential has no signed form and no proof binds the chain, though the number is no integer as written',
      input: kit.inputOf(largeIntegerProof, { request, response, delegationChain: [largeIntegerCredential] }),
    },
  ];
}

/**
 * A VC-JWT the user issued for `id`, with its payload rewritten by a caller
 * and the issuer's signature kept: the claims as issued and as rewritten, and
 * the VC-JWT that carries the rewritten claims.
 */
async function rewrittenVcJwt<P extends { did: string }>(
  kit: BindingKit<P>,
  id: string,
  rewrite: (issued: string) => string,
): Promise<{ issued: string; claims: string; jwt: string }> {
  const issuedJwt = await kit.mint.vcJwt(kit.user, await kit.credential(id));
  const [header, , signature] = issuedJwt.split('.');
  const issued = payloadText(issuedJwt);
  const claims = rewrite(issued);
  return { issued, claims, jwt: `${header}.${Buffer.from(claims, 'utf8').toString('base64url')}.${signature}` };
}

/**
 * The server's refusal of a VC-JWT whose signature no longer verifies: it
 * names the id the credential shows, and binds it by its segments as received.
 */
async function refusedUnverified<P extends { did: string }>(kit: BindingKit<P>, jwt: string): Promise<DetachedProof> {
  return kit.refused('JWT envelope signature is not valid: signature verification failed', {
    delegationRef: await kit.reference(jwt),
    delegationChainDigest: await kit.chainDigest([jwt]),
  });
}
